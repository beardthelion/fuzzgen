// rust-probe classifies a Rust function or method signature for fuzzgen.
// Usage: rust-probe -file <path.rs> -name <name> [-type <Type>]
// Emits one JSON report on stdout; exit code is not the success test.
use std::env;
use std::fs;
use std::process;

use serde_json::json;

fn main() {
    let mut file = String::new();
    let mut name = String::new();
    let mut typ = String::new();
    let mut args = env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-file" => file = args.next().unwrap_or_default(),
            "-name" => name = args.next().unwrap_or_default(),
            "-type" => typ = args.next().unwrap_or_default(),
            _ => {}
        }
    }
    if file.is_empty() || name.is_empty() {
        emit(&json!({"found": false, "reason": "file and name are required"}));
        return;
    }
    let src = match fs::read_to_string(&file) {
        Ok(s) => s,
        Err(e) => {
            emit(&json!({"found": false, "reason": format!("read: {}", e)}));
            return;
        }
    };
    let ast = match syn::parse_file(&src) {
        Ok(f) => f,
        Err(e) => {
            emit(&json!({"found": false, "reason": format!("parse: {}", e)}));
            return;
        }
    };
    let aliases = collect_aliases(&ast);

    if typ.is_empty() {
        for item in &ast.items {
            if let syn::Item::Fn(f) = item {
                if f.sig.ident == name {
                    emit(&classify_fn(&f.sig, &aliases));
                    return;
                }
            }
        }
        emit(&json!({"found": false, "reason": format!("{} not found", name)}));
        return;
    }

    for item in &ast.items {
        if let syn::Item::Impl(imp) = item {
            if !type_matches(&imp.self_ty, &typ) {
                continue;
            }
            for it in &imp.items {
                if let syn::ImplItem::Fn(m) = it {
                    if m.sig.ident == name {
                        let mut r = classify_fn(&m.sig, &aliases);
                        r["method_of"] = json!(typ);
                        emit(&r);
                        return;
                    }
                }
            }
        }
    }
    emit(&json!({"found": false, "reason": format!("{}::{} not found", typ, name)}));
    let _ = process::id();
}

fn emit(v: &serde_json::Value) {
    println!("{}", v);
}

fn type_matches(ty: &syn::Type, want: &str) -> bool {
    let want = want.trim_start_matches('*');
    if let syn::Type::Path(p) = ty {
        if let Some(seg) = p.path.segments.last() {
            return seg.ident == want;
        }
    }
    false
}

fn collect_aliases(ast: &syn::File) -> Vec<(String, String)> {
    // `use a::b::C;` records C -> a::b::C for bound-name resolution.
    let mut out = Vec::new();
    for item in &ast.items {
        if let syn::Item::Use(u) = item {
            collect_use_tree(&u.tree, String::new(), &mut out);
        }
    }
    out
}

fn collect_use_tree(tree: &syn::UseTree, prefix: String, out: &mut Vec<(String, String)>) {
    match tree {
        syn::UseTree::Path(p) => {
            let p2 = if prefix.is_empty() {
                p.ident.to_string()
            } else {
                format!("{}::{}", prefix, p.ident)
            };
            collect_use_tree(&p.tree, p2, out);
        }
        syn::UseTree::Name(n) => out.push((
            n.ident.to_string(),
            if prefix.is_empty() {
                n.ident.to_string()
            } else {
                format!("{}::{}", prefix, n.ident)
            },
        )),
        syn::UseTree::Rename(r) => {
            out.push((r.rename.to_string(), format!("{}::{}", prefix, r.ident)))
        }
        syn::UseTree::Group(g) => {
            for t in &g.items {
                collect_use_tree(t, prefix.clone(), out);
            }
        }
        _ => {}
    }
}

fn last_seg(path: &syn::Path) -> String {
    path.segments
        .last()
        .map(|s| s.ident.to_string())
        .unwrap_or_default()
}

fn ty_kind(ty: &syn::Type, aliases: &[(String, String)]) -> String {
    match ty {
        syn::Type::Reference(r) => ty_kind(&r.elem, aliases),
        syn::Type::Slice(s) => {
            if let syn::Type::Path(p) = &*s.elem {
                if last_seg(&p.path) == "u8" {
                    return "bytes".into();
                }
            }
            "other".into()
        }
        syn::Type::Path(p) => {
            let name = last_seg(&p.path);
            match name.as_str() {
                "str" | "String" => "string".into(),
                "Vec" => {
                    if let Some(arg) = first_generic(&p.path) {
                        if let syn::Type::Path(e) = arg {
                            if last_seg(&e.path) == "u8" {
                                return "bytes".into();
                            }
                        }
                    }
                    "other".into()
                }
                "Box" => {
                    if let Some(arg) = first_generic(&p.path) {
                        return ty_kind(arg, aliases);
                    }
                    "other".into()
                }
                "Read" | "BufRead" => "io-reader".into(),
                _ => {
                    for (alias, target) in aliases {
                        if alias == &name {
                            if let Some(tail) = target.rsplit("::").next() {
                                if tail == "Read" || tail == "BufRead" {
                                    return "io-reader".into();
                                }
                            }
                        }
                    }
                    "other".into()
                }
            }
        }
        _ => "other".into(),
    }
}

fn first_generic(path: &syn::Path) -> Option<&syn::Type> {
    let seg = path.segments.last()?;
    if let syn::PathArguments::AngleBracketed(a) = &seg.arguments {
        for arg in &a.args {
            if let syn::GenericArgument::Type(t) = arg {
                return Some(t);
            }
        }
    }
    None
}

// Marker traits whose last segment names a wire format or input mode.
fn marker_for(bound: &str) -> Option<&'static str> {
    match bound {
        "Decode" | "Decodable" => Some("ssz"),
        "Deserialize" | "DeserializeOwned" | "de::DeserializeOwned" => Some("struct"),
        "Arbitrary" => Some("struct"),
        "Encodable" => Some("rlp"),
        _ => None,
    }
}

fn bound_names(sig: &syn::Signature, aliases: &[(String, String)]) -> Vec<String> {
    let mut names = Vec::new();
    for input in &sig.inputs {
        if let syn::FnArg::Typed(pt) = input {
            if let syn::Type::ImplTrait(it) = &*pt.ty {
                for b in &it.bounds {
                    if let syn::TypeParamBound::Trait(t) = b {
                        names.push(last_seg(&t.path));
                    }
                }
            }
        }
    }
    if let Some(wc) = &sig.generics.where_clause {
        for pred in &wc.predicates {
            if let syn::WherePredicate::Type(pt) = pred {
                for b in &pt.bounds {
                    if let syn::TypeParamBound::Trait(t) = b {
                        names.push(last_seg(&t.path));
                    }
                }
            }
        }
    }
    for tp in sig.generics.type_params() {
        for b in &tp.bounds {
            if let syn::TypeParamBound::Trait(t) = b {
                names.push(last_seg(&t.path));
            }
        }
    }
    // Alias resolution: a bound named by a use alias maps to its target tail.
    for (alias, target) in aliases {
        if let Some(i) = names.iter().position(|n| n == alias) {
            if let Some(tail) = target.rsplit("::").next() {
                names[i] = tail.to_string();
            }
        }
    }
    names
}

fn classify_fn(sig: &syn::Signature, aliases: &[(String, String)]) -> serde_json::Value {
    let bounds = bound_names(sig, aliases);
    for b in &bounds {
        if let Some(marker) = marker_for(b) {
            return json!({"found": true, "kind": marker, "bounds": bounds});
        }
    }
    let mut args = Vec::new();
    for input in &sig.inputs {
        if let syn::FnArg::Typed(pt) = input {
            args.push(ty_kind(&pt.ty, aliases));
        }
    }
    if args.len() == 1 {
        match args[0].as_str() {
            "bytes" | "string" | "io-reader" => {
                return json!({"found": true, "kind": args[0], "bounds": bounds})
            }
            _ => {}
        }
    }
    if args.len() > 1 && args.iter().all(|a| a != "other") {
        return json!({"found": true, "kind": "multi", "args": args, "bounds": bounds});
    }
    json!({"found": true, "kind": "unknown", "args": args, "bounds": bounds})
}
