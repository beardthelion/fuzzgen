// go-probe classifies a Go function or method signature for fuzzgen.
// Usage: go-probe -dir <pkg-dir> -name <Name> [-type <RecvType>]
// Emits one JSON report on stdout; exit code is not the success test.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/types"
	"os"

	"golang.org/x/tools/go/packages"
)

type report struct {
	Found    bool     `json:"found"`
	Kind     string   `json:"kind,omitempty"` // bytes, string, multi, io-reader, ssz, rlp, binary, json, unknown
	Args     []string `json:"args,omitempty"`
	Reason   string   `json:"reason,omitempty"`
	MethodOf string   `json:"method_of,omitempty"`
	Markers  []string `json:"markers,omitempty"`
}

func fail(reason string) {
	emit(report{Found: false, Reason: reason})
	os.Exit(0)
}

func emit(r report) {
	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(r); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func argKind(t types.Type) string {
	switch u := t.Underlying().(type) {
	case *types.Slice:
		if basic, ok := u.Elem().Underlying().(*types.Basic); ok && basic.Kind() == types.Byte {
			return "bytes"
		}
		return "other"
	case *types.Basic:
		if u.Kind() == types.String {
			return "string"
		}
	}
	if named, ok := t.(*types.Named); ok {
		if named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "io" && named.Obj().Name() == "Reader" {
			return "io-reader"
		}
	}
	if iface, ok := t.Underlying().(*types.Interface); ok {
		if iface.NumMethods() == 1 && iface.Method(0).Name() == "Read" {
			return "io-reader"
		}
	}
	return "other"
}

// markerMethods returns decoder marker traits a *T method set satisfies.
var markerMethods = map[string]string{
	"UnmarshalSSZ":    "ssz",
	"DecodeRLP":       "rlp",
	"UnmarshalBinary": "binary",
	"UnmarshalJSON":   "json",
}

func methodMarkers(named *types.Named) []string {
	ms := types.NewMethodSet(types.NewPointer(named))
	var out []string
	for m, marker := range markerMethods {
		for i := 0; i < ms.Len(); i++ {
			if ms.At(i).Obj().Name() == m {
				if sig, ok := ms.At(i).Type().(*types.Signature); ok &&
					sig.Params().Len() == 1 {
					out = append(out, marker)
				}
			}
		}
	}
	return out
}

func main() {
	dir := flag.String("dir", ".", "package directory inside the target module")
	name := flag.String("name", "", "function or method name")
	recv := flag.String("type", "", "receiver type for methods, e.g. T or *T")
	flag.Parse()
	if *name == "" {
		fail("name is required")
	}

	cfg := &packages.Config{
		Mode:  packages.NeedName | packages.NeedTypes | packages.NeedDeps | packages.NeedImports,
		Dir:   *dir,
		Tests: false,
	}
	pkgs, err := packages.Load(cfg, ".")
	if err != nil || len(pkgs) == 0 {
		fail("package load failed")
	}
	pkg := pkgs[0]
	if pkg.Types == nil {
		fail("no type info")
	}
	scope := pkg.Types.Scope()

	if *recv != "" {
		obj := scope.Lookup(*recv)
		if obj == nil {
			fail(fmt.Sprintf("type %s not found", *recv))
		}
		named, ok := obj.Type().(*types.Named)
		if !ok {
			fail(fmt.Sprintf("type %s not found", *recv))
		}
		ms := types.NewMethodSet(types.NewPointer(named))
		for i := 0; i < ms.Len(); i++ {
			if ms.At(i).Obj().Name() != *name {
				continue
			}
			sig, ok := ms.At(i).Type().(*types.Signature)
			if !ok {
				continue
			}
			r := classifySig(sig)
			r.MethodOf = *recv
			r.Markers = methodMarkers(named)
			emit(r)
			return
		}
		fail(fmt.Sprintf("method %s not found on %s", *name, *recv))
	}

	obj := scope.Lookup(*name)
	if obj == nil {
		fail(fmt.Sprintf("%s not found", *name))
	}
	sig, ok := obj.Type().(*types.Signature)
	if !ok {
		fail(fmt.Sprintf("%s is not a function", *name))
	}
	emit(classifySig(sig))
}

func classifySig(sig *types.Signature) report {
	params := sig.Params()
	if params.Len() == 0 {
		return report{Found: true, Kind: "unknown", Reason: "no parameters"}
	}
	kinds := make([]string, params.Len())
	args := make([]string, params.Len())
	for i := 0; i < params.Len(); i++ {
		kinds[i] = argKind(params.At(i).Type())
		args[i] = params.At(i).Type().String()
	}
	if params.Len() == 1 {
		switch kinds[0] {
		case "bytes", "string", "io-reader":
			return report{Found: true, Kind: kinds[0], Args: args}
		}
		return report{Found: true, Kind: "unknown", Args: args}
	}
	for _, k := range kinds {
		if k == "other" || k == "io-reader" {
			return report{Found: true, Kind: "unknown", Args: args,
				Reason: "arg kind not seedable"}
		}
	}
	return report{Found: true, Kind: "multi", Args: args}
}
