use arbitrary::Arbitrary;
use ssz::Decode;

pub fn decode(input: &[u8]) -> Result<u32, ()> {
    Ok(input.len() as u32)
}

pub fn decode_str(input: &str) -> u32 {
    input.len() as u32
}

pub fn decode_vec(input: Vec<u8>) -> u32 {
    input.len() as u32
}

pub fn decode_two(a: &[u8], b: &[u8]) -> u32 {
    (a.len() + b.len()) as u32
}

pub fn decode_weird(input: f64) -> u32 {
    input as u32
}

pub fn decode_bounded<T>(input: T) -> u32
where
    T: Decode,
{
    0
}

pub fn decode_arb(input: impl Arbitrary) -> u32 {
    0
}

impl Reader {
    pub fn read_from(&self, input: &[u8]) -> u32 {
        input.len() as u32
    }
}

pub struct Reader;
