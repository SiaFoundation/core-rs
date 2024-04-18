use serde::Serialize;

const SPECIFIER_SIZE: usize = 16;

#[derive(Debug, PartialEq, Serialize)]
pub struct Specifier([u8; SPECIFIER_SIZE]);

// implement the `From` trait for the `Specifier` struct to allow for creating a
// Specifier from any type that can be converted to a slice of bytes such as
// 'String', '&str' or byte arrays.
impl<T: AsRef<[u8]>> From<T> for Specifier {
    fn from(src: T) -> Self {
        let src = src.as_ref();
        assert!(src.len() <= SPECIFIER_SIZE, "specifier too long");
        let mut spec = Specifier([0; SPECIFIER_SIZE]);
        spec.0[..src.len()].copy_from_slice(src);
        spec
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_specifier() {
        let spec = Specifier::from("hello");
        let expected = Specifier([
            b'h', b'e', b'l', b'l', b'o', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        assert_eq!(spec, expected);
    }
}
