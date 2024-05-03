use core::{fmt, str};

use serde::Serialize;

pub const SPECIFIER_SIZE: usize = 16;

#[derive(Debug, PartialEq, Serialize)]
pub struct Specifier([u8; SPECIFIER_SIZE]);

impl Specifier {
    pub const fn new(buf: [u8; SPECIFIER_SIZE]) -> Self {
        Self(buf)
    }

    pub fn as_bytes(&self) -> &[u8; SPECIFIER_SIZE] {
        &self.0
    }
}

impl fmt::Display for Specifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // get the last non-zero byte or 0 if all bytes are 0
        let index = self
            .0
            .iter()
            .rev()
            .position(|&x| x != 0)
            .map_or(0, |pos| SPECIFIER_SIZE - pos);
        let str = str::from_utf8(&self.0[..index]).map_err(|_| fmt::Error)?;
        write!(f, "{}", str)
    }
}

impl<T: AsRef<[u8]>> From<T> for Specifier {
    fn from(src: T) -> Self {
        let src = src.as_ref();
        assert!(src.len() <= SPECIFIER_SIZE, "specifier too long");
        let mut spec = Specifier([0; SPECIFIER_SIZE]);
        spec.0[..src.len()].copy_from_slice(src);
        spec
    }
}

macro_rules! specifier {
    ($text:expr) => {{
        let src = $text.as_bytes();
        let len = src.len();
        assert!(
            len <= $crate::specifier::SPECIFIER_SIZE,
            "specifier too long"
        );
        let mut buf = [0; 16];
        let mut index: usize = 0;
        while index < len {
            buf[index] = src[index];
            index += 1;
        }
        $crate::specifier::Specifier::new(buf)
    }};
}

pub(crate) use specifier;

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

    #[test]
    fn test_specifier_macro() {
        let test_cases = vec![(specifier!["hello world"], "hello world")];
        for (specifier, expected) in test_cases {
            assert_eq!(specifier.to_string(), expected);
        }
    }

    #[test]
    fn test_specifier_string() {
        let test_cases = vec![
            (specifier!["hello world"], "hello world"),
            (specifier!["hello"], "hello"),
            (
                Specifier::from([
                    b'h', b'e', b'l', b'l', b'o', 0, b'w', b'o', b'r', b'l', b'd',
                ]),
                "hello\0world",
            ),
            (Specifier::new([0; 16]), ""),
        ];
        for (specifier, expected) in test_cases {
            assert_eq!(specifier.to_string(), expected);
        }
    }
}
