use std::{fmt::Display, vec};

use serde::{de, Deserialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    Custom(String),

    #[error("Failed to convert unsigned integer")]
    ConversionFailed(#[from] std::num::TryFromIntError),

    #[error("Deserializing type '{0}' is not supported")]
    UnsupportedType(&'static str),

    #[error("The Sia encoding is not a self-describing format and does therefore not support deserialize_any")]
    DeserializeAnyUnavailable,

    #[error("The value {0} is invalid for a bool")]
    InvalidBoolValue(u8),

    #[error("Failed to read from io::read")]
    IO(#[from] std::io::Error),
}

// Implement de::Error for Error
impl de::Error for Error {
    fn custom<T>(msg: T) -> Self
    where
        T: Display,
    {
        Error::Custom(msg.to_string())
    }
}

#[allow(dead_code)]
pub fn from_reader<'a, T, R>(reader: &'a mut R) -> Result<T, Error>
where
    T: Deserialize<'a>,
    R: std::io::Read,
{
    T::deserialize(&mut Deserializer { reader })
}

impl<'a, R> Deserializer<'a, R>
where
    R: std::io::Read,
{
    fn parse_bool(&mut self) -> Result<bool, Error> {
        let mut b: [u8; 1] = [0; 1];
        self.reader.read_exact(&mut b)?;
        match b[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::InvalidBoolValue(b[0])),
        }
    }

    fn parse_u64(&mut self) -> Result<u64, Error> {
        let mut b: [u8; 8] = [0; 8];
        self.reader.read_exact(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
}

pub struct Deserializer<'de, R>
where
    R: std::io::Read,
{
    reader: &'de mut R,
}

impl<'de, 'a, R> de::Deserializer<'de> for &'a mut Deserializer<'de, R>
where
    R: std::io::Read,
{
    type Error = Error;

    fn is_human_readable(&self) -> bool {
        false
    }

    // deserialize_any is not available for the Sia format since it's not
    // self-describing
    fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(Error::DeserializeAnyUnavailable)
    }

    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        visitor.visit_bool(self.parse_bool()?)
    }

    fn deserialize_i8<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(Error::UnsupportedType("i8"))
    }

    fn deserialize_i16<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(Error::UnsupportedType("i16"))
    }

    fn deserialize_i32<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(Error::UnsupportedType("i32"))
    }

    fn deserialize_i64<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(Error::UnsupportedType("i64"))
    }

    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        let mut v: [u8; 1] = [0; 1];
        self.reader.read_exact(&mut v)?;
        visitor.visit_u8(v[0])
    }

    fn deserialize_u16<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        visitor.visit_u16(self.parse_u64()? as u16)
    }

    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        visitor.visit_u32(self.parse_u64()? as u32)
    }

    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        visitor.visit_u64(self.parse_u64()?)
    }

    fn deserialize_f32<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(Error::UnsupportedType("f32"))
    }

    fn deserialize_f64<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(Error::UnsupportedType("f64"))
    }

    fn deserialize_char<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(Error::UnsupportedType("char"))
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        self.deserialize_byte_buf(visitor)
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        self.deserialize_byte_buf(visitor)
    }

    fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        self.deserialize_byte_buf(visitor)
    }

    fn deserialize_byte_buf<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        let len = self.parse_u64()? as usize;
        let mut buf = vec![0u8; len];
        self.reader.read_exact(&mut buf)?;
        visitor.visit_byte_buf(buf)
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        let b = self.parse_bool()?;
        if b {
            visitor.visit_some(self)
        } else {
            visitor.visit_none()
        }
    }

    fn deserialize_unit<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        visitor.visit_unit()
    }

    fn deserialize_unit_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        visitor.visit_unit()
    }

    fn deserialize_newtype_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        let len = self.parse_u64()? as usize;
        visitor.visit_seq(PrefixedSeqAccess {
            de: self,
            remaining: len,
        })
    }

    fn deserialize_tuple<V>(self, len: usize, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        visitor.visit_seq(PrefixedSeqAccess {
            de: self,
            remaining: len,
        })
    }

    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        _len: usize,
        _visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(Error::UnsupportedType("tuple_struct"))
    }

    fn deserialize_map<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(Error::UnsupportedType("map"))
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        let len = fields.len();
        visitor.visit_seq(PrefixedSeqAccess {
            remaining: len,
            de: self,
        })
    }

    fn deserialize_enum<V>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(Error::UnsupportedType("enum"))
    }

    fn deserialize_identifier<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(Error::UnsupportedType("identifier"))
    }

    fn deserialize_ignored_any<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(Error::UnsupportedType("ignored_any"))
    }
}

struct PrefixedSeqAccess<'a, 'de: 'a, R>
where
    R: std::io::Read,
{
    de: &'a mut Deserializer<'de, R>,
    remaining: usize,
}

impl<'de, 'a, R> de::SeqAccess<'de> for PrefixedSeqAccess<'a, 'de, R>
where
    R: std::io::Read,
{
    type Error = Error;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
    where
        T: de::DeserializeSeed<'de>,
    {
        if self.remaining == 0 {
            return Ok(None);
        }
        self.remaining -= 1;
        seed.deserialize(&mut *self.de).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[test]
    fn test_serializer() {
        let data: [u8; 60] = [
            1, // true
            0, // false
            1, // 1
            2, 0, 0, 0, 0, 0, 0, 0, // 2
            3, 0, 0, 0, 0, 0, 0, 0, // 3
            4, 0, 0, 0, 0, 0, 0, 0, // 4
            3, 0, 0, 0, 0, 0, 0, 0, 102, 111, 111, // "foo"
            3, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, // var_bytes prefix + [1, 2, 3]
            1, 2, 3, // fixed_bytes [1, 2, 3]
            1, 1, // Some(true)
            1, 0, // Some(false)
            0, // None
            // UnitStruct
            1, // NewTypeStrucdt(true)
            0, 1, // (false, true)
        ];

        #[derive(Debug, Deserialize, PartialEq)]
        struct UnitStruct;
        #[derive(Debug, Deserialize, PartialEq)]
        struct NewTypeStruct(bool);

        #[derive(Debug, Deserialize, PartialEq)]
        struct Test {
            b_true: bool,
            b_false: bool,
            unsigned8: u8,
            unsigned16: u16,
            unsigned32: u32,
            unsigned64: u64,
            string: String,
            var_bytes: Vec<u8>,   // dynamic size slice
            fixed_bytes: [u8; 3], // fixed size array
            some_true: Option<bool>,
            some_false: Option<bool>,
            none: Option<bool>,
            unit: UnitStruct,
            new_type: NewTypeStruct,
            tuple: (bool, bool),
        }

        let expected = Test {
            b_true: true,
            b_false: false,
            unsigned8: 1,
            unsigned16: 2,
            unsigned32: 3,
            unsigned64: 4,
            string: "foo".to_string(),
            var_bytes: vec![1, 2, 3],
            fixed_bytes: [1, 2, 3],
            some_true: Some(true),
            some_false: Some(false),
            none: None,
            unit: UnitStruct {},
            new_type: NewTypeStruct(true),
            tuple: (false, true),
        };

        let t: Test = from_reader(&mut &data[..]).unwrap();
        assert_eq!(t, expected);
    }
}
