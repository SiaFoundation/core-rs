use byteorder::{LittleEndian, WriteBytesExt};
use serde::{
    ser::{self, SerializeSeq},
    Serialize,
};
use std::fmt::Display;
use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    Custom(String),

    #[error("Serializing type '{0}' is not supported")]
    UnsupportedType(&'static str),

    #[error("Can't serialize type when length is not available")]
    LengthUnavailable,

    #[error("Failed to write to io::write: {0}")]
    IO(#[from] io::Error),
}

// Implement ser::Error for Error
impl ser::Error for Error {
    fn custom<T>(msg: T) -> Self
    where
        T: Display,
    {
        Error::Custom(msg.to_string())
    }
}

pub fn to_bytes<T>(value: &T) -> Result<Vec<u8>, Error>
where
    T: Serialize,
{
    let mut buf = Vec::new();
    to_writer(&mut buf, value)?;
    Ok(buf)
}

pub fn to_writer<T, W>(writer: &mut W, value: &T) -> Result<(), Error>
where
    T: Serialize,
    W: io::Write,
{
    let mut serializer = Serializer { writer };
    value.serialize(&mut serializer)
}

pub struct Serializer<'a, W>
where
    W: io::Write,
{
    writer: &'a mut W,
}

impl<W: io::Write> ser::Serializer for &mut Serializer<'_, W> {
    // Result is written to internal io::Write
    type Ok = ();

    // Error is a standard error
    type Error = Error;

    // Associated types for keeping track of additional state while serializing
    // compound data structures like sequences and maps. In this case no
    // additional state is required beyond what is already stored in the
    // Serializer struct.
    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    fn serialize_bool(self, v: bool) -> Result<Self::Ok, Self::Error> {
        self.writer.write_u8(if v { 1 } else { 0 })?;
        Ok(())
    }

    fn serialize_i8(self, v: i8) -> Result<Self::Ok, Self::Error> {
        self.writer.write_i8(v)?;
        Ok(())
    }

    fn serialize_i16(self, v: i16) -> Result<Self::Ok, Self::Error> {
        self.writer.write_i16::<LittleEndian>(v)?;
        Ok(())
    }

    fn serialize_i32(self, v: i32) -> Result<Self::Ok, Self::Error> {
        self.writer.write_i32::<LittleEndian>(v)?;
        Ok(())
    }

    fn serialize_i64(self, v: i64) -> Result<Self::Ok, Self::Error> {
        self.writer.write_i64::<LittleEndian>(v)?;
        Ok(())
    }

    fn serialize_u8(self, v: u8) -> Result<Self::Ok, Self::Error> {
        self.writer.write_u8(v)?;
        Ok(())
    }

    fn serialize_u16(self, v: u16) -> Result<Self::Ok, Self::Error> {
        self.writer.write_u16::<LittleEndian>(v)?;
        Ok(())
    }

    fn serialize_u32(self, v: u32) -> Result<Self::Ok, Self::Error> {
        self.writer.write_u32::<LittleEndian>(v)?;
        Ok(())
    }

    fn serialize_u64(self, v: u64) -> Result<Self::Ok, Self::Error> {
        self.writer.write_u64::<LittleEndian>(v)?;
        Ok(())
    }

    fn serialize_f32(self, v: f32) -> Result<Self::Ok, Self::Error> {
        self.writer.write_f32::<LittleEndian>(v)?;
        Ok(())
    }

    fn serialize_f64(self, v: f64) -> Result<Self::Ok, Self::Error> {
        self.writer.write_f64::<LittleEndian>(v)?;
        Ok(())
    }

    fn serialize_char(self, v: char) -> Result<Self::Ok, Self::Error> {
        let mut buf: [u8; 4] = [0; 4];
        self.serialize_str(v.encode_utf8(&mut buf))
    }

    fn serialize_str(self, v: &str) -> Result<Self::Ok, Self::Error> {
        self.serialize_bytes(v.as_bytes())
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok, Self::Error> {
        let seq = self.serialize_seq(Some(v.len()))?;
        seq.writer.write_all(v)?;
        seq.end()
    }

    // 'none' is serialized as a '0' byte
    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        self.writer.write_all(&[0])?;
        Ok(())
    }

    // 'some' is serialized by writing a '1' byte followed by the value
    fn serialize_some<T: ?Sized>(self, value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize,
    {
        self.writer.write_all(&[1])?;
        value.serialize(self)
    }

    // units don't have a value so they are ignored
    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    // unit_structs don't have a value so they are ignored
    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    // newtype_variants are not supported
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        Err(Error::UnsupportedType("unit_variant"))
    }

    // As is done here, serializers are encouraged to treat newtype structs as
    // insignificant wrappers around the data they contain
    fn serialize_newtype_struct<T: ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize,
    {
        value.serialize(self)
    }

    // newtype_variants are not supported
    fn serialize_newtype_variant<T: ?Sized>(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize,
    {
        Err(Error::UnsupportedType("newtype_variant"))
    }

    // sequences have an 8 byte, little-endian encoded prefix describing their
    // length
    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        match len {
            Some(len) => {
                self.writer.write_u64::<LittleEndian>(len as u64)?;
                Ok(self)
            }
            None => Err(Error::LengthUnavailable),
        }
    }

    // serialize_tuple is called on fixed size arrays as well as tuples
    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        Ok(self)
    }

    // tuple structs are not supported
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        Err(Error::UnsupportedType("tuple_struct"))
    }

    // tuple variants are not supported
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Err(Error::UnsupportedType("tuple_variant"))
    }

    // maps are not supported
    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        Err(Error::UnsupportedType("map"))
    }

    // serializing a struct doesn't require any 'setup'
    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        Ok(self)
    }

    // struct variants are not supported
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        Err(Error::UnsupportedType("struct_variant"))
    }
}

// The following 7 impls deal with the serialization of compound types like
// sequences and maps. Serialization of such types is begun by a Serializer
// method and followed by zero or more calls to serialize individual elements of
// the compound type and one call to end the compound type.
//
// This impl is SerializeSeq so these methods are called after `serialize_seq`
// is called on the Serializer.
impl<'a, W: io::Write> ser::SerializeSeq for &'a mut Serializer<'_, W> {
    // Must match the `Ok` type of the serializer.
    type Ok = ();
    // Must match the `Error` type of the serializer.
    type Error = Error;

    // Serialize a single element of the sequence.
    fn serialize_element<T>(&mut self, value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    // Close the sequence.
    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

// Tuples are not supported
impl<'a, W: io::Write> ser::SerializeTuple for &'a mut Serializer<'_, W> {
    type Ok = ();
    type Error = Error;

    fn serialize_element<T>(&mut self, value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

// Tuple structs are serialized like their inner value
impl<'a, W: io::Write> ser::SerializeTupleStruct for &'a mut Serializer<'_, W> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

// Tuple variants aren't supported by the Sia encoding
impl<'a, W: io::Write> ser::SerializeTupleVariant for &'a mut Serializer<'_, W> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, _value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        panic!("unsupported type - this should never be called")
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

// Serializing maps is not supported
impl<'a, W: io::Write> ser::SerializeMap for &'a mut Serializer<'_, W> {
    type Ok = ();
    type Error = Error;

    // The Serde data model allows map keys to be any serializable type. JSON
    // only allows string keys so the implementation below will produce invalid
    // JSON if the key serializes as something other than a string.
    //
    // A real JSON serializer would need to validate that map keys are strings.
    // This can be done by using a different Serializer to serialize the key
    // (instead of `&mut **self`) and having that other serializer only
    // implement `serialize_str` and return an error on any other data type.
    fn serialize_key<T>(&mut self, _key: &T) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        panic!("unsupported type - this should never be called")
    }

    // It doesn't make a difference whether the colon is printed at the end of
    // `serialize_key` or at the beginning of `serialize_value`. In this case
    // the code is a bit simpler having it here.
    fn serialize_value<T>(&mut self, _value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        panic!("unsupported type - this should never be called")
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

// Structs are serialized one field after another.
impl<'a, W: io::Write> ser::SerializeStruct for &'a mut Serializer<'_, W> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, _key: &'static str, value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

// Struct variants are not supported
impl<'a, W: io::Write> ser::SerializeStructVariant for &'a mut Serializer<'_, W> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(
        &mut self,
        _key: &'static str,
        _value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        panic!("unsupported type - this should never be called")
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[test]
    fn test_struct() {
        #[derive(Serialize)]
        struct UnitStruct;
        #[derive(Serialize)]
        struct NewTypeStruct(bool);

        #[derive(Serialize)]
        struct Test {
            b_true: bool,
            b_false: bool,
            signed8: i8,
            signed16: i16,
            signed32: i32,
            signed64: i64,
            unsigned8: u8,
            unsigned16: u16,
            unsigned32: u32,
            unsigned64: u64,
            float32: f32,
            float64: f64,
            character8: char,
            character16: char,
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

        let test = Test {
            b_true: true,
            b_false: false,
            signed8: -4,
            signed16: -3,
            signed32: -2,
            signed64: -1,
            unsigned8: 1,
            unsigned16: 2,
            unsigned32: 3,
            unsigned64: 4,
            float32: 0.75,
            float64: 1.5,
            character8: 'a',
            character16: '❤',
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
        let expected = [
            1,   // true
            0,   // false
            252, // -4
            253, 255, // -3
            254, 255, 255, 255, // -2
            255, 255, 255, 255, 255, 255, 255, 255, // -1
            1,   // 1
            2, 0, // 2
            3, 0, 0, 0, // 3
            4, 0, 0, 0, 0, 0, 0, 0, // 4
            0, 0, 64, 63, // 0.75
            0, 0, 0, 0, 0, 0, 248, 63, // 1.5
            1, 0, 0, 0, 0, 0, 0, 0, // 'a'
            97, 3, 0, 0, 0, 0, 0, 0, 0, 226, 157, 164, // '❤'
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
        assert_eq!(to_bytes(&test).unwrap(), expected);
    }
}
