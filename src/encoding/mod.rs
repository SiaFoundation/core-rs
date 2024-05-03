mod deserializer;
mod serializer;

// place the deserializer and serializer modules in the encoding module.
pub use deserializer::{from_reader, Deserializer, Error as DeserializeError};
pub use serializer::{serialize_array, to_bytes, to_writer, Error as SerializeError};
