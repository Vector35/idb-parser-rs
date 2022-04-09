use crate::sections::til::{TILInitialTypeInfo, TILInitialTypeInfoType};
use crate::utils::{StringWithLength, VectorWithLength};
use serde::de::{SeqAccess, Visitor};
use serde::Deserializer;
use std::fmt;

struct NullTerminatedVisitor;
impl<'de> Visitor<'de> for NullTerminatedVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Expected valid string w/ length sequence.")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut vec: Vec<u8> = Vec::new();
        loop {
            let elem: u8 = seq.next_element().unwrap().unwrap();
            if elem == '\x00' as u8 {
                break;
            }
            vec.push(elem);
        }
        Ok(vec)
    }
}

struct VectorWithLengthVisitor;
impl<'de> Visitor<'de> for VectorWithLengthVisitor {
    type Value = VectorWithLength;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Expected valid vector w/ length sequence.")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let len: u32 = seq.next_element().unwrap().unwrap();
        if len == 0 {
            return Ok(VectorWithLength::default());
        }

        Ok(VectorWithLength {
            len,
            data: (0..len)
                .map(|_| -> u8 { seq.next_element().unwrap_or_default().unwrap_or(0) })
                .collect::<Vec<u8>>(),
        })
    }
}

struct StringVisitor;
impl<'de> Visitor<'de> for StringVisitor {
    type Value = StringWithLength;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Expected valid string w/ length sequence.")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let len: u8 = seq.next_element().unwrap().unwrap();
        Ok(StringWithLength {
            len,
            data: String::from_utf8_lossy(
                (0..len)
                    .map(|_| {
                        let elem: u8 = seq.next_element().unwrap().unwrap();
                        elem
                    })
                    .collect::<Vec<u8>>()
                    .as_slice(),
            )
            .to_string(),
        })
    }
}

struct InitialTypeInfoTypeVisitor;
impl<'de> Visitor<'de> for InitialTypeInfoTypeVisitor {
    type Value = TILInitialTypeInfoType;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Expected valid vector w/ length sequence.")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let flags: u32 = seq.next_element::<u32>().unwrap().unwrap();
        let mut vec: Vec<u8> = Vec::new();
        loop {
            let elem: u8 = seq.next_element().unwrap().unwrap();
            if elem == '\x00' as u8 {
                break;
            }
            vec.push(elem);
        }
        let name = String::from_utf8_lossy(vec.as_slice()).to_string();

        if (flags >> 31u32) != 0 {
            Ok(TILInitialTypeInfoType::Ordinal64(TILInitialTypeInfo {
                flags,
                name,
                ordinal: seq.next_element().unwrap().unwrap(),
            }))
        } else {
            Ok(TILInitialTypeInfoType::Ordinal32(TILInitialTypeInfo {
                flags,
                name,
                ordinal: seq.next_element().unwrap().unwrap(),
            }))
        }
    }
}

/*
   TODO: Fix all instances of deserializers using `deserialize_tuple(usize::MAX)`
   TODO: I'm using `usize::MAX` instead of the actual length due to the length
   TODO: typically being unknown and due to other deserialize methods try deserializing
   TODO: the first element assuming its a length.
*/

pub fn parse_cstr<'de, D: Deserializer<'de>>(d: D) -> Result<StringWithLength, D::Error> {
    d.deserialize_tuple(usize::MAX, StringVisitor)
}

pub fn parse_til_initial_type_info<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<TILInitialTypeInfoType, D::Error> {
    d.deserialize_tuple(usize::MAX, InitialTypeInfoTypeVisitor)
}

pub fn parse_null_terminated<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    d.deserialize_tuple(usize::MAX, NullTerminatedVisitor)
}

pub fn parse_null_terminated_string<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    Ok(String::from_utf8_lossy(
        d.deserialize_tuple(usize::MAX, NullTerminatedVisitor)
            .unwrap()
            .as_slice(),
    )
    .to_string())
}

pub fn parse_vec_len<'de, D: Deserializer<'de>>(d: D) -> Result<VectorWithLength, D::Error> {
    d.deserialize_tuple(usize::MAX, VectorWithLengthVisitor)
}
