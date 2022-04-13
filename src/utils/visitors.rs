use crate::sections::til::{TILInitialTypeInfo, TILInitialTypeInfoType};
use crate::utils::{LengthPrefixString, LengthPrefixVector};
use serde::de::{SeqAccess, Visitor};
use serde::Deserializer;
use std::fmt;

/// This macro just removes lots of boiler plate that is needed for
/// creating a visitor in serde.
///
/// # Parameters
/// * `StructName`- Name of the structure that will contain visitor
/// * `parser_name` || `(parser_name...)` - Name of the parser function that serde can reference
/// * `InternalType` - The internal type that serde will hold and expect from the return of visitor
/// * `|seq|` - The name chosen to reference the sequence of elements
/// * `{}` - Sequence processing block
/// * `|d|<RetTy>` - The name chosen to reference the deserializer <return type of deserializer>
/// * `{}` || `{}...` -  Deserialization processing block
///
/// # Usage
/// ```
/// gen_visitor!(
///     impl StructName fn (parser_name, ...) for InternalType
///     |seq| { process_sequence(seq) },
///     |d|<RetTy> { process_deserializer(d) }, ...
/// )
/// ```
macro_rules! gen_visitor {
    (impl $visitor_name:ident fn $parse_name:ident for $type_name:ty, |$seq:ident|$visit_seq:expr, |$d:ident|<$ret:ty>$parse:expr) => {
        gen_visitor!(impl $visitor_name fn ($parse_name) for $type_name, |$seq|$visit_seq, |$d|<$ret>$parse);
    };
    (impl $visitor_name:ident fn ($($parse_name:ident),*) for $type_name:ty, |$seq:ident|$visit_seq:expr, $(|$d:ident|<$ret:ty>$parse:expr),*) => {
        struct $visitor_name;
        impl<'de> Visitor<'de> for $visitor_name {
            type Value = $type_name;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("Unexpected data")
            }

            fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut $seq = seq;
                $visit_seq
            }
        }

        $(
            pub fn $parse_name<'de, D: Deserializer<'de>>(d: D) -> Result<$ret, D::Error> {
                let $d = d;
                $parse
            }
        )*
    };
}

/*
   TODO: Fix all instances of deserializers using `deserialize_tuple(usize::MAX)`
   TODO: I'm using `usize::MAX` instead of the actual length due to the length
   TODO: typically being unknown and due to other deserialize methods attempting
   TODO: to deserialize the first element assuming its a length.
*/

gen_visitor!(
    impl NullTerminatedVisitor fn (parse_null_terminated, parse_null_terminated_string) for Vec<u8>,
    |seq| {
        let mut vec: Vec<u8> = Vec::new();
        loop {
            let elem: u8 = seq.next_element().unwrap().unwrap();
            if elem == '\x00' as u8 {
                break;
            }
            vec.push(elem);
        }
        Ok(vec)
    },
    |d|<Vec<u8>> d.deserialize_tuple(usize::MAX, NullTerminatedVisitor),
    |d|<String> {
        Ok(String::from_utf8_lossy(
            d.deserialize_tuple(usize::MAX, NullTerminatedVisitor)
                .unwrap()
                .as_slice(),
        )
        .to_string())
    }
);

gen_visitor!(
    impl LengthPrefixVectorVisitor fn parse_length_prefix_vector for Vec<u8>,
    |seq| {
        let len: u32 = seq.next_element().unwrap().unwrap();
        if len == 0 {
            return Ok(Vec::new());
        }

        Ok(
            (0..len)
                .map(|_| -> u8 { seq.next_element().unwrap_or_default().unwrap_or(0) })
                .collect::<Vec<u8>>()
        )
    },
    |d|<Vec<u8>> d.deserialize_tuple(usize::MAX, LengthPrefixVectorVisitor)
);

gen_visitor!(
    impl LengthPrefixStringVisitor fn parse_length_prefix_string for String,
    |seq| {
        let len: u8 = seq.next_element().unwrap().unwrap();
        Ok(
            String::from_utf8_lossy(
                (0..len)
                    .map(|_| {
                        let elem: u8 = seq.next_element().unwrap().unwrap();
                        elem
                    })
                    .collect::<Vec<u8>>()
                    .as_slice(),
            ).to_string()
        )
    },
    |d|<String> {
        d.deserialize_tuple(usize::MAX, LengthPrefixStringVisitor)
    }
);

gen_visitor!(
    impl TILInitialTypeInfoTypeVisitor fn parse_til_initial_type_info for TILInitialTypeInfoType,
    |seq| {
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
    },
    |d|<TILInitialTypeInfoType> d.deserialize_tuple(usize::MAX, TILInitialTypeInfoTypeVisitor)
);
