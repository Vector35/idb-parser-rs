use crate::sections::IDBSectionHeader;
use crate::utils::visitors;
use crate::utils::visitors::parse_null_terminated;
use crate::utils::{LengthPrefixString, LengthPrefixVector};
use bincode::config::{AllowTrailing, FixintEncoding, WithOtherIntEncoding, WithOtherTrailing};
use bincode::{DefaultOptions, Options};
use derivative::Derivative;
use enumflags2::{bitflags, BitFlags};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::default::Default;
use std::fmt::Formatter;

#[bitflags]
#[repr(u32)]
#[derive(Deserialize, Debug, Copy, Clone, PartialEq)]
pub enum TILFlags {
    Zip = 0x0001,
    Mac = 0x0002,
    Esi = 0x0004,
    Uni = 0x0008,
    Ord = 0x0010,
    Ali = 0x0020,
    Mod = 0x0040,
    Stm = 0x0080,
    Sld = 0x0100,
}

#[derive(Deserialize, Debug)]
pub enum TILInitialTypeInfoType {
    None,
    Ordinal32(TILInitialTypeInfo<u32>),
    Ordinal64(TILInitialTypeInfo<u64>),
}

impl Default for TILInitialTypeInfoType {
    fn default() -> Self {
        TILInitialTypeInfoType::None
    }
}

#[derive(Deserialize, Default, Debug)]
pub struct TILInitialTypeInfo<T> {
    pub flags: u32,
    #[serde(deserialize_with = "visitors::parse_null_terminated_string")]
    pub name: String,
    pub ordinal: T,
}

#[derive(Default, Derivative)]
pub struct TILTypeInfos {
    infos: Vec<TILTypeInfo>,
}

#[derive(Default, Derivative)]
#[derivative(Debug)]
pub struct TILTypeInfo {
    pub initial_type_info: TILInitialTypeInfoType,
    #[derivative(Debug = "ignore")]
    pub type_info: Vec<u8>,
    #[derivative(Debug = "ignore")]
    pub cmt: String,
    #[derivative(Debug = "ignore")]
    pub fields_buf: Vec<u8>,
    #[derivative(Debug = "ignore")]
    pub fieldcmts: Vec<u8>,
    pub sclass: u8,
    pub fields: Vec<String>,
}

#[derive(Deserialize, Default, Debug)]
pub struct TILBucket {
    pub ndefs: u32,
    #[serde(deserialize_with = "visitors::parse_length_prefix_vector")]
    pub data: Vec<u8>,
    #[serde(skip)]
    pub type_info: Vec<TILTypeInfo>,
}

#[derive(Deserialize, Default, Debug)]
pub struct TILBucketZip {
    pub ndefs: u32,
    pub size: u32,
    #[serde(deserialize_with = "visitors::parse_length_prefix_vector")]
    pub data: Vec<u8>,
    #[serde(skip)]
    pub type_info: Vec<TILTypeInfo>,
}

#[derive(Deserialize, Debug)]
pub enum TILBucketType {
    None,
    Default(TILBucket),
    Zip(TILBucketZip),
}

impl Default for TILBucketType {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Deserialize, Default, Debug)]
pub struct TILOptional {
    pub size_s: u8,
    pub size_l: u8,
    pub size_ll: u8,
    pub size_ldbl: u8,
    pub syms: TILBucketType,
    pub type_ordinal_numbers: u32,
    pub types: TILBucketType,
    pub macros: TILBucketType,
}

#[derive(Default, Derivative)]
#[derivative(Debug)]
pub struct TILSection {
    pub header: IDBSectionHeader,
    pub signature: [u8; 6],
    pub format: u32,
    pub flags: BitFlags<TILFlags>,
    pub title_len: u8,
    pub title: String,
    pub base_len: u8,
    pub base: String,
    pub id: u8,
    pub cm: u8,
    pub size_i: u8,
    pub size_b: u8,
    pub size_e: u8,
    pub def_align: u8,
    pub size_s: Option<u8>,
    pub size_l: Option<u8>,
    pub size_ll: Option<u8>,
    pub size_ldbl: Option<u8>,
    pub syms: Option<TILBucketType>,
    pub type_ordinal_numbers: Option<u32>,
    pub types: Option<TILBucketType>,
    pub macros: Option<TILBucketType>,
}

fn visit_null_terminated<'de, A>(seq: &mut A) -> Result<Vec<u8>, A::Error>
where
    A: SeqAccess<'de>,
{
    let mut vec: Vec<u8> = Vec::new();
    loop {
        let elem: u8 = seq.next_element()?.unwrap();
        if elem == '\x00' as u8 {
            break;
        }
        vec.push(elem);
    }
    Ok(vec)
}

struct Yep2;
impl<'de> Visitor<'de> for Yep2 {
    type Value = TILTypeInfos;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("Unexpected data")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let ndefs = seq.next_element::<u8>()?.unwrap();
        let mut infos = TILTypeInfos::default();
        for i in (0..ndefs) {
            let flags: u32 = seq.next_element::<u32>()?.unwrap();
            let name =
                String::from_utf8_lossy(visit_null_terminated(&mut seq)?.as_slice()).to_string();
            let initial_type_info = if (flags >> 31u32) != 0 {
                TILInitialTypeInfoType::Ordinal64(TILInitialTypeInfo {
                    flags,
                    name,
                    ordinal: seq.next_element()?.unwrap(),
                })
            } else {
                TILInitialTypeInfoType::Ordinal32(TILInitialTypeInfo {
                    flags,
                    name,
                    ordinal: seq.next_element()?.unwrap(),
                })
            };
            let type_info = visit_null_terminated(&mut seq)?;
            let cmt =
                String::from_utf8_lossy(visit_null_terminated(&mut seq)?.as_slice()).to_string();
            let fields_buf = visit_null_terminated(&mut seq)?;
            let fieldcmts = visit_null_terminated(&mut seq)?;
            let sclass = seq.next_element()?.unwrap();
            let mut pos = 0;
            let mut fields: Vec<String> = Vec::new();
            while pos < fields_buf.len() {
                let len = fields_buf[pos];
                fields.push(
                    String::from_utf8_lossy(&fields_buf[pos + 1..pos + len as usize]).to_string(),
                );
                pos += len as usize;
            }

            infos.infos.push(TILTypeInfo {
                initial_type_info,
                type_info,
                cmt,
                fields_buf,
                fieldcmts,
                sclass,
                fields,
            });
        }

        Ok(infos)
    }
}

impl<'de> Deserialize<'de> for TILTypeInfos {
    fn deserialize<D>(deserializer: D) -> Result<TILTypeInfos, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_tuple(usize::MAX, Yep2)
    }
}

fn visit_til_bucket_type<'de, A>(
    seq: &mut A,
    flags: &BitFlags<TILFlags>,
) -> Result<TILBucketType, A::Error>
where
    A: SeqAccess<'de>,
{
    if flags.intersects(TILFlags::Zip) {
        Ok(TILBucketType::Zip(TILBucketZip::default()))
    } else {
        let ndefs: u32 = seq.next_element()?.unwrap();
        let len: u32 = seq.next_element()?.unwrap();
        let mut data = if len != 0 {
            (0..len)
                .map(|_| -> u8 { seq.next_element().unwrap_or_default().unwrap_or(0) })
                .collect()
        } else {
            Vec::<u8>::new()
        };

        let type_info = if ndefs != 0 {
            data.insert(0, ndefs as u8);
            let collected = bincode::deserialize::<TILTypeInfos>(data.as_slice()).unwrap();
            data.remove(0);
            collected.infos
        } else {
            TILTypeInfos::default().infos
        };
        Ok(TILBucketType::Default(TILBucket {
            ndefs,
            data,
            type_info,
        }))
    }
}

fn visit_len_pref_str<'de, A>(seq: &mut A) -> Result<(u8, String), A::Error>
where
    A: SeqAccess<'de>,
{
    let len = seq.next_element::<u8>()?.unwrap();
    let str = String::from_utf8_lossy(
        (0..len)
            .map(|_| seq.next_element::<u8>().unwrap().unwrap())
            .collect::<Vec<u8>>()
            .as_slice(),
    )
    .to_string();
    Ok((len, str))
}

macro_rules! gen_parser {
    (parse <$ty:ty> visit $ident:ident, |$seq:ident|<$ret:ident>, [$($fields:ident),*], [$($tokens:tt),*]) => {
        struct $ident;
        impl<'de> Visitor<'de> for $ident {
            type Value = $ty;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("Unexpected data")
            }

            gen_parser_body!(
                |$seq|<$ret>,
                [$($fields),*],
                [$($tokens),*]
            );
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D>(deserializer: D) -> Result<$ty, D::Error>
            where
                D: Deserializer<'de>,
            {
                deserializer.deserialize_tuple(usize::MAX, $ident)
            }
        }
    };
}

macro_rules! gen_parser_body {
    (|$seq:ident|<$ret:ident>, [$($fields:ident),*], [$($tokens:tt),*]) => {
        fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut $seq = seq;
            $(
                gen_field_opt!($tokens, $seq);
            )*

            Ok($ret {
                $(
                    $fields,
                )*
            })
        }
    };
}

macro_rules! gen_field_opt {
    ($field:ident, $seq:ident) => {
        let $field = $seq.next_element()?.unwrap();
    };
    (($field:ident<$ty:ty>), $seq:ident) => {
        let $field: $ty = $seq.next_element()?.unwrap();
    };
    ((? $field:ident), $seq:ident) => {
        let $field = match $seq.next_element() {
            Ok(ok) => ok,
            Err(_) => None,
        };
    };
    ((? $field:ident . $body:expr), $seq:ident) => {
        let mut $field: Option<_> = None;
        if $body {
            $field = Some($seq.next_element()?.unwrap());
        }
    };
    ((? $field:ident => $body:expr), $seq:ident) => {
        let $field = match $body {
            Ok(ok) => Some(ok),
            Err(_) => None,
        };
    };
    (($field:ident => $body:expr), $seq:ident) => {
        let $field = match $body {
            Ok(ok) => ok,
            Err(err) => panic!("{:?}", err),
        };
    };
    // not proud of this one..
    ((($field:ident, $field2:ident) => $body:expr), $seq:ident) => {
        let ($field, $field2) = match $body {
            Ok(ok) => ok,
            Err(err) => panic!("{:?}", err),
        };
    };
}

gen_parser!(
    parse <TILSection> visit TILSection2Visitor,
    |seq|<TILSection>,
    [
        header, signature, format, flags,
        title_len, title, base_len, base,
        id, cm, size_i, size_b, size_e,
        def_align, size_s, size_l, size_ll,
        size_ldbl, syms, type_ordinal_numbers,
        types, macros
    ],
    [
        header,
        signature,
        format,
        (flags<BitFlags<TILFlags>>),
        ((base_len, base) => visit_len_pref_str(&mut seq)),
        ((title_len, title) => visit_len_pref_str(&mut seq)),
        id,
        cm,
        size_i,
        size_b,
        size_e,
        def_align,
        (? size_s . flags.intersects(TILFlags::Esi)),
        (? size_l . flags.intersects(TILFlags::Esi)),
        (? size_ll . flags.intersects(TILFlags::Esi)),
        (? syms => visit_til_bucket_type(&mut seq, &flags)),
        (? size_ldbl . flags.intersects(TILFlags::Sld)),
        (? type_ordinal_numbers . flags.intersects(TILFlags::Ord)),
        (? types => visit_til_bucket_type(&mut seq, &flags)),
        (? macros => visit_til_bucket_type(&mut seq, &flags))
    ]
);
