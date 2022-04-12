use crate::sections::IDBSectionHeader;
use crate::utils::visitors;
use crate::utils::{LengthPrefixString, LengthPrefixVector};
use derivative::Derivative;
use enumflags2::{bitflags, BitFlags};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::default::Default;

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

#[derive(Deserialize, Default, Derivative)]
#[derivative(Debug)]
pub struct TILTypeInfo {
    #[serde(deserialize_with = "visitors::parse_til_initial_type_info")]
    pub initial_type_info: TILInitialTypeInfoType,
    #[serde(deserialize_with = "visitors::parse_null_terminated")]
    #[derivative(Debug = "ignore")]
    pub type_info: Vec<u8>,
    #[serde(deserialize_with = "visitors::parse_null_terminated_string")]
    #[derivative(Debug = "ignore")]
    pub cmt: String,
    #[serde(deserialize_with = "visitors::parse_null_terminated")]
    #[derivative(Debug = "ignore")]
    pub fields_buf: Vec<u8>,
    #[derivative(Debug = "ignore")]
    #[serde(deserialize_with = "visitors::parse_null_terminated")]
    pub fieldcmts: Vec<u8>,
    pub sclass: u8,
    #[serde(skip)]
    pub fields: Vec<String>,
}

#[derive(Deserialize, Default, Debug)]
pub struct TILBucket {
    pub ndefs: u32,
    #[serde(deserialize_with = "visitors::parse_length_prefix_vector")]
    pub data: LengthPrefixVector,
    #[serde(skip)]
    pub type_info: Vec<TILTypeInfo>,
}

#[derive(Deserialize, Default, Debug)]
pub struct TILBucketZip {
    pub ndefs: u32,
    pub size: u32,
    #[serde(deserialize_with = "visitors::parse_length_prefix_vector")]
    pub data: LengthPrefixVector,
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

#[derive(Deserialize, Default, Derivative)]
#[derivative(Debug)]
pub struct TILSection {
    #[derivative(Debug = "ignore")]
    #[serde(skip)]
    pub section_buffer: Vec<u8>,

    pub header: IDBSectionHeader,
    pub signature: [u8; 6],
    pub format: u32,
    pub flags: BitFlags<TILFlags>,
    #[serde(deserialize_with = "visitors::parse_length_prefix_string")]
    pub title: String,
    #[serde(deserialize_with = "visitors::parse_length_prefix_string")]
    pub base: String,
    pub id: u8,
    pub cm: u8,
    pub size_i: u8,
    pub size_b: u8,
    pub size_e: u8,
    pub def_align: u8,
    #[serde(skip)]
    pub optional: TILOptional,
}

#[derive(Default, Derivative)]
#[derivative(Debug)]
pub struct TILSection2 {
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
    pub syms: TILBucketType,
    pub type_ordinal_numbers: Option<u32>,
    pub types: TILBucketType,
    pub macros: TILBucketType,
}

fn visit_len_pref_str<'de, A>(seq: &mut A) -> Result<(u8, String), A::Error>
where
    A: SeqAccess<'de>,
{
    let len = seq.next_element::<u8>()?.unwrap();
    let str = String::from_utf8(
        (0..len)
            .map(|_| seq.next_element::<u8>().unwrap().unwrap())
            .collect::<Vec<u8>>(),
    )
    .unwrap();
    Ok((len, str))
}

struct Yep;
impl<'de> Visitor<'de> for Yep {
    type Value = TILSection2;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("Unexpected data")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let header = seq.next_element()?.unwrap();
        let signature = seq.next_element()?.unwrap();
        let format = seq.next_element()?.unwrap();
        let flags: BitFlags<TILFlags> = seq.next_element()?.unwrap();
        let (title_len, title) = visit_len_pref_str(&mut seq)?;
        let (base_len, base) = visit_len_pref_str(&mut seq)?;
        let id = seq.next_element()?.unwrap();
        let cm = seq.next_element()?.unwrap();
        let size_i = seq.next_element()?.unwrap();
        let size_b = seq.next_element()?.unwrap();
        let size_e = seq.next_element()?.unwrap();
        let def_align = seq.next_element()?.unwrap();
        println!("OK");

        let mut size_s: Option<u8> = None;
        let mut size_l: Option<u8> = None;
        let mut size_ll: Option<u8> = None;
        let mut size_ldbl: Option<u8> = None;
        let mut type_ordinal_numbers: Option<u32> = None;
        if flags.intersects(TILFlags::Esi) {
            size_s = Some(seq.next_element()?.unwrap());
            size_l = Some(seq.next_element()?.unwrap());
            size_ll = Some(seq.next_element()?.unwrap());
        }
        let syms = seq.next_element()?.unwrap();
        if flags.intersects(TILFlags::Sld) {
            size_ldbl = Some(seq.next_element()?.unwrap());
        }
        if flags.intersects(TILFlags::Ord) {
            type_ordinal_numbers = Some(seq.next_element()?.unwrap());
        }
        let types = seq.next_element()?.unwrap();
        let macros = seq.next_element()?.unwrap();

        Ok(TILSection2 {
            header,
            signature,
            format,
            flags,
            title_len,
            title,
            base_len,
            base,
            id,
            cm,
            size_i,
            size_b,
            size_e,
            def_align,
            size_s,
            size_l,
            size_ll,
            size_ldbl,
            syms,
            type_ordinal_numbers,
            types,
            macros,
            ..Default::default()
        })
    }
}

impl<'de> Deserialize<'de> for TILSection2 {
    fn deserialize<D>(deserializer: D) -> Result<TILSection2, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_tuple(usize::MAX, Yep)
    }
}
