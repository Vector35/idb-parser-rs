use crate::sections::IDBSectionHeader;
use crate::utils::visitors;
use crate::utils::{LengthPrefixString, LengthPrefixVector};
use derivative::Derivative;
use enumflags2::{bitflags, BitFlags};
use serde::Deserialize;
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
    pub title: LengthPrefixString,
    #[serde(deserialize_with = "visitors::parse_length_prefix_string")]
    pub base: LengthPrefixString,
    pub id: u8,
    pub cm: u8,
    pub size_i: u8,
    pub size_b: u8,
    pub size_e: u8,
    pub def_align: u8,
    #[serde(skip)]
    pub optional: TILOptional,
}
