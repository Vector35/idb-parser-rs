use crate::sections::IDBSectionHeader;
use crate::utils::parser::*;
use crate::{gen_field_opt, gen_parser, gen_parser_body};
use byteorder::ByteOrder;
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

#[derive(Default, Debug)]
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
    pub syms: TILBucketType,
    pub type_ordinal_numbers: Option<u32>,
    pub types: TILBucketType,
    pub macros: TILBucketType,
}

#[derive(Default, Debug)]
pub struct TILTypeInfo {
    pub flags: u32,
    pub name: String,
    pub ordinal: u64,
    pub type_info: Vec<u8>,
    pub cmt: String,
    pub fields_buf: Vec<u8>,
    pub fieldcmts: Vec<u8>,
    pub sclass: u8,
    pub fields: Vec<String>,
}

#[derive(Default, Debug)]
pub struct TILBucket {
    pub ndefs: u32,
    pub len: u32,
    pub data: Vec<u8>,
    pub type_info: Vec<TILTypeInfo>,
}

#[derive(Deserialize, Default, Debug)]
pub struct TILBucketZip {
    pub ndefs: u32,
    pub size: u32,
    pub data: Vec<u8>,
    #[serde(skip)]
    pub type_info: Vec<TILTypeInfo>,
}

#[derive(Debug)]
pub enum TILBucketType {
    None,
    Default(Option<TILBucket>),
    Zip(Option<TILBucketZip>),
}

impl Default for TILBucketType {
    fn default() -> Self {
        Self::None
    }
}

struct TypeInfoVec {
    ndefs: u32,
    vec: Vec<TILTypeInfo>,
}

gen_parser!(
    parse <TILTypeInfo> visit TypeInfoVisitor,
    |seq|<TILTypeInfo>,
    [
        flags, name, ordinal, type_info,
        fields_buf, cmt, fieldcmts, sclass,
        fields
    ],
    [
        flags,
        (name => consume_null_terminated_string(&mut seq)),
        (ordinal => .
            if (flags >> 31u32) != 0 {
                seq.next_element()?.unwrap()
            } else {
                seq.next_element::<u32>()?.unwrap() as u64
            }
        ),
        (type_info => consume_null_terminated(&mut seq)),
        (cmt => consume_null_terminated_string(&mut seq)),
        (fields_buf => consume_null_terminated(&mut seq)),
        (fieldcmts => consume_null_terminated(&mut seq)),
        sclass,
        (fields => . parse_len_prefix_str_vec(&fields_buf))
    ]
);

gen_parser!(
    parse <TypeInfoVec> visit TypeInfoVecVisitor,
    |seq|<TypeInfoVec>,
    [
        ndefs,
        vec
    ],
    [
        ndefs,
        (vec => . {
            (0..ndefs).map(|_| {
                seq.next_element::<TILTypeInfo>().unwrap().unwrap()
            }).collect()
        })
    ]
);

gen_parser!(
    parse <TILBucket> visit TILBucketVisitor,
    |seq|<TILBucket>,
    [
        ndefs,
        len,
        data,
        type_info
    ],
    [
        ndefs,
        len,
        (mut data => . {
                (0..len)
                    .map(|_| -> u8 { seq.next_element().unwrap_or_default().unwrap_or(0) })
                    .collect::<Vec<u8>>()
            }
        ),
        (type_info => . {
            (0..4).for_each(|_| data.insert(0, 0));
            byteorder::NativeEndian::write_u32(&mut data[0..4], ndefs);
            let collected = bincode::deserialize::<TypeInfoVec>(data.as_slice()).unwrap();
            (0..4).for_each(|_| {let _ = data.remove(0);});
            collected.vec
        })
    ]
);

gen_parser!(
    parse <TILSection> visit TILSectionVisitor,
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
        ((base_len, base) => consume_len_prefix_str(&mut seq)),
        ((title_len, title) => consume_len_prefix_str(&mut seq)),
        id,
        cm,
        size_i,
        size_b,
        size_e,
        def_align,
        (? size_s . flags.intersects(TILFlags::Esi)),
        (? size_l . flags.intersects(TILFlags::Esi)),
        (? size_ll . flags.intersects(TILFlags::Esi)),
        (syms => .
        if flags.intersects(TILFlags::Zip) {
            TILBucketType::Zip(
                match seq.next_element::<TILBucketZip>() {
                    Ok(ok) => ok,
                    Err(_) => None,
                }
            )
        } else {
            TILBucketType::Default(
                match seq.next_element::<TILBucket>() {
                    Ok(ok) => ok,
                    Err(_) => None,
                }
            )
        }),
        (? size_ldbl . flags.intersects(TILFlags::Sld)),
        (? type_ordinal_numbers . flags.intersects(TILFlags::Ord)),
        (types => .
        if flags.intersects(TILFlags::Zip) {
            TILBucketType::Zip(
                match seq.next_element::<TILBucketZip>() {
                    Ok(ok) => ok,
                    Err(_) => None,
                }
            )
        } else {
            TILBucketType::Default(
                match seq.next_element::<TILBucket>() {
                    Ok(ok) => ok,
                    Err(_) => None,
                }
            )
        }),
        (macros => .
        if flags.intersects(TILFlags::Zip) {
            TILBucketType::Zip(
                match seq.next_element::<TILBucketZip>() {
                    Ok(ok) => ok,
                    Err(_) => None,
                }
            )
        } else {
            TILBucketType::Default(
                match seq.next_element::<TILBucket>() {
                    Ok(ok) => ok,
                    Err(_) => None,
                }
            )
        })
    ]
);
