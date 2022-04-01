use bincode::{deserialize, Options};
use derivative::Derivative;
use enumflags2::{bitflags, make_bitflags, BitFlags};
use memoffset::{offset_of, span_of};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::borrow::Borrow;
use std::default::Default;
use std::ffi::{CString, OsString};
use std::fmt;

#[derive(Default, Deserialize, Debug)]
struct IDBHeaderSerialize {
    signature: [u8; 4],
    _unk: u16,
    offset1: u64,
    offset2: u64,
    _unk2: u32,
    sig2: u32,
    version: u16,
    offset3: u64,
    offset4: u64,
    offset5: u64,
    checksum1: u32,
    checksum2: u32,
    checksum3: u32,
    checksum4: u32,
    checksum5: u32,
    offset6: u64,
    checksum6: u32,
}

#[derive(Default, Debug)]
struct IDBHeader {
    offsets: Vec<u64>,
    checksums: Vec<u32>,
    deserialized: IDBHeaderSerialize,
}

enum Error {
    InvalidSignature,
    InvalidSecondarySignature,
    UnsupportedIDBVersion,
}

impl IDBHeader {
    pub fn new(bytes: &[u8]) -> Result<Self, Error> {
        let deserialized: IDBHeaderSerialize =
            bincode::deserialize(bytes).expect("Failed to deserialize header.");
        let header = Self {
            offsets: vec![
                deserialized.offset1,
                deserialized.offset2,
                deserialized.offset3,
                deserialized.offset4,
                deserialized.offset5,
                deserialized.offset6,
            ],
            checksums: vec![
                deserialized.checksum1,
                deserialized.checksum2,
                deserialized.checksum3,
                deserialized.checksum4,
                deserialized.checksum5,
                deserialized.checksum6,
            ],
            deserialized,
        };

        let possible_sigs = ["IDA0", "IDA1", "IDA2"];
        if !possible_sigs.contains(&header.signature().as_str()) {
            return Err(Error::InvalidSignature);
        } else if header.deserialized.sig2 != 0xAABBCCDD {
            return Err(Error::InvalidSecondarySignature);
        } else if header.deserialized.version != 0x6 {
            return Err(Error::UnsupportedIDBVersion);
        }

        Ok(header)
    }

    pub fn signature(&self) -> String {
        return String::from_utf8_lossy(&self.deserialized.signature).to_string();
    }
}

#[derive(Default, Deserialize, Debug)]
struct IDBSectionHeader {
    compression_method: u8,
    length: u64,
}

#[derive(Deserialize, Default, Derivative)]
#[derivative(Debug)]
struct IDBSection {
    #[derivative(Debug = "ignore")]
    #[serde(skip)]
    section_buffer: Vec<u8>,
    header: IDBSectionHeader,
}

#[derive(Deserialize, Default, Derivative)]
#[derivative(Debug)]
struct BranchEntryPointer {
    page: u32,
    offset: u16,
}

#[derive(Deserialize, Default, Derivative)]
#[derivative(Debug)]
struct LeafEntryPointer {
    common_prefix: u16,
    _pad: u16,
    offset: u16,
}

#[derive(Deserialize, Default, Derivative, Clone)]
#[derivative(Debug)]
struct KeyValueEntry {
    key: Vec<u8>,
    value: Vec<u8>,
    is_leaf: bool,
}

#[derive(Default, Derivative)]
#[derivative(Debug)]
struct Page {
    pointer: u32,
    entry_count: u16,
    pub kv_entries: Vec<KeyValueEntry>,
}

impl Page {
    pub fn new(data: &[u8]) -> Self {
        let pointer = deserialize(&data).unwrap();
        let entry_count = deserialize(&data[4..]).unwrap();
        let kv_entries = Page::parse_entries(entry_count, pointer == 0, data);
        Self {
            pointer,
            entry_count,
            kv_entries,
        }
    }

    fn parse_entries(entry_count: u16, is_leaf: bool, contents: &[u8]) -> Vec<KeyValueEntry> {
        let mut leaf_key = Vec::<u8>::new();
        (0..entry_count)
            .into_iter()
            .map(|index| {
                if is_leaf {
                    let leaf_ptr: LeafEntryPointer =
                        bincode::deserialize(&contents[6 + (index * 6) as usize..]).unwrap();
                    let key_length: u16 =
                        bincode::deserialize(&contents[leaf_ptr.offset as usize..]).unwrap();
                    let value_length: u16 = bincode::deserialize(
                        &contents[(leaf_ptr.offset + 2 + key_length) as usize..],
                    )
                    .unwrap();

                    let value_offset = (leaf_ptr.offset + 4 + key_length) as usize;
                    let value =
                        contents[value_offset..value_offset + value_length as usize].to_vec();

                    let key_offset = (leaf_ptr.offset + 2) as usize;
                    let key_no_prefix =
                        contents[key_offset..key_offset + key_length as usize].to_vec();
                    let key = if leaf_ptr.common_prefix == 0 {
                        [leaf_key.clone(), key_no_prefix].concat()
                    } else {
                        [
                            leaf_key[..leaf_ptr.common_prefix as usize].to_vec(),
                            key_no_prefix,
                        ]
                        .concat()
                    };
                    leaf_key = key.clone();

                    KeyValueEntry {
                        key,
                        value,
                        is_leaf: true,
                    }
                } else {
                    let branch_ptr: BranchEntryPointer =
                        bincode::deserialize(&contents[6 + (index * 6) as usize..]).unwrap();

                    let key_length: u16 =
                        bincode::deserialize(&contents[branch_ptr.offset as usize..]).unwrap();
                    let value_length: u16 = bincode::deserialize(
                        &contents[(branch_ptr.offset + 2 + key_length) as usize..],
                    )
                    .unwrap();

                    let value_offset = (branch_ptr.offset + 4 + key_length) as usize;
                    let value =
                        contents[value_offset..value_offset + value_length as usize].to_vec();
                    let key_offset = (branch_ptr.offset + 2) as usize;
                    let key = contents[key_offset..key_offset + key_length as usize].to_vec();
                    leaf_key = key.clone();

                    KeyValueEntry {
                        key,
                        value,
                        is_leaf: false,
                    }
                }
            })
            .collect()
    }
}

#[derive(Deserialize, Default, Derivative)]
#[derivative(Debug)]
struct ID0Section {
    #[derivative(Debug = "ignore")]
    #[serde(skip)]
    section_buffer: Vec<u8>,
    #[serde(skip)]
    btree_version: f32,

    header: IDBSectionHeader,
    next_free_offset: u32,
    page_size: u16,
    root_page: u32,
    record_count: u32,
    page_count: u32,
    _unk: u8,
    signature: [u8; 25],
}

impl ID0Section {
    pub fn signature(&self) -> String {
        String::from_utf8_lossy(&self.signature).to_string()
    }

    pub fn is_valid(&self) -> bool {
        String::from_utf8_lossy(&self.signature).starts_with("B-tree")
    }

    pub fn get_page(&self, page_number: u16) -> Page {
        let offset = self.page_size as usize * page_number as usize;
        let page_buf = &self.section_buffer[offset..(offset + self.page_size as usize)];
        Page::new(page_buf)
    }
}

#[derive(Deserialize, Default, Derivative)]
#[derivative(Debug)]
struct ID1Section {
    #[derivative(Debug = "ignore")]
    #[serde(skip)]
    section_buffer: Vec<u8>,

    header: IDBSectionHeader,
}

#[derive(Deserialize, Default, Derivative)]
#[derivative(Debug)]
struct NAMSection {
    #[derivative(Debug = "ignore")]
    #[serde(skip)]
    section_buffer: Vec<u8>,

    header: IDBSectionHeader,
}

#[derive(Deserialize, Default, Derivative)]
#[derivative(Debug)]
struct SEGSection {
    #[derivative(Debug = "ignore")]
    #[serde(skip)]
    section_buffer: Vec<u8>,

    header: IDBSectionHeader,
}

#[derive(Default, Debug)]
struct StringWithLength {
    len: u8,
    data: String,
}

#[bitflags]
#[repr(u32)]
#[derive(Deserialize, Debug, Copy, Clone, PartialEq)]
enum TILFlags {
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

#[derive(Deserialize, Default, Debug)]
struct TILInitialTypeInfo {
    flags: u32,
    name: String,
    ordinal: u64,
}

#[derive(Deserialize, Default, Debug)]
struct TILTypeInfo {
    flags: u32,
    #[serde(deserialize_with = "parse_null_terminated_string")]
    name: String,
    ordinal: u64,
    #[serde(deserialize_with = "parse_null_terminated")]
    type_info: Vec<u8>,
    #[serde(deserialize_with = "parse_null_terminated_string")]
    cmt: String,
    #[serde(deserialize_with = "parse_null_terminated")]
    fields_buf: Vec<u8>,
    #[serde(deserialize_with = "parse_null_terminated")]
    fieldcmts: Vec<u8>,
    sclass: u8,
}

#[derive(Deserialize, Default, Debug)]
struct TILBucket {
    ndefs: u32,
    #[serde(deserialize_with = "parse_vec_len")]
    data: VectorWithLength,
    #[serde(skip)]
    type_info: Vec<TILTypeInfo>,
}

#[derive(Deserialize, Default, Debug)]
struct TILBucketZip {
    ndefs: u32,
    size: u32,
    #[serde(deserialize_with = "parse_vec_len")]
    data: VectorWithLength,
    #[serde(skip)]
    type_info: Vec<TILTypeInfo>,
}

#[derive(Deserialize, Debug)]
enum TILBucketType {
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
struct VectorWithLength {
    len: u32,
    data: Vec<u8>,
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

fn parse_vec_len<'de, D: Deserializer<'de>>(d: D) -> Result<VectorWithLength, D::Error> {
    // TODO: Fix this, i'm currently using `usize::MAX` instead of an actual length
    // TODO: because the other deserialize methods try deserializing the first element
    // TODO: to find a length.
    d.deserialize_tuple(usize::MAX, VectorWithLengthVisitor)
}

#[derive(Deserialize, Default, Debug)]
struct TILOptional {
    size_s: u8,
    size_l: u8,
    size_ll: u8,
    size_ldbl: u8,
    syms: TILBucketType,
    type_ordinal_numbers: u32,
    types: TILBucketType,
    macros: TILBucketType,
}

#[derive(Deserialize, Default, Derivative)]
#[derivative(Debug)]
struct TILSection {
    #[derivative(Debug = "ignore")]
    #[serde(skip)]
    section_buffer: Vec<u8>,

    header: IDBSectionHeader,
    signature: [u8; 6],
    format: u32,
    flags: BitFlags<TILFlags>,
    #[serde(deserialize_with = "parse_cstr")]
    title: StringWithLength,
    #[serde(deserialize_with = "parse_cstr")]
    base: StringWithLength,
    id: u8,
    cm: u8,
    size_i: u8,
    size_b: u8,
    size_e: u8,
    def_align: u8,
    #[serde(skip)]
    optional: TILOptional,
}

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

fn parse_null_terminated<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    // TODO: Fix this, i'm currently using `usize::MAX` instead of an actual length
    // TODO: because the other deserialize methods try deserializing the first element
    // TODO: to find a length.
    d.deserialize_tuple(usize::MAX, NullTerminatedVisitor)
}

fn parse_null_terminated_string<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    // TODO: Fix this, i'm currently using `usize::MAX` instead of an actual length
    // TODO: because the other deserialize methods try deserializing the first element
    // TODO: to find a length.
    Ok(String::from_utf8_lossy(
        d.deserialize_tuple(usize::MAX, NullTerminatedVisitor)
            .unwrap()
            .as_slice(),
    )
    .to_string())
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

fn parse_cstr<'de, D: Deserializer<'de>>(d: D) -> Result<StringWithLength, D::Error> {
    // TODO: Fix this, i'm currently using `usize::MAX` instead of an actual length
    // TODO: because the other deserialize methods try deserializing the first element
    // TODO: to find a length.
    d.deserialize_tuple(usize::MAX, StringVisitor)
}

#[derive(Deserialize, Default, Derivative)]
#[derivative(Debug)]
struct ID2Section {
    #[derivative(Debug = "ignore")]
    #[serde(skip)]
    section_buffer: Vec<u8>,

    header: IDBSectionHeader,
}

#[derive(Default, Debug)]
struct IDB {
    header: IDBHeader,
    id0: Option<ID0Section>,
    id1: Option<ID1Section>,
    nam: Option<NAMSection>,
    seg: Option<SEGSection>,
    til: Option<TILSection>,
    id2: Option<ID2Section>,
}

impl From<IDBSection> for Option<ID0Section> {
    fn from(section: IDBSection) -> Self {
        if section.header.length == 0 {
            None
        } else {
            let mut res: ID0Section =
                bincode::deserialize(section.section_buffer.as_slice()).unwrap();
            res.btree_version = res
                .signature()
                .chars()
                .filter(|c| c.is_digit(10) || *c == '.')
                .take(3)
                .collect::<String>()
                .parse::<f32>()
                .unwrap();
            res.section_buffer = section.section_buffer[9..].to_vec();

            if res.is_valid() {
                Some(res)
            } else {
                None
            }
        }
    }
}

impl From<IDBSection> for Option<ID1Section> {
    fn from(section: IDBSection) -> Self {
        if section.header.length == 0 {
            None
        } else {
            Some(ID1Section::default())
        }
    }
}

impl From<IDBSection> for Option<NAMSection> {
    fn from(section: IDBSection) -> Self {
        if section.header.length == 0 {
            None
        } else {
            Some(NAMSection::default())
        }
    }
}

impl From<IDBSection> for Option<SEGSection> {
    fn from(section: IDBSection) -> Self {
        if section.header.length == 0 {
            None
        } else {
            Some(SEGSection::default())
        }
    }
}

struct Consumer<'a> {
    offset: usize,
    buf: &'a Vec<u8>,
    flags: Option<BitFlags<TILFlags>>,
}

impl<'a> Consumer<'a> {
    fn new_with_flags(offset: usize, buf: &'a Vec<u8>, flags: BitFlags<TILFlags>) -> Consumer<'a> {
        Consumer {
            offset,
            buf,
            flags: Some(flags),
        }
    }

    fn new(offset: usize, buf: &'a Vec<u8>) -> Consumer<'a> {
        Consumer {
            offset,
            buf,
            flags: None,
        }
    }

    fn consume<T>(&mut self) -> T
    where
        T: serde::de::Deserialize<'a>,
    {
        let deserialized = bincode::deserialize(&self.buf[self.offset..]).unwrap();
        self.offset += std::mem::size_of_val(&deserialized);
        deserialized
    }

    fn consume_type_info(&mut self) -> Option<TILTypeInfo> {
        if self.offset > self.buf.len() {
            None
        } else {
            let ti = bincode::deserialize::<TILTypeInfo>(&self.buf[self.offset..]).unwrap();
            let off = std::mem::size_of_val(&ti.flags)
                + std::mem::size_of_val(&ti.ordinal)
                + std::mem::size_of_val(&ti.sclass)
                + ti.name.len()
                + ti.type_info.len()
                + ti.fieldcmts.len()
                + ti.fieldcmts.len()
                + ti.cmt.len();
            println!("ti.name.len()->>{:#x}", ti.name.len());
            println!("ti.type_info.len()->>{:#x}", ti.type_info.len());
            println!("ti.cmt.len()->>{:#x}", ti.cmt.len());
            println!("ti.fields_buf.len()->>{:#x}", ti.fields_buf.len());
            println!("ti.fieldcmts.len()->>{:#x}", ti.fieldcmts.len());
            println!("offset->>{:#x}", off);
            println!("totaloffset->>{:#x}", self.offset);
            self.offset += off;
            Some(ti)
        }
    }

    fn consume_bucket(&mut self) -> TILBucketType {
        if self.offset > self.buf.len() {
            TILBucketType::None
        } else {
            let bucket = if self.flags.unwrap().intersects(TILFlags::Zip) {
                let mut zip =
                    bincode::deserialize::<TILBucketZip>(&self.buf[self.offset..]).unwrap();
                TILBucketType::Zip(zip)
            } else {
                let mut def = bincode::deserialize::<TILBucket>(&self.buf[self.offset..]).unwrap();
                if def.data.len > 0 {
                    let mut type_consumer = Consumer::new(0, &def.data.data);
                    for def_index in 0..def.ndefs {
                        println!("len->>{}", def.data.len);

                        def.type_info
                            .push(type_consumer.consume_type_info().unwrap());
                        println!("TypeInfo->>{:#x?}", def.type_info.last().unwrap());
                    }
                }
                /*
                   defs = []
                   offset = 0
                   for _ in range(self.ndefs):
                       _def = TILTypeInfo(self.format)
                       offset = _def.vsParse(buf, offset=offset)
                       defs.append(_def)
                */

                TILBucketType::Default(def)
            };

            self.offset += std::mem::size_of::<u64>()
                + match &bucket {
                    TILBucketType::Zip(zip) => zip.data.len as usize,
                    TILBucketType::Default(default) => default.data.len as usize,
                    _ => 0usize,
                };

            bucket
        }
    }
}

impl From<IDBSection> for Option<TILSection> {
    fn from(section: IDBSection) -> Self {
        if section.header.length == 0 {
            None
        } else {
            let mut til_section: TILSection =
                bincode::deserialize(section.section_buffer.as_slice()).unwrap();

            let mut consumer =
                Consumer::new_with_flags(0x51, &section.section_buffer, til_section.flags.clone());

            if til_section.flags.intersects(TILFlags::Esi) {
                til_section.optional.size_s = consumer.consume();
                til_section.optional.size_l = consumer.consume();
                til_section.optional.size_ll = consumer.consume();
            }

            if til_section.flags.intersects(TILFlags::Sld) {
                til_section.optional.size_ldbl = consumer.consume();
            }

            til_section.optional.syms = consumer.consume_bucket();

            if til_section.flags.intersects(TILFlags::Ord) {
                til_section.optional.type_ordinal_numbers = consumer.consume();
            }

            til_section.optional.types = consumer.consume_bucket();
            til_section.optional.macros = consumer.consume_bucket();

            Some(til_section)
        }
    }
}

impl From<IDBSection> for Option<ID2Section> {
    fn from(section: IDBSection) -> Self {
        if section.header.length == 0 {
            None
        } else {
            Some(ID2Section::default())
        }
    }
}

impl IDB {
    pub fn new(bytes: &[u8]) -> Self {
        let header = IDBHeader::new(bytes).ok().expect("Invalid IDB header");
        let mut result = Self {
            header: Default::default(),
            id0: None,
            id1: None,
            nam: None,
            seg: None,
            til: None,
            id2: None,
        };

        header
            .offsets
            .iter()
            .map(|&offset| {
                if offset == 0 {
                    IDBSection::default()
                } else {
                    let sec_start = &bytes[offset as usize..];
                    let header: IDBSectionHeader = bincode::deserialize(sec_start).unwrap();
                    IDBSection {
                        section_buffer: sec_start[..header.length as usize].to_vec(),
                        header,
                    }
                }
            })
            .enumerate()
            .for_each(|(index, section)| {
                match index {
                    0 => result.id0 = section.into(),
                    1 => result.id1 = section.into(),
                    2 => result.nam = section.into(),
                    3 => result.seg = section.into(),
                    4 => result.til = section.into(),
                    5 => result.id2 = section.into(),
                    _ => (),
                };
            });
        result.header = header;

        result
    }
}

fn main() {
    let idb_bytes = include_bytes!("/Users/admin/projects/idb/complicated-gcc.i64");
    let now = std::time::Instant::now();
    let idb = IDB::new(idb_bytes.as_slice());
    println!("time to parse: {} ns", now.elapsed().as_nanos());

    println!("{:#?}", idb);
    println!("{:?}", idb.id0.as_ref().unwrap().get_page(1).kv_entries);
    println!("{:?}", idb.id0.as_ref().unwrap().get_page(2).kv_entries);
    println!("{:?}", idb.id0.as_ref().unwrap().get_page(3).kv_entries);
    println!("{:?}", idb.id0.as_ref().unwrap().get_page(4).kv_entries);
    println!("{:?}", idb.id0.as_ref().unwrap().get_page(5).kv_entries);
    println!("{:?}", idb.id0.as_ref().unwrap().get_page(6).kv_entries);
    println!("{:?}", idb.id0.as_ref().unwrap().get_page(7).kv_entries);
    println!("{:?}", idb.id0.as_ref().unwrap().get_page(8).kv_entries);
    println!("{:?}", idb.id0.as_ref().unwrap().get_page(9).kv_entries);
}
