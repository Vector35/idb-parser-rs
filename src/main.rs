use bincode::{deserialize, Options};
use derivative::Derivative;
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
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

#[derive(Deserialize, Default, Derivative)]
#[derivative(Debug)]
struct TILSection {
    #[derivative(Debug = "ignore")]
    #[serde(skip)]
    section_buffer: Vec<u8>,

    header: IDBSectionHeader,
    signature: [u8; 6],
    format: u32,
    flags: u32,
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
}

struct StringVisitor;
impl<'de> Visitor<'de> for StringVisitor {
    type Value = StringWithLength;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("???")
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
    // TODO: this len of 200 is completely arbitrary... fix l8r
    d.deserialize_tuple(200, StringVisitor)
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

impl From<IDBSection> for Option<TILSection> {
    fn from(section: IDBSection) -> Self {
        if section.header.length == 0 {
            None
        } else {
            Some(bincode::deserialize(section.section_buffer.as_slice()).unwrap())
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
