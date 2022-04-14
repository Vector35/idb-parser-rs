use crate::idb::idb::IDBError::{DeserializingError, InvalidHeader};
use crate::sections::{
    id0::ID0Section, id1::ID1Section, id2::ID2Section, nam::NAMSection, seg::SEGSection,
    til::TILFlags, til::TILSection, IDBSection, IDBSectionHeader,
};
use crate::utils::parser::*;
use crate::{gen_field_opt, gen_parser, gen_parser_body};
use bincode::ErrorKind;
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::default::Default;

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

#[derive(Default, Debug)]
pub struct IDB {
    header: IDBHeader,
    pub id0: Option<ID0Section>,
    pub id1: Option<ID1Section>,
    pub nam: Option<NAMSection>,
    pub seg: Option<SEGSection>,
    pub til: Option<TILSection>,
    pub id2: Option<ID2Section>,
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
            match bincode::deserialize::<TILSection>(section.section_buffer.as_slice()) {
                Ok(sec) => Some(sec),
                Err(_) => None,
            }
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

#[derive(Default, Deserialize, Debug)]
pub struct IDBHeader2 {
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

impl IDBHeader2 {
    fn is_valid(&self) -> bool {
        let possible_sigs = ["IDA0", "IDA1", "IDA2"];

        possible_sigs.contains(
            &String::from_utf8_lossy(&self.signature)
                .to_string()
                .as_str(),
        ) && self.sig2 == 0xAABBCCDD
            && self.version == 0x6
    }
}

#[derive(Default, Debug)]
pub struct IDB2 {
    header: IDBHeader2,
    pub id0: Option<ID0Section>,
    pub id1: Option<ID1Section>,
    pub nam: Option<NAMSection>,
    pub seg: Option<SEGSection>,
    pub til: Option<TILSection>,
    pub id2: Option<ID2Section>,
}

gen_parser!(
    parse <IDB2> visit IDB2Visitor,
    |seq|<IDB2>,
    [
        header, id0, id1,
        nam, seg, til, id2
    ],
    [
        header,
        (id0 => . None),
        (id1 => . None),
        (nam => . None),
        (seg => . None),
        (til => . None),
        (id2 => . None)
    ]
);

#[derive(Debug)]
pub enum IDBError {
    DeserializingError,
    InvalidHeader,
    InvalidOffset,
}

impl From<Box<ErrorKind>> for IDBError {
    fn from(_: Box<ErrorKind>) -> Self {
        DeserializingError
    }
}

impl IDB2 {
    fn deserialize_section<'de, T>(bytes: &'de [u8], offset: usize) -> Result<T, IDBError>
    where
        T: Deserialize<'de>,
    {
        if offset != 0 {
            let sect_header = bincode::deserialize::<IDBSectionHeader>(&bytes[offset..])?;
            Ok(bincode::deserialize::<T>(
                &bytes[offset as usize..(offset + sect_header.length as usize)],
            )?)
        } else {
            Err(IDBError::InvalidOffset)
        }
    }

    pub fn new(bytes: &[u8]) -> Result<Self, IDBError> {
        let mut idb = bincode::deserialize::<Self>(bytes)?;
        if !idb.header.is_valid() {
            Err(InvalidHeader)
        } else {
            let offsets = vec![
                idb.header.offset1 as usize,
                idb.header.offset2 as usize,
                idb.header.offset3 as usize,
                idb.header.offset4 as usize,
                idb.header.offset5 as usize,
                idb.header.offset6 as usize,
            ];

            for (index, offset) in offsets.into_iter().enumerate() {
                match index {
                    4 => {
                        idb.til = Some(IDB2::deserialize_section::<TILSection>(&bytes, offset)?);
                    }
                    _ => {}
                }
            }

            Ok(idb)
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
