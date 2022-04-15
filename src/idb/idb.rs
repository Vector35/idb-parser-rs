use crate::idb::idb::IDBError::{DeserializingError, InvalidHeader};
use crate::sections::{
    id0::ID0Section, id1::ID1Section, id2::ID2Section, nam::NAMSection, seg::SEGSection,
    til::TILSection, IDBSectionHeader,
};
use crate::{gen_field_opt, gen_parser, gen_parser_body};
use bincode::ErrorKind;
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::default::Default;

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
    _checksum1: u32,
    _checksum2: u32,
    _checksum3: u32,
    _checksum4: u32,
    _checksum5: u32,
    offset6: u64,
    _checksum6: u32,
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

#[derive(Debug)]
pub struct IDB2 {
    header: IDBHeader2,
    pub id0: Result<ID0Section, IDBError>,
    pub id1: Result<ID1Section, IDBError>,
    pub nam: Result<NAMSection, IDBError>,
    pub seg: Result<SEGSection, IDBError>,
    pub til: Result<TILSection, IDBError>,
    pub id2: Result<ID2Section, IDBError>,
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
        (id0 => . Err(IDBError::SectionUnset)),
        (id1 => . Err(IDBError::SectionUnset)),
        (nam => . Err(IDBError::SectionUnset)),
        (seg => . Err(IDBError::SectionUnset)),
        (til => . Err(IDBError::SectionUnset)),
        (id2 => . Err(IDBError::SectionUnset))
    ]
);

#[derive(Debug)]
pub enum IDBError {
    DeserializingError,
    InvalidHeader,
    InvalidOffset,
    SectionUnset,
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
                    0 => idb.id0 = IDB2::deserialize_section(&bytes, offset),
                    1 => idb.id1 = IDB2::deserialize_section(&bytes, offset),
                    2 => idb.nam = IDB2::deserialize_section(&bytes, offset),
                    3 => idb.seg = IDB2::deserialize_section(&bytes, offset),
                    4 => idb.til = IDB2::deserialize_section(&bytes, offset),
                    5 => idb.id2 = IDB2::deserialize_section(&bytes, offset),
                    _ => {}
                }
            }

            Ok(idb)
        }
    }
}
