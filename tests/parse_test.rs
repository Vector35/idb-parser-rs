use idb_parser;
use idb_parser::TILBucketType;
use std::borrow::Borrow;

const IDB: &'static [u8] = include_bytes!("resources/gcc.i64");
// This is the unpacked TIL section from the above IDB
// IDA type libraries are also stored as unpacked sections like this
// and can be parsed using this library
const TIL: &'static [u8] = include_bytes!("resources/gcc.til");

#[test]
fn test_parse_idb() {
    let _idb = idb_parser::IDB::parse(IDB).unwrap();
}

#[test]
fn test_parse_til() {
    let _til = idb_parser::TILSection::parse(TIL).unwrap();
}

#[test]
fn test_idb_til_same() {
    let idb = idb_parser::IDB::parse(IDB).unwrap();
    let til = idb_parser::TILSection::parse(TIL).unwrap();

    let idb_type_ndefs = match idb.til.unwrap().types {
        TILBucketType::Default(def) => def.ndefs as usize + def.type_info.len(),
        TILBucketType::Zip(zip) => zip.ndefs as usize + zip.type_info.len(),
    };
    let til_type_ndefs = match til.types {
        TILBucketType::Default(def) => def.ndefs as usize + def.type_info.len(),
        TILBucketType::Zip(zip) => zip.ndefs as usize + zip.type_info.len(),
    };

    assert_eq!(idb_type_ndefs, til_type_ndefs);
}
