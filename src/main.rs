mod idb;
mod sections;
#[macro_use]
mod utils;
use crate::sections::til::Types;
use sections::til::TILBucketType;

fn main() {
    let idb_bytes = include_bytes!("/Users/admin/projects/idb/complicated-gcc.i64");
    let now = std::time::Instant::now();
    let idb = idb::idb::IDB2::new(idb_bytes.as_slice()).unwrap();
    println!("time to parse: {:?}", now.elapsed());
    println!("{:?}", idb);

    for page in idb.id0.unwrap().pages {
        if let Some(page) = page {
            println!("{:?}", page);
        }
    }

    println!("-- TYPES --");
    match &idb.til.as_ref().unwrap().types {
        TILBucketType::Default(Some(bucket)) => bucket
            .type_info
            .iter()
            .for_each(|info| println!("{}", info.name)),
        _ => {}
    }

    match &idb.til.as_ref().unwrap().types {
        TILBucketType::Default(Some(bucket)) => {
            match &bucket
                .type_info
                .iter()
                .find(|x| x.name == "mach_header_64")
                .unwrap()
                .info
            {
                Types::Pointer(_) => {}
                Types::Function(_) => {}
                Types::Array(_) => {}
                Types::Typedef(_) => {}
                Types::Struct(str) => {
                    println!("{:?}\n", str);
                }
                Types::Enum(_) => {}
                Types::Bitfield(_) => {}
                Types::Unknown(_) => {}
                _ => {}
            }
        }
        _ => {}
    }
}
