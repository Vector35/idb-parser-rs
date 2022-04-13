mod idb;
mod sections;
mod utils;
use sections::til::{TILBucketType, TILInitialTypeInfoType};

fn main() {
    let idb_bytes = include_bytes!("/Users/admin/projects/idb/complicated-gcc.i64");
    let now = std::time::Instant::now();
    let idb = idb::idb::IDB::new(idb_bytes.as_slice());
    println!("time to parse: {:?}", now.elapsed());

    println!("{:#x?}", idb);
    println!("{:?}", idb.id0.as_ref().unwrap().get_page(1).kv_entries);
    println!("{:?}", idb.id0.as_ref().unwrap().get_page(2).kv_entries);
    println!("{:?}", idb.id0.as_ref().unwrap().get_page(3).kv_entries);
    println!("{:?}", idb.id0.as_ref().unwrap().get_page(4).kv_entries);
    println!("{:?}", idb.id0.as_ref().unwrap().get_page(5).kv_entries);
    println!("{:?}", idb.id0.as_ref().unwrap().get_page(6).kv_entries);
    println!("{:?}", idb.id0.as_ref().unwrap().get_page(7).kv_entries);
    println!("{:?}", idb.id0.as_ref().unwrap().get_page(8).kv_entries);
    println!("{:?}", idb.id0.as_ref().unwrap().get_page(9).kv_entries);

    println!("-- TYPES --");
    if let Some(til_bucket) = &idb.til.as_ref().unwrap().types {
        match til_bucket {
            TILBucketType::Default(bucket) => bucket.type_info.iter().for_each(|info| match &info
                .initial_type_info
            {
                TILInitialTypeInfoType::Ordinal32(tinfo) => {
                    println!("{}", tinfo.name);
                }
                TILInitialTypeInfoType::Ordinal64(tinfo) => {
                    println!("{}", tinfo.name);
                }
                _ => {}
            }),
            _ => {}
        }
    }
}
