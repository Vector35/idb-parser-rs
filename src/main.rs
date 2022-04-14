mod idb;
mod sections;
#[macro_use]
mod utils;
use sections::til::TILBucketType;

fn main() {
    let idb_bytes = include_bytes!("/Users/admin/projects/idb/complicated-gcc.i64");
    let now = std::time::Instant::now();
    let idb = idb::idb::IDB2::new(idb_bytes.as_slice()).unwrap();
    println!("time to parse: {:?}", now.elapsed());

    println!("{:#x?}", idb);
    // println!("{:?}", idb.id0.as_ref().unwrap().get_page(1).kv_entries);
    // println!("{:?}", idb.id0.as_ref().unwrap().get_page(2).kv_entries);
    // println!("{:?}", idb.id0.as_ref().unwrap().get_page(3).kv_entries);
    // println!("{:?}", idb.id0.as_ref().unwrap().get_page(4).kv_entries);
    // println!("{:?}", idb.id0.as_ref().unwrap().get_page(5).kv_entries);
    // println!("{:?}", idb.id0.as_ref().unwrap().get_page(6).kv_entries);
    // println!("{:?}", idb.id0.as_ref().unwrap().get_page(7).kv_entries);
    // println!("{:?}", idb.id0.as_ref().unwrap().get_page(8).kv_entries);
    // println!("{:?}", idb.id0.as_ref().unwrap().get_page(9).kv_entries);

    println!("-- TYPES --");
    match &idb.til.as_ref().unwrap().types {
        TILBucketType::Default(Some(bucket)) => bucket
            .type_info
            .iter()
            .for_each(|info| println!("{}", info.name)),
        _ => {}
    }
}
