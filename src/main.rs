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

    // id0 removed for now to speed up parse testing .
    // for page in idb.id0.unwrap().pages {
    //     if let Some(page) = page {
    //         println!("{:?}", page);
    //     }
    // }

    println!("-- TYPES --");
    match &idb.til.as_ref().unwrap().types {
        TILBucketType::Default(Some(bucket)) => bucket
            .type_info
            .iter()
            .for_each(|info| println!("{}", info.name)),
        _ => {}
    }

    // let str = match &idb.til.as_ref().unwrap().types {
    //     TILBucketType::Default(Some(bucket)) => Some(
    //         bucket
    //             .type_info
    //             .iter()
    //             .find(|x| x.name == "String")
    //             .unwrap()
    //             .get_type_name(),
    //     ),
    //     _ => None,
    // };
    // println!("String - Typename: \n{}", str.unwrap());

    match &idb.til.as_ref().unwrap().types {
        TILBucketType::Default(Some(bucket)) => {
            match &bucket
                .type_info
                .iter()
                .find(|x| x.name == "String")
                .unwrap()
                .info
            {
                Some(typ) => match &typ.types {
                    Types::Pointer(_, _) => {}
                    Types::Function(_, _) => {}
                    Types::Array(_, _) => {}
                    Types::Typedef(mdata, tdef) => {
                        println!(
                            "tdef: {:#x?} -> {:#x?}",
                            tdef,
                            mdata.get_underlying_typeinfo(&tdef, bucket.clone())
                        )
                    }
                    Types::Struct(_, str) => {
                        println!("{:#x?}\n", str);
                    }
                    Types::Union(_, _) => {}
                    Types::Enum(_, _) => {}
                    Types::Bitfield(_, _) => {}
                    Types::Unknown(_, _) => {}
                    _ => {}
                },
                None => {}
            }
        }
        _ => {}
    }

    println!(
        "OUTSTRING:\n{}",
        idb.til
            .as_ref()
            .unwrap()
            .get_type("String".to_string())
            .unwrap()
            .get_type_str()
    );
}
