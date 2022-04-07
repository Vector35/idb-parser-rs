use crate::sections::til::{
    TILBucket, TILBucketType, TILBucketZip, TILFlags, TILInitialTypeInfoType, TILTypeInfo,
};
use enumflags2::{bitflags, BitFlags};

pub struct Consumer<'a> {
    offset: usize,
    buf: &'a Vec<u8>,
    flags: Option<BitFlags<TILFlags>>,
}

impl<'a> Consumer<'a> {
    pub fn new_with_flags(
        offset: usize,
        buf: &'a Vec<u8>,
        flags: BitFlags<TILFlags>,
    ) -> Consumer<'a> {
        Consumer {
            offset,
            buf,
            flags: Some(flags),
        }
    }

    pub fn new(offset: usize, buf: &'a Vec<u8>) -> Consumer<'a> {
        Consumer {
            offset,
            buf,
            flags: None,
        }
    }

    pub fn consume<T>(&mut self) -> T
    where
        T: serde::de::Deserialize<'a>,
    {
        let deserialized = bincode::deserialize(&self.buf[self.offset..]).unwrap();
        self.offset += std::mem::size_of_val(&deserialized);
        deserialized
    }

    pub fn consume_type_info(&mut self) -> Option<TILTypeInfo> {
        if self.offset > self.buf.len() {
            None
        } else {
            let mut ti = bincode::deserialize::<TILTypeInfo>(&self.buf[self.offset..]).unwrap();
            let mut le_vec: Vec<String> = Vec::new();
            let mut pos = 0;
            while pos < ti.fields_buf.len() {
                let len = ti.fields_buf[pos];
                le_vec.push(
                    String::from_utf8_lossy(&ti.fields_buf[pos + 1..pos + len as usize])
                        .to_string(),
                );
                pos += len as usize;
            }
            ti.fields = le_vec;
            let off = match &ti.initial_type_info {
                TILInitialTypeInfoType::Ordinal64(tinfo) => {
                    std::mem::size_of_val(&tinfo.flags)
                        + tinfo.name.len()
                        + std::mem::size_of_val(&tinfo.ordinal)
                }
                TILInitialTypeInfoType::Ordinal32(tinfo) => {
                    std::mem::size_of_val(&tinfo.flags)
                        + tinfo.name.len()
                        + std::mem::size_of_val(&tinfo.ordinal)
                }
                _ => 0,
            } + ti.type_info.len()
                + ti.cmt.len()
                + ti.fields_buf.len()
                + ti.fieldcmts.len()
                + std::mem::size_of_val(&ti.sclass)
                + 5;
            self.offset += off;
            Some(ti)
        }
    }

    pub fn consume_bucket(&mut self) -> TILBucketType {
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
                        def.type_info
                            .push(type_consumer.consume_type_info().unwrap());
                    }
                }

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
