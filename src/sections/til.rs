use crate::sections::IDBSectionHeader;
use crate::utils::parser::*;
use crate::{gen_field_opt, gen_parser, gen_parser_body};
use byteorder::ByteOrder;
use derivative::Derivative;
use enumflags2::{bitflags, BitFlags};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::borrow::BorrowMut;
use std::default::Default;
use std::ops::Deref;

// 1300
// 788

#[bitflags]
#[repr(u32)]
#[derive(Deserialize, Debug, Copy, Clone, PartialEq)]
pub enum TILFlags {
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

#[derive(Default, Debug)]
pub struct TILSection {
    pub header: IDBSectionHeader,
    pub signature: [u8; 6],
    pub format: u32,
    pub flags: BitFlags<TILFlags>,
    pub title_len: u8,
    pub title: String,
    pub base_len: u8,
    pub base: String,
    pub id: u8,
    pub cm: u8,
    pub size_i: u8,
    pub size_b: u8,
    pub size_e: u8,
    pub def_align: u8,
    pub size_s: Option<u8>,
    pub size_l: Option<u8>,
    pub size_ll: Option<u8>,
    pub size_ldbl: Option<u8>,
    pub syms: TILBucketType,
    pub type_ordinal_numbers: Option<u32>,
    pub types: TILBucketType,
    pub macros: TILBucketType,
}

pub struct BaseTypeFlag {
    pub flag: u8,
}

pub struct FullTypeFlag {
    pub flag: u8,
}

pub struct TypeFlag {
    pub flag: u8,
}

#[derive(Deserialize, Default, Debug)]
pub struct TypeMetadata {
    pub flag: u8,
}

impl TypeMetadata {
    pub fn get_base_type_flag(&self) -> BaseTypeFlag {
        BaseTypeFlag {
            flag: self.flag & 0x0F,
        }
    }

    pub fn get_full_type_flag(&self) -> FullTypeFlag {
        FullTypeFlag {
            flag: self.flag & (0x0F | 0x30),
        }
    }

    pub fn get_type_flag(&self) -> TypeFlag {
        TypeFlag {
            flag: self.flag & 0x30,
        }
    }
}

impl BaseTypeFlag {
    pub fn is_pointer(&self) -> bool {
        self.flag == 0x0A
    }

    pub fn is_function(&self) -> bool {
        self.flag == 0x0C
    }

    pub fn is_array(&self) -> bool {
        self.flag == 0x0B
    }

    pub fn is_bitfield(&self) -> bool {
        self.flag == 0x0E
    }

    pub fn is_typeid_last(&self) -> bool {
        self.flag <= 0x09
    }

    pub fn is_reserved(&self) -> bool {
        self.flag == 0x0F
    }
}

impl FullTypeFlag {
    pub fn is_enum(&self) -> bool {
        self.flag == (0x0D | 0x20)
    }

    pub fn is_struct(&self) -> bool {
        self.flag == (0x0D | 0x00)
    }

    pub fn is_union(&self) -> bool {
        self.flag == (0x0D | 0x10)
    }

    pub fn is_struct_or_union(&self) -> bool {
        self.is_struct() || self.is_union()
    }

    pub fn is_typedef(&self) -> bool {
        self.flag == (0x0D | 0x30)
    }
}

#[derive(Default, Debug)]
pub struct TestTypes {
    pub types: Types,
}

pub struct TestTypesVec {
    pub should_sdacl: u8,
    pub mem_cnt: u16,
    pub types_vec: Vec<Types>,
}

gen_parser!(
    parse <TestTypesVec> visit TestTypesVecVisitor,
    |seq|<TestTypesVec>,
    [
        should_sdacl,
        mem_cnt,
        types_vec
    ],
    [
        should_sdacl,
        mem_cnt,
        (types_vec => . {
            let mut types:Vec<Types>=Vec::new();
            let mut index=0;
            while index<mem_cnt{
                let x = create_type_info(&mut seq);
                match x{
                    Ok(ok)=>{
                        types.push(ok);
                    },
                    Err(_)=>{}
                }
                index+=1;
                if should_sdacl==1{
                    let sdacl=consume_sdacl(&mut seq);
                    match sdacl {
                        Ok(sdacl) => {
                           if !sdacl.is_sdacl {
                                types.push(create_type_info_test(&mut seq, TypeMetadata{flag:sdacl.sdacl}).unwrap());
                                index+=1;
                            } else {
                            }
                        },
                        Err(_) => {}
                    }
                }
            }
            types

            // let mut SHOULD_SDACL:(u8,bool) =(0,false);
            // (0..mem_cnt).map(|_| {
            //     // if sdacl fail , create_next_Tinfo using failed sdacl as it will just be
            //     // equivalent to the following Type
            //     // TODO: i was trying to finish this b4 5pm so code is gross , will fix tmrw
            //     if SHOULD_SDACL.1{
            //         create_type_info_test(&mut seq, TypeMetadata{flag:SHOULD_SDACL.0}).unwrap()
            //     }else{
            //         let x = create_type_info(&mut seq);
            //         if should_sdacl == 1 {
            //             let sdacl = consume_sdacl(&mut seq);
            //             match sdacl {
            //                 Ok(sdacl) => {
            //                    if !sdacl.is_sdacl {
            //                         SHOULD_SDACL=(sdacl.sdacl,true);
            //                             x.unwrap()
            //                     } else {
            //                         x.unwrap()
            //                     }
            //                 },
            //                 Err(_) => {
            //                     x.unwrap()
            //                 }
            //             }
            //         } else {
            //             x.unwrap()
            //         }
            //     }
            // }).collect()
        })
    ]
);

gen_parser!(
    parse <TestTypes> visit TestTypesVisitor,
    |seq|<TestTypes>,
    [
        types
    ],
    [
        (types => create_type_info(&mut seq))
    ]
);

pub fn create_type_info_test<'de, A>(seq: &mut A, typ: TypeMetadata) -> Result<Types, A::Error>
where
    A: SeqAccess<'de>,
{
    if typ.get_base_type_flag().is_typeid_last() || typ.get_base_type_flag().is_reserved() {
        println!("!--UNSET!->{}", typ.flag);
        Ok(Types::Unset)
    } else {
        if typ.get_base_type_flag().is_pointer() {
            println!("  --POINTER!");
            Ok(Types::Pointer(consume_null_terminated(seq)?))
        } else if typ.get_base_type_flag().is_function() {
            println!("  --FUNCTION!");
            Ok(Types::Function(consume_null_terminated(seq)?))
        } else if typ.get_base_type_flag().is_array() {
            println!("  --ARRAY!");
            Ok(Types::Array(seq.next_element()?.unwrap()))
        } else if typ.get_full_type_flag().is_typedef() {
            println!("  --TYPEDEF!");
            Ok(Types::Typedef(seq.next_element()?.unwrap()))
        } else if typ.get_full_type_flag().is_union() {
            println!("--UNION!");
            Ok(Types::Union(seq.next_element()?.unwrap()))
        } else if typ.get_full_type_flag().is_struct() {
            println!("--STRUCT!");
            Ok(Types::Struct(seq.next_element()?.unwrap()))
        } else if typ.get_full_type_flag().is_enum() {
            println!("--ENUM!");
            Ok(Types::Enum(consume_null_terminated(seq)?))
        } else if typ.get_base_type_flag().is_bitfield() {
            println!("  --BITFIELD!");
            let mut bitfield: BitfieldType = seq.next_element()?.unwrap();
            bitfield.nbytes = 1 << (typ.get_type_flag().flag >> 4);
            Ok(Types::Bitfield(bitfield))
        } else {
            println!("--UNKNOWN!");
            Ok(Types::Unknown(consume_null_terminated(seq)?))
        }
    }
}

pub fn create_type_info<'de, A>(seq: &mut A) -> Result<Types, A::Error>
where
    A: SeqAccess<'de>,
{
    let typ = seq.next_element::<TypeMetadata>()?.unwrap();
    if typ.get_base_type_flag().is_typeid_last() || typ.get_base_type_flag().is_reserved() {
        println!("!--UNSET!->{}", typ.flag);
        Ok(Types::Unset)
    } else {
        if typ.get_base_type_flag().is_pointer() {
            println!("  --POINTER!");
            Ok(Types::Pointer(consume_null_terminated(seq)?))
        } else if typ.get_base_type_flag().is_function() {
            println!("  --FUNCTION!");
            Ok(Types::Function(consume_null_terminated(seq)?))
        } else if typ.get_base_type_flag().is_array() {
            println!("  --ARRAY!");
            Ok(Types::Array(seq.next_element()?.unwrap()))
        } else if typ.get_full_type_flag().is_typedef() {
            println!("  --TYPEDEF!");
            Ok(Types::Typedef(seq.next_element()?.unwrap()))
        } else if typ.get_full_type_flag().is_union() {
            println!("--UNION!");
            Ok(Types::Union(seq.next_element()?.unwrap()))
        } else if typ.get_full_type_flag().is_struct() {
            println!("--STRUCT!");
            Ok(Types::Struct(seq.next_element()?.unwrap()))
        } else if typ.get_full_type_flag().is_enum() {
            println!("--ENUM!");
            Ok(Types::Enum(consume_null_terminated(seq)?))
        } else if typ.get_base_type_flag().is_bitfield() {
            println!("  --BITFIELD!");
            let mut bitfield: BitfieldType = seq.next_element()?.unwrap();
            bitfield.nbytes = 1 << (typ.get_type_flag().flag >> 4);
            Ok(Types::Bitfield(bitfield))
        } else {
            println!("--UNKNOWN!");
            Ok(Types::Unknown(consume_null_terminated(seq)?))
        }
    }
}

#[derive(Default, Debug)]
pub struct PointerType {}
#[derive(Default, Debug)]
pub struct FunctionType {}

#[derive(Default, Debug)]
pub struct ArrayType {
    elem_num: u16,
    base: Box<Types>,
}

#[derive(Default, Debug)]
pub struct TypedefType {
    buf: Vec<u8>,
}

#[derive(Default, Debug)]
pub struct StructType {
    n: u16,
    is_ref: bool,
    type_ref: Option<Box<Types>>,
    ref_taudt: Option<PossibleSdacl>,
    effective_alignment: Option<u16>,
    taudt_bits: Option<PossibleSdacl>,
    members: Option<Vec<Types>>,
}

// this isnt named very well ( fix later lol )
pub fn consume_one_or_two_bytes<'de, A>(seq: &mut A) -> Result<u16, A::Error>
where
    A: SeqAccess<'de>,
{
    let mut val: u8 = seq.next_element()?.unwrap();
    if (val & 0x80) == 1 {
        val = val & 0x7f;
        let other: u8 = seq.next_element()?.unwrap();
        Ok(((val as u16) | (other as u16) << 7) - 1)
    } else {
        Ok((val - 1) as u16)
    }
    // let initial: u16 = seq.next_element()?.unwrap();
    // let bytes = initial.to_le_bytes();
    // if (bytes[0] & 0x7F) == 0 {
    //     Ok(initial - 1)
    // } else {
    //     Ok((bytes[0] - 1) as u16)
    // }
}

pub fn consume_type_attr<'de, A>(seq: &mut A, tah: u8) -> Result<u16, A::Error>
where
    A: SeqAccess<'de>,
{
    let mut val = 0;
    let mut tmp = ((tah & 1) | ((tah >> 3) & 6)) + 1;
    if is_tah_byte(tah) || tmp == 8 {
        if tmp == 8 {
            val = tmp
        }
        let mut shift = 0;
        loop {
            let mut next_byte = seq.next_element::<u8>()?.unwrap();
            if next_byte == 0 {
                panic!("OK");
            }
            val |= (next_byte & 0x7F) << shift;
            if next_byte & 0x80 == 1 {
                break;
            }
            shift += 7
        }
    }
    let mut unk: Vec<String> = Vec::new();
    if (val & 0x0010) == 1 {
        val = consume_one_or_two_bytes(seq)? as u8;
        for _ in 0..val {
            let len = consume_one_or_two_bytes(seq)?;
            let buf = String::from_utf8_lossy(
                (0..len)
                    .map(|_| seq.next_element::<u8>().unwrap().unwrap())
                    .collect::<Vec<u8>>()
                    .as_slice(),
            )
            .to_string();
            println!("buff->{}", buf);
            unk.push(buf);
        }
    }
    println!("TYPEATTR->{}", val);
    return Ok(val as u16);
}

#[derive(Default, Debug)]
pub struct PossibleSdacl {
    type_addr: u16,
    sdacl: u8,
    is_sdacl: bool,
}

#[derive(Default, Debug)]
pub struct PossibleTah {
    type_addr: u16,
    tah: u8,
    is_tah: bool,
}

#[derive(Default, Debug)]
pub struct StructMember {
    typ: Types,
}

pub fn consume_tah<'de, A>(seq: &mut A) -> Result<PossibleTah, A::Error>
where
    A: SeqAccess<'de>,
{
    let tah = seq.next_element::<u8>()?.unwrap();
    if is_sdacl_byte(tah) {
        Ok(PossibleTah {
            type_addr: consume_type_attr(seq, tah)?,
            tah,
            is_tah: true,
        })
    } else {
        Ok(PossibleTah {
            type_addr: 0,
            tah,
            is_tah: false,
        })
    }
}

pub fn consume_sdacl<'de, A>(seq: &mut A) -> Result<PossibleSdacl, A::Error>
where
    A: SeqAccess<'de>,
{
    let sdacl = seq.next_element::<u8>()?.unwrap();
    if is_sdacl_byte(sdacl) {
        Ok(PossibleSdacl {
            type_addr: consume_type_attr(seq, sdacl)?,
            sdacl,
            is_sdacl: true,
        })
    } else {
        Ok(PossibleSdacl {
            type_addr: 0,
            sdacl,
            is_sdacl: false,
        })
    }
}

pub fn is_sdacl_byte(really: u8) -> bool {
    ((really & !0x30) ^ 0xC0) <= 0x01
}

pub fn is_tah_byte(really: u8) -> bool {
    really == 0xFE
}

pub fn serialize_dt(n: u16) -> Vec<u8> {
    if n > 0x7FFE {
        panic!("invalid dt");
    }
    let mut lo = n + 1;
    let mut hi = n + 1;
    let mut result: Vec<u8> = Vec::new();
    if lo > 127 {
        result.push((lo & 0x7F | 0x80) as u8);
        hi = (lo >> 7) & 0xFF;
    }
    result.push(hi as u8);
    result
}

pub fn create_ref(vec: Vec<u8>) -> Option<Box<Types>> {
    let mut vec = vec;
    if vec[0] != '=' as u8 {
        let mut ser = serialize_dt(vec.len() as u16);
        vec.splice(..0, ser.drain(..));
        vec.insert(0, '=' as u8);
    }

    match bincode::deserialize::<TestTypes>(vec.as_slice()) {
        Ok(ok) => Some(Box::new(ok.types)),
        Err(_) => None,
    }
}

gen_parser!(parse <PointerType> visit PointerVisitor, |seq|<PointerType>, [], []);
gen_parser!(parse <FunctionType> visit FunctionVisitor, |seq|<FunctionType>, [], []);
gen_parser!(
    parse <ArrayType> visit ArrayVisitor,
    |seq|<ArrayType>,
    [
        elem_num,
        base
    ],
    [
        (elem_num => consume_one_or_two_bytes(&mut seq)),
        (base => . {
            let _ = consume_tah(&mut seq);
            Box::new(create_type_info(&mut seq)?)
        })
    ]
);
gen_parser!(
    parse <TypedefType> visit TypedefVisitor,
    |seq|<TypedefType>,
    [
        buf
    ],
    [
        (buf => . {
            let len = consume_one_or_two_bytes(&mut seq)?;
            (0..len)
            .map(|_| seq.next_element::<u8>().unwrap().unwrap())
            .collect::<Vec<u8>>()
        })
    ]
);

gen_parser!(
    parse <UnionType> visit UnionVisitor,
    |seq|<UnionType>,
    [
        n,
        is_ref,
        type_ref,
        ref_taudt,
        effective_alignment,
        taudt_bits,
        members
    ],
    [
        (n => . {
            let dt = consume_one_or_two_bytes(&mut seq)?;
            if dt == 0 {
                dt
            } else if dt == 0x7FFE {
                panic!("Unhandled dt");
            } else {
                dt
            }
        }),
        (is_ref => . {
            n == 0
        }),
        (type_ref => . {
            if is_ref {
                let len = consume_one_or_two_bytes(&mut seq)?;
                let buf = (0..len)
                    .map(|_| seq.next_element::<u8>().unwrap().unwrap())
                    .collect::<Vec<u8>>();
                create_ref(buf)
            } else {
                None
            }
        }),
        (ref_taudt => . {
            if is_ref {
                Some(consume_sdacl(&mut seq)?)
            } else {
                None
            }
        }),
        (effective_alignment => . {
            if is_ref {
                None
            } else {
                let alpow = n & 7;
                if alpow == 0 {
                    Some(0)
                } else {
                    Some(1 << (alpow - 1))
                }
            }
        }),
        (taudt_bits => . {
            if is_ref {
                None
            } else {
                Some(consume_sdacl(&mut seq)?)
            }
        }),
        (members => . {
            if is_ref {
                None
            } else {
                let mem_cnt = n >> 3;
                // println!("[N]-> {} | [MEM_CNT]-> {}",n,mem_cnt);
                let mut term = consume_with_null_terminated(&mut seq)?;
                if let Some(ref taudt_bits) = taudt_bits {
                    if !taudt_bits.is_sdacl {
                        term.insert(0, taudt_bits.sdacl);
                    }
                }
                (0..2).for_each(|_| term.insert(0, 0));
                term.insert(0, 0);
                byteorder::NativeEndian::write_u16(&mut term[0..2], mem_cnt);
                let xyz=bincode::deserialize::<TestTypesVec>(term.as_slice()).unwrap().types_vec;
                (0..3).for_each(|_| {let _ = term.remove(0);});
                Some(xyz)
            }
        })
    ]
);

gen_parser!(parse <EnumType> visit EnumVisitor, |seq|<EnumType>, [], []);

gen_parser!(
    parse <BitfieldType> visit BitfieldVisitor,
    |seq|<BitfieldType>,
    [nbytes, dt, width, is_unsigned, tah],
    [
        (nbytes => . 0),
        (dt => consume_one_or_two_bytes(&mut seq)),
        (width => . dt >> 1),
        (is_unsigned => . (dt & 1) == 1),
        (tah => consume_tah(&mut seq))
    ]
);

gen_parser!(
    parse <StructType> visit StructVisitor,
    |seq|<StructType>,
    [
        n,
        is_ref,
        type_ref,
        ref_taudt,
        effective_alignment,
        taudt_bits,
        members
    ],
    [
        (n => . {
            let dt = consume_one_or_two_bytes(&mut seq)?;
            if dt == 0 {
                dt
            } else if dt == 0x7FFE {
                panic!("Unhandled dt");
            } else {
                dt
            }
        }),
        (is_ref => . {
            n == 0
        }),
        (type_ref => . {
            if is_ref {
                let len = consume_one_or_two_bytes(&mut seq)?;
                let buf = (0..len)
                    .map(|_| seq.next_element::<u8>().unwrap().unwrap())
                    .collect::<Vec<u8>>();
                create_ref(buf)
            } else {
                None
            }
        }),
        (ref_taudt => . {
            if is_ref {
                Some(consume_sdacl(&mut seq)?)
            } else {
                None
            }
        }),
        (effective_alignment => . {
            if is_ref {
                None
            } else {
                let alpow = n & 7;
                if alpow == 0 {
                    Some(0)
                } else {
                    Some(1 << (alpow - 1))
                }
            }
        }),
        (taudt_bits => . {
            if is_ref {
                None
            } else {
                Some(consume_sdacl(&mut seq)?)
            }
        }),
        (members => . {
            if is_ref {
                None
            } else {
                let mem_cnt = n >> 3;
                let mut term = consume_with_null_terminated(&mut seq)?;
                if let Some(ref taudt_bits) = taudt_bits {
                    if !taudt_bits.is_sdacl {
                        term.insert(0, taudt_bits.sdacl);
                    }
                }
                (0..2).for_each(|_| term.insert(0, 0));
                byteorder::NativeEndian::write_u16(&mut term[0..2], mem_cnt);
                term.insert(0, 1);
                let xyz=bincode::deserialize::<TestTypesVec>(term.as_slice()).unwrap().types_vec;
                (0..3).for_each(|_| {let _ = term.remove(0);});
                Some(xyz)
            }
        })
    ]
);

#[derive(Default, Debug)]
pub struct UnionType {
    n: u16,
    is_ref: bool,
    type_ref: Option<Box<Types>>,
    ref_taudt: Option<PossibleSdacl>,
    effective_alignment: Option<u16>,
    taudt_bits: Option<PossibleSdacl>,
    members: Option<Vec<Types>>,
}
#[derive(Default, Debug)]
pub struct EnumType {}
#[derive(Default, Debug)]
pub struct BitfieldType {
    nbytes: u8,
    dt: u16,
    width: u16,
    is_unsigned: bool,
    tah: PossibleTah,
}

#[derive(Debug)]
pub enum Types {
    Unset,
    Pointer(Vec<u8>),
    Function(Vec<u8>),
    Array(ArrayType),
    Typedef(TypedefType),
    Struct(StructType),
    Union(UnionType),
    Enum(Vec<u8>),
    Bitfield(BitfieldType),
    Unknown(Vec<u8>),
}
impl Default for Types {
    fn default() -> Self {
        Types::Unset
    }
}

#[derive(Default, Debug)]
pub struct TILTypeInfo {
    pub flags: u32,
    pub name: String,
    pub ordinal: u64,
    pub info: Option<TestTypes>,
    pub cmt: String,
    pub fields_buf: Vec<u8>,
    pub fieldcmts: Vec<u8>,
    pub sclass: u8,
    pub fields: Vec<String>,
}

#[derive(Default, Debug)]
pub struct TILBucket {
    pub ndefs: u32,
    pub len: u32,
    pub data: Vec<u8>,
    pub type_info: Vec<TILTypeInfo>,
}

#[derive(Deserialize, Default, Debug)]
pub struct TILBucketZip {
    pub ndefs: u32,
    pub size: u32,
    pub data: Vec<u8>,
    #[serde(skip)]
    pub type_info: Vec<TILTypeInfo>,
}

#[derive(Debug)]
pub enum TILBucketType {
    None,
    Default(Option<TILBucket>),
    Zip(Option<TILBucketZip>),
}

impl Default for TILBucketType {
    fn default() -> Self {
        Self::None
    }
}

struct TypeInfoVec {
    ndefs: u32,
    vec: Vec<TILTypeInfo>,
}

gen_parser!(
    parse <TILTypeInfo> visit TypeInfoVisitor,
    |seq|<TILTypeInfo>,
    [
        flags, name, ordinal, info,
        fields_buf, cmt, fieldcmts, sclass,
        fields
    ],
    [
        flags,
        (name => consume_null_terminated_string(&mut seq)),
        (ordinal => .
            if (flags >> 31u32) != 0 {
                seq.next_element::<u64>()?.unwrap()
            } else {
                seq.next_element::<u32>()?.unwrap() as u64
            }
        ),
        (info => . {
            let nt = consume_with_null_terminated(&mut seq)?;
            match bincode::deserialize::<TestTypes>(nt.as_slice()) {
                Ok(ok) => Some(ok),
                Err(_) => None
            }
        }),
        (cmt => consume_null_terminated_string(&mut seq)),
        (fields_buf => consume_null_terminated(&mut seq)),
        (fieldcmts => consume_null_terminated(&mut seq)),
        sclass,
        (fields => . parse_len_prefix_str_vec(&fields_buf))
    ]
);

gen_parser!(
    parse <TypeInfoVec> visit TypeInfoVecVisitor,
    |seq|<TypeInfoVec>,
    [
        ndefs,
        vec
    ],
    [
        ndefs,
        (vec => . {
            (0..ndefs).map(|_| {
                seq.next_element::<TILTypeInfo>().unwrap().unwrap()
            }).collect()
        })
    ]
);

gen_parser!(
    parse <TILBucket> visit TILBucketVisitor,
    |seq|<TILBucket>,
    [
        ndefs,
        len,
        data,
        type_info
    ],
    [
        ndefs,
        len,
        (mut data => . {
                (0..len)
                    .map(|_| -> u8 { seq.next_element().unwrap_or_default().unwrap_or(0) })
                    .collect::<Vec<u8>>()
            }
        ),
        (type_info => . {
            (0..4).for_each(|_| data.insert(0, 0));
            byteorder::NativeEndian::write_u32(&mut data[0..4], ndefs);
            let collected = bincode::deserialize::<TypeInfoVec>(data.as_slice()).unwrap();
            (0..4).for_each(|_| {let _ = data.remove(0);});
            collected.vec
        })
    ]
);

gen_parser!(
    parse <TILSection> visit TILSectionVisitor,
    |seq|<TILSection>,
    [
        header, signature, format, flags,
        title_len, title, base_len, base,
        id, cm, size_i, size_b, size_e,
        def_align, size_s, size_l, size_ll,
        size_ldbl, syms, type_ordinal_numbers,
        types, macros
    ],
    [
        header,
        signature,
        format,
        (flags<BitFlags<TILFlags>>),
        ((base_len, base) => consume_len_prefix_str(&mut seq)),
        ((title_len, title) => consume_len_prefix_str(&mut seq)),
        id,
        cm,
        size_i,
        size_b,
        size_e,
        def_align,
        (? size_s . flags.intersects(TILFlags::Esi)),
        (? size_l . flags.intersects(TILFlags::Esi)),
        (? size_ll . flags.intersects(TILFlags::Esi)),
        (syms => .
        if flags.intersects(TILFlags::Zip) {
            TILBucketType::Zip(
                match seq.next_element::<TILBucketZip>() {
                    Ok(ok) => ok,
                    Err(_) => None,
                }
            )
        } else {
            TILBucketType::Default(
                match seq.next_element::<TILBucket>() {
                    Ok(ok) => ok,
                    Err(_) => None,
                }
            )
        }),
        (? size_ldbl . flags.intersects(TILFlags::Sld)),
        (? type_ordinal_numbers . flags.intersects(TILFlags::Ord)),
        (types => .
        if flags.intersects(TILFlags::Zip) {
            TILBucketType::Zip(
                match seq.next_element::<TILBucketZip>() {
                    Ok(ok) => ok,
                    Err(_) => None,
                }
            )
        } else {
            TILBucketType::Default(
                match seq.next_element::<TILBucket>() {
                    Ok(ok) => ok,
                    Err(_) => None,
                }
            )
        }),
        (macros => .
        if flags.intersects(TILFlags::Zip) {
            TILBucketType::Zip(
                match seq.next_element::<TILBucketZip>() {
                    Ok(ok) => ok,
                    Err(_) => None,
                }
            )
        } else {
            TILBucketType::Default(
                match seq.next_element::<TILBucket>() {
                    Ok(ok) => ok,
                    Err(_) => None,
                }
            )
        })
    ]
);
