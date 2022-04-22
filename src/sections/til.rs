use crate::sections::IDBSectionHeader;
use crate::utils::parser::*;
use crate::{gen_field_opt, gen_parser, gen_parser_body};
use byteorder::ByteOrder;
use derivative::Derivative;
use enumflags2::{bitflags, BitFlags};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::borrow::{Borrow, BorrowMut};
use std::default::Default;
use std::fs::Metadata;
use std::ops::Deref;

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

#[derive(PartialEq, Deserialize, Copy, Clone, Default, Debug)]
pub struct TypeMetadata {
    pub flag: u8,
}

impl TypeFlag {
    pub fn is_unsigned(&self) -> bool {
        self.flag == 0x20
    }
}

impl TypeMetadata {
    pub fn get_underlying_typeinfo(&self, typedef: &TypedefType, bucket: TILBucket) -> TILTypeInfo {
        if typedef.is_ordref {
            bucket
                .type_info
                .into_iter()
                .find(|x| x.ordinal == typedef.ordinal.unwrap() as u64)
                .unwrap()
        } else {
            bucket
                .type_info
                .into_iter()
                .find(|x| x.name == *typedef.name.as_ref().unwrap())
                .unwrap()
        }
    }

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

#[derive(Default, Debug, Clone)]
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
                                types.push(create_type_info_impl(&mut seq, TypeMetadata{flag:sdacl.sdacl}).unwrap());
                                index+=1;
                            }
                        },
                        Err(_) => {}
                    }
                }
            }
            types
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

pub fn create_type_info_impl<'de, A>(seq: &mut A, typ: TypeMetadata) -> Result<Types, A::Error>
where
    A: SeqAccess<'de>,
{
    if typ.get_base_type_flag().is_typeid_last() || typ.get_base_type_flag().is_reserved() {
        Ok(Types::Unset(typ))
    } else {
        if typ.get_base_type_flag().is_pointer() {
            println!("  --POINTER!");
            Ok(Types::Pointer(typ, seq.next_element()?.unwrap()))
        } else if typ.get_base_type_flag().is_function() {
            println!("  --FUNCTION!");
            Ok(Types::Function(typ, consume_null_terminated(seq)?))
        } else if typ.get_base_type_flag().is_array() {
            println!("  --ARRAY!");
            Ok(Types::Array(typ, seq.next_element()?.unwrap()))
        } else if typ.get_full_type_flag().is_typedef() {
            println!("  --TYPEDEF!");
            Ok(Types::Typedef(typ, seq.next_element()?.unwrap()))
        } else if typ.get_full_type_flag().is_union() {
            println!("--UNION!");
            Ok(Types::Union(typ, seq.next_element()?.unwrap()))
        } else if typ.get_full_type_flag().is_struct() {
            println!("--STRUCT!");
            Ok(Types::Struct(typ, seq.next_element()?.unwrap()))
        } else if typ.get_full_type_flag().is_enum() {
            println!("--ENUM!");
            Ok(Types::Enum(typ, consume_null_terminated(seq)?))
        } else if typ.get_base_type_flag().is_bitfield() {
            println!("  --BITFIELD!");
            let mut bitfield: BitfieldType = seq.next_element()?.unwrap();
            bitfield.nbytes = 1 << (typ.get_type_flag().flag >> 4);
            Ok(Types::Bitfield(typ, bitfield))
        } else {
            println!("--UNKNOWN!");
            Ok(Types::Unknown(typ, consume_null_terminated(seq)?))
        }
    }
}

pub fn create_type_info<'de, A>(seq: &mut A) -> Result<Types, A::Error>
where
    A: SeqAccess<'de>,
{
    let typ = seq.next_element::<TypeMetadata>()?.unwrap();
    create_type_info_impl(seq, typ)
}

#[derive(PartialEq, Default, Debug, Clone)]
pub struct PointerType {
    tah: PossibleTah,
    typ: Box<Types>,
}
#[derive(PartialEq, Default, Debug, Clone)]
pub struct FunctionType {}

#[derive(PartialEq, Default, Debug, Clone)]
pub struct ArrayType {
    elem_num: u16,
    base: Box<Types>,
}

#[derive(PartialEq, Default, Debug, Clone)]
pub struct TypedefType {
    buf: Vec<u8>,
    is_ordref: bool,
    ordinal: Option<u32>,
    name: Option<String>,
}

#[derive(PartialEq, Default, Debug, Clone)]
pub struct StructType {
    n: u16,
    pub is_ref: bool,
    type_ref: Option<Box<Types>>,
    ref_taudt: Option<PossibleSdacl>,
    effective_alignment: Option<u16>,
    taudt_bits: Option<PossibleSdacl>,
    pub members: Option<Vec<Types>>,
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
}

pub fn consume_one_to_four_bytes_vec(bytes: &Vec<u8>) -> u32 {
    let mut index = 0;
    let mut val: u32 = 0;
    loop {
        let mut hi = val << 6;
        let mut b = bytes[index + 1];
        index += 1;
        let mut sign = b & 0x80;
        if sign == 0 {
            let mut lo = b & 0x3F;
            val = (lo as u32) | hi;
            break;
        } else {
            let mut lo = 2 * hi;
            hi = (b as u32) & 0x7F;
            val = lo | hi;
        }
    }
    return val;
}

pub fn consume_one_to_four_bytes<'de, A>(seq: &mut A) -> Result<u32, A::Error>
where
    A: SeqAccess<'de>,
{
    let mut val: u32 = 0;
    loop {
        let mut hi = val << 6;
        let mut b = seq.next_element::<u8>()?.unwrap();
        let mut sign = b & 0x80;
        if sign == 0 {
            let mut lo = b & 0x3F;
            val = (lo as u32) | hi;
            break;
        } else {
            let mut lo = 2 * hi;
            hi = (b as u32) & 0x7F;
            val = lo | hi;
        }
    }
    return Ok(val);
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

#[derive(PartialEq, Default, Debug, Clone)]
pub struct PossibleSdacl {
    type_addr: u16,
    sdacl: u8,
    is_sdacl: bool,
}

#[derive(PartialEq, Default, Debug, Clone)]
pub struct PossibleTah {
    type_addr: u16,
    tah: u8,
    is_tah: bool,
}

#[derive(PartialEq, Default, Debug)]
pub struct StructMember {
    typ: Types,
}

pub fn consume_tah<'de, A>(seq: &mut A) -> Result<PossibleTah, A::Error>
where
    A: SeqAccess<'de>,
{
    let tah = seq.next_element::<u8>()?.unwrap();
    if is_tah_byte(tah) {
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

gen_parser!(
    parse <PointerType> visit PointerVisitor,
    |seq|<PointerType>,
    [tah, typ],
    [
        (tah => consume_tah(&mut seq)),
        (typ => . {
            if !tah.is_tah {
                Box::new(create_type_info_impl(&mut seq, TypeMetadata{flag: tah.tah}).unwrap())
            } else {
                Box::new(create_type_info(&mut seq)?)
            }
        })
    ]
);

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
            let tah = consume_tah(&mut seq)?;
            if !tah.is_tah {
                Box::new(create_type_info_impl(&mut seq, TypeMetadata{flag: tah.tah}).unwrap())
            } else {
                Box::new(create_type_info(&mut seq)?)
            }
        })
    ]
);

gen_parser!(
    parse <TypedefType> visit TypedefVisitor,
    |seq|<TypedefType>,
    [
        buf, is_ordref, ordinal, name
    ],
    [
        (buf => . {
            let len = consume_one_or_two_bytes(&mut seq)?;
            (0..len)
            .map(|_| seq.next_element::<u8>().unwrap().unwrap())
            .collect::<Vec<u8>>()
        }),
        (is_ordref => . {
            buf[0]=='#' as u8
        }),
        (ordinal => . {
            if is_ordref{
                Some(consume_one_to_four_bytes_vec(&buf))
            }else{
                None
            }
        }),
        (name => . {
            if !is_ordref{
                Some(String::from_utf8_lossy(buf.as_slice()).to_string())
            }else{
                None
            }
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

#[derive(PartialEq, Default, Debug, Clone)]
pub struct UnionType {
    n: u16,
    is_ref: bool,
    type_ref: Option<Box<Types>>,
    ref_taudt: Option<PossibleSdacl>,
    effective_alignment: Option<u16>,
    taudt_bits: Option<PossibleSdacl>,
    members: Option<Vec<Types>>,
}
#[derive(PartialEq, Default, Debug, Clone)]
pub struct EnumType {}
#[derive(PartialEq, Default, Debug, Clone)]
pub struct BitfieldType {
    nbytes: u8,
    dt: u16,
    width: u16,
    is_unsigned: bool,
    tah: PossibleTah,
}

#[derive(PartialEq, Debug, Clone)]
pub enum Types {
    Unset(TypeMetadata),
    Pointer(TypeMetadata, PointerType),
    Function(TypeMetadata, Vec<u8>),
    Array(TypeMetadata, ArrayType),
    Typedef(TypeMetadata, TypedefType),
    Struct(TypeMetadata, StructType),
    Union(TypeMetadata, UnionType),
    Enum(TypeMetadata, Vec<u8>),
    Bitfield(TypeMetadata, BitfieldType),
    Unknown(TypeMetadata, Vec<u8>),
}

impl Default for Types {
    fn default() -> Self {
        Types::Unset(TypeMetadata::default())
    }
}

#[derive(Default, Debug, Clone)]
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

#[derive(Debug)]
pub struct TILType<'a> {
    pub sec: &'a TILSection,
    pub tinfo: TILTypeInfo,
    pub typ: Option<Types>,
    pub metadata: Option<TypeMetadata>,
}

// keep tinfo
// point to type -> new object
// store new metadata
// ???
// profit

impl<'a> TILType<'a> {
    pub fn convert_to_til_type(&self, typ: &Types, metadata: &TypeMetadata) -> TILType {
        TILType {
            sec: self.sec,
            tinfo: self.tinfo.clone(),
            typ: Some(typ.clone()),
            metadata: Some(metadata.clone()),
        }
    }

    pub fn locate_til_type(&self, typ: &Types) -> Option<TILType> {
        println!("all_types:{:#x?}", self.sec.get_types().unwrap());
        self.sec
            .get_types()
            .unwrap()
            .into_iter()
            .find(|x| x.typ.as_ref().unwrap().eq(typ))
    }

    pub fn get_type_decl(&self) -> String {
        let mut tstr = String::new();

        match self.typ.as_ref().unwrap() {
            Types::Unset(_) => {}
            Types::Pointer(_, _) => {}
            Types::Function(_, _) => {}
            Types::Array(_, _) => {}
            Types::Typedef(_, _) => {}
            Types::Struct(_, str) => {
                tstr += "struct ";
                tstr += &self.get_type_name();
            }
            Types::Union(_, _) => {}
            Types::Enum(_, _) => {}
            Types::Bitfield(_, _) => {}
            Types::Unknown(_, _) => {}
        }

        tstr
    }

    pub fn get_type_str(&self) -> String {
        let mut tstr = self.get_type_decl();

        match self.typ.as_ref().unwrap() {
            Types::Unset(_) => {}
            Types::Pointer(_, _) => {}
            Types::Function(_, _) => {}
            Types::Array(_, _) => {}
            Types::Typedef(_, _) => {}
            Types::Struct(_, str) => {
                let mem = str.members.as_ref().unwrap();
                tstr += " {\n";
                let mut index = 0;
                for m in mem {
                    let tiltype = match self.locate_til_type(m) {
                        None => self.convert_to_til_type(m, m.get_metadata().unwrap()),
                        Some(sm) => sm,
                    };
                    println!("LESGO:{:#x?}", tiltype);
                    tstr += format!(
                        "   {} {};\n",
                        tiltype.get_type_name(),
                        tiltype.tinfo.fields[index]
                    )
                    .as_str();
                    index += 1;
                }
                tstr += "}\n";
            }
            Types::Union(_, _) => {}
            Types::Enum(_, _) => {}
            Types::Bitfield(_, _) => {}
            Types::Unknown(_, _) => {}
        }

        tstr
    }

    pub fn get_type_name(&self) -> String {
        if let Types::Unset(mdata) = self.typ.as_ref().unwrap() {
            let mut tstr = String::new();
            let base = mdata.get_base_type_flag();
            let tflag = mdata.get_type_flag();

            if base.is_typeid_last() {
                match base.flag {
                    0x00 => tstr += "unknown",
                    0x01 => tstr += "void",
                    0x02 => tstr += "int8_t",
                    0x03 => tstr += "int16_t",
                    0x04 => tstr += "int32_t",
                    0x05 => tstr += "int64_t",
                    0x06 => tstr += "int128_t",
                    0x07 => tstr += "int",
                    0x08 => tstr += "bool",
                    0x09 => match tflag.flag {
                        0x00 => tstr += "float",
                        0x10 => tstr += "double",
                        0x20 => tstr += "long double",
                        0x30 => tstr += "special float",
                        _ => tstr += "unknown float",
                    },
                    _ => {}
                }
            }
            tstr
        } else {
            let mut tstr = String::new();

            let base = self.metadata.unwrap().get_base_type_flag();
            let tflag = self.metadata.unwrap().get_type_flag();

            if base.is_typeid_last() {
                match base.flag {
                    0x00 => tstr += "unknown",
                    0x01 => tstr += "void",
                    0x02 => tstr += "int8_t",
                    0x03 => tstr += "int16_t",
                    0x04 => tstr += "int32_t",
                    0x05 => tstr += "int64_t",
                    0x06 => tstr += "int128_t",
                    0x07 => tstr += "int",
                    0x08 => tstr += "bool",
                    0x09 => match tflag.flag {
                        0x00 => tstr += "float",
                        0x10 => tstr += "double",
                        0x20 => tstr += "long double",
                        0x30 => tstr += "special float",
                        _ => tstr += "unknown float",
                    },
                    _ => {}
                }
            } else {
                match self.typ.as_ref().unwrap() {
                    Types::Unset(_) => {
                        println!("TYPERESOLUTION:UNSET");
                    }
                    Types::Pointer(m, p) => {
                        tstr += format!(
                            "{}*",
                            self.convert_to_til_type(p.typ.as_ref(), m).get_type_name()
                        )
                        .as_str();
                    }
                    Types::Function(_, _) => {
                        println!("TYPERESOLUTION:Function");
                    }
                    Types::Array(_, _) => {
                        println!("TYPERESOLUTION:ARRAY");
                    }
                    Types::Typedef(_, p) => {
                        tstr += p.name.as_ref().unwrap().as_str();
                        println!("TYPERESOLUTION:TYPEDEF");
                    }
                    Types::Struct(m, s) => {
                        tstr += &self.tinfo.name;
                    }
                    Types::Union(_, _) => {
                        println!("TYPERESOLUTION:union");
                    }
                    Types::Enum(_, _) => {
                        println!("TYPERESOLUTION:enum");
                    }
                    Types::Bitfield(_, _) => {
                        println!("TYPERESOLUTION:bitfld");
                    }
                    Types::Unknown(_, _) => {
                        println!("TYPERESOLUTION:unk");
                    }
                }
            }

            tstr
        }
    }
}

impl TILSection {
    pub fn get_types(&self) -> Option<Vec<TILType>> {
        match &self.types {
            TILBucketType::Default(def) => match def {
                None => None,
                Some(sm) => Some(
                    sm.type_info
                        .iter()
                        .map(|x| TILType {
                            sec: self,
                            tinfo: x.clone(),
                            typ: match &x.info {
                                None => None,
                                Some(xy) => Some(xy.types.clone()),
                            },
                            metadata: match &x.info {
                                None => None,
                                Some(xy) => match xy.types {
                                    Types::Pointer(mdata, _)
                                    | Types::Function(mdata, _)
                                    | Types::Array(mdata, _)
                                    | Types::Typedef(mdata, _)
                                    | Types::Struct(mdata, _)
                                    | Types::Union(mdata, _)
                                    | Types::Enum(mdata, _)
                                    | Types::Bitfield(mdata, _)
                                    | Types::Unknown(mdata, _) => Some(mdata),
                                    _ => None,
                                },
                            },
                        })
                        .collect::<Vec<TILType>>(),
                ),
            },
            _ => None,
        }
    }

    pub fn get_type(&self, name: String) -> Option<TILType> {
        self.get_types()
            .unwrap()
            .into_iter()
            .find(|x| x.tinfo.name == name)
    }
}

impl Types {
    pub fn get_metadata(&self) -> Option<&TypeMetadata> {
        match self {
            Types::Pointer(m, _) => Some(m),
            Types::Function(m, _) => Some(m),
            Types::Array(m, _) => Some(m),
            Types::Typedef(m, _) => Some(m),
            Types::Struct(m, _) => Some(m),
            Types::Union(m, _) => Some(m),
            Types::Enum(m, _) => Some(m),
            Types::Bitfield(m, _) => Some(m),
            Types::Unknown(m, _) => Some(m),
            _ => None,
        }
    }

    pub fn get_tinfo(&self, sec: &TILSection) -> Option<TILTypeInfo> {
        match &sec.types {
            TILBucketType::Default(def) => match def {
                None => None,
                Some(sm) => sm.type_info.clone().into_iter().find(|x| match &x.info {
                    None => false,
                    Some(sinfo) => sinfo.types == *self,
                }),
            },
            _ => None,
        }
    }
}

impl TILTypeInfo {
    pub fn get_type_name(&self) -> String {
        let ty = &self.info.as_ref().unwrap().types;
        if matches!(ty, Types::Unset(_)) {
            String::from("")
        } else {
            let mut tstr = String::new();
            let flags = match ty {
                Types::Pointer(mdata, _)
                | Types::Function(mdata, _)
                | Types::Array(mdata, _)
                | Types::Typedef(mdata, _)
                | Types::Struct(mdata, _)
                | Types::Union(mdata, _)
                | Types::Enum(mdata, _)
                | Types::Bitfield(mdata, _)
                | Types::Unknown(mdata, _) => Some(mdata),
                _ => None,
            }
            .unwrap();

            let base = flags.get_base_type_flag();
            let tflag = flags.get_type_flag();

            if base.is_typeid_last() {
                match base.flag {
                    0x00 => tstr += "unknown",
                    0x01 => tstr += "void",
                    0x02 => tstr += "int8_t",
                    0x03 => tstr += "int16_t",
                    0x04 => tstr += "int32_t",
                    0x05 => tstr += "int64_t",
                    0x06 => tstr += "int128_t",
                    0x07 => tstr += "int",
                    0x08 => tstr += "bool",
                    0x09 => match tflag.flag {
                        0x00 => tstr += "float",
                        0x10 => tstr += "double",
                        0x20 => tstr += "long double",
                        0x30 => tstr += "special float",
                        _ => tstr += "unknown float",
                    },
                    _ => {}
                }
            } else {
                match ty {
                    Types::Unset(_) => {}
                    Types::Pointer(mdata, ptr) => {
                        let ptd = ptr.typ.as_ref();
                        let mut tinfo = self.clone();
                        tinfo.info = Some(TestTypes { types: ptd.clone() });
                        tstr += format!("{}", tinfo.get_type_name()).as_str();
                    }
                    Types::Function(_, _) => {}
                    Types::Array(_, _) => {}
                    Types::Typedef(_, _) => {}
                    Types::Struct(mdata, str) => {
                        if str.is_ref {
                            if let Types::Typedef(md, td) = str.type_ref.as_ref().unwrap().as_ref()
                            {
                                panic!("unhandled ref");
                            } else {
                                panic!("shouldnt occur");
                            }
                        } else {
                            tstr += self.name.as_ref()
                        }
                    }
                    Types::Union(_, _) => {}
                    Types::Enum(_, _) => {}
                    Types::Bitfield(_, _) => {}
                    Types::Unknown(_, _) => {}
                }
            }
            tstr
        }
    }
}

#[derive(Default, Debug, Clone)]
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
