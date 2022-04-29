use binrw::error::CustomError;
use binrw::{binread, FilePtr32};
use binrw::{BinRead, BinResult, ReadOptions};
use binrw::{BinReaderExt, BinrwNamedArgs};
use miniz_oxide::inflate::TINFLStatus;
use std::any::Any;
use std::fmt::{Debug, Display, Formatter};
use std::fs::File;
use std::io::prelude::*;
use std::io::{Read, Seek, SeekFrom};
use std::num::NonZeroU8;

#[derive(BinRead, Debug)]
struct IDBHeader {
    #[br(
    count = 4,
    map = |bytes: Vec<u8>| String::from_utf8_lossy(&bytes).into_owned(),
    assert(magic == "IDA0" || magic == "IDA1" || magic == "IDA2"))]
    magic: String,
    #[br(pad_before = 0x2_u16)]
    id0_offset: u64,
    id1_offset: u64,
    #[br(pad_before = 0x4_u32, assert(signature == 0xAABBCCDD))]
    signature: u32,
    #[br(assert(version == 0x6))]
    version: u16,
    nam_offset: u64,
    seg_offset: u64,
    til_offset: u64,
    initial_checksums: [u32; 5],
    id2_offset: u64,
    final_checksum: u32,
}

#[derive(BinRead, Debug, Default)]
struct IDBSectionHeader {
    compression_method: u8,
    section_length: u64,
}

#[derive(BinRead, Debug)]
struct ID0Section {}
#[derive(BinRead, Debug)]
struct ID1Section {}
#[derive(BinRead, Debug)]
struct NAMSection {}
#[derive(BinRead, Debug)]
struct SEGSection {}

const TIL_ZIP: u32 = 0x0001;
const TIL_MAC: u32 = 0x0002;
const TIL_ESI: u32 = 0x0004;
const TIL_UNI: u32 = 0x0008;
const TIL_ORD: u32 = 0x0010;
const TIL_ALI: u32 = 0x0020;
const TIL_MOD: u32 = 0x0040;
const TIL_STM: u32 = 0x0080;
const TIL_SLD: u32 = 0x0100;

#[derive(BinRead, Debug, Clone)]
#[br(import { is_u64: bool })]
pub enum TILOrdinal {
    #[br(pre_assert(is_u64 == false))]
    U32(u32),
    #[br(pre_assert(is_u64 == true))]
    U64(u64),
}

#[derive(Clone, Debug)]
pub struct NullVecLenString(pub Vec<String>);
#[derive(Clone, Default, BinRead, Debug)]
pub struct TypeMetadata(pub u8);
#[derive(Clone, Debug)]
pub struct BaseTypeFlag(pub u8);
#[derive(Clone, Debug)]
pub struct FullTypeFlag(u8);
#[derive(Clone, Debug)]
pub struct TypeFlag(pub u8);
#[derive(Clone, Debug)]
pub struct CallingConventionFlag(u8);

impl CallingConventionFlag {
    fn is_spoiled(&self) -> bool {
        self.0 == 0xA0
    }

    fn is_void_arg(&self) -> bool {
        self.0 == 0x20
    }

    fn is_special_pe(&self) -> bool {
        self.0 == 0xD0 || self.0 == 0xE0 || self.0 == 0xF0
    }
}

impl TypeMetadata {
    pub fn get_base_type_flag(&self) -> BaseTypeFlag {
        BaseTypeFlag(self.0 & 0x0F)
    }

    pub fn get_full_type_flag(&self) -> FullTypeFlag {
        FullTypeFlag(self.0 & (0x0F | 0x30))
    }

    pub fn get_type_flag(&self) -> TypeFlag {
        TypeFlag(self.0 & 0x30)
    }

    pub fn get_calling_convention(&self) -> CallingConventionFlag {
        CallingConventionFlag(self.0 & 0xF0)
    }
}

impl TypeFlag {
    fn is_non_based(&self) -> bool {
        self.0 == 0x10
    }

    pub fn is_unsigned(&self) -> bool {
        self.0 == 0x20
    }

    pub fn is_signed(&self) -> bool {
        !self.is_unsigned()
    }

    fn is_type_closure(&self) -> bool {
        self.0 == 0x30
    }
}

impl FullTypeFlag {
    fn is_enum(&self) -> bool {
        self.0 == (0x0D | 0x20)
    }

    fn is_void(&self) -> bool {
        self.0 == (0x01 | 0x00)
    }

    fn is_struct(&self) -> bool {
        self.0 == (0x0D | 0x00)
    }

    fn is_union(&self) -> bool {
        self.0 == (0x0D | 0x10)
    }

    fn is_typedef(&self) -> bool {
        self.0 == (0x0D | 0x30)
    }
}

impl BaseTypeFlag {
    fn is_pointer(&self) -> bool {
        self.0 == 0x0A
    }

    fn is_function(&self) -> bool {
        self.0 == 0x0C
    }

    fn is_array(&self) -> bool {
        self.0 == 0x0B
    }

    fn is_bitfield(&self) -> bool {
        self.0 == 0x0E
    }

    fn is_typeid_last(&self) -> bool {
        self.0 <= 0x09
    }

    fn is_reserved(&self) -> bool {
        self.0 == 0x0F
    }
}

#[derive(Clone, Debug)]
pub enum Types {
    Unset(TypeMetadata),
    Pointer(Box<Pointer>),
    Function(Box<Function>),
    Array(Box<Array>),
    Typedef(Typedef),
    Struct(Box<Struct>),
    Union(Box<Union>),
    Enum(Box<Enum>),
    Bitfield(Bitfield),
    Unknown(Vec<u8>),
}

impl Default for Types {
    fn default() -> Self {
        Self::Unset(TypeMetadata::default())
    }
}

#[derive(Clone, Default, Debug)]
pub struct DT(pub u16, u8);
#[derive(Clone, Default, Debug)]
pub struct DE(pub u32);
#[derive(Clone, Default, Debug)]
pub struct TypeAttribute(pub u16);
#[derive(Clone, Default, Debug)]
pub struct TAH(pub TypeAttribute);
#[derive(Clone, Default, Debug)]
pub struct SDACL(pub TypeAttribute);
#[derive(Clone, Default, Debug)]
#[binread]
struct DTString {
    dt: DT,
    #[br(
    count = dt.0,
    map = | bytes: Vec < u8 > | String::from_utf8_lossy(& bytes).into_owned())]
    string: String,
}
#[derive(Clone, Default, Debug)]
#[binread]
pub struct DTBytes {
    pub dt: DT,
    #[br(count = dt.0)]
    pub bytes: Vec<u8>,
}
#[derive(Default, Debug)]
struct DA {
    nelem: u8,
    base: u8,
}

#[derive(BinRead, Default, Clone, Debug)]
pub struct StructMember(pub Types, pub SDACL);
#[derive(Clone, BinRead, Default, Debug)]
pub struct UnionMember(pub Types);

#[derive(Clone, Default, Debug)]
pub struct Ref(pub Types);

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

impl BinRead for Ref {
    type Args = ();

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        _: &binrw::ReadOptions,
        _: Self::Args,
    ) -> binrw::BinResult<Self> {
        let mut bytes = reader.read_ne::<DTBytes>()?;
        if bytes.bytes.is_empty() || bytes.bytes[0] != '=' as u8 {
            let mut ser = serialize_dt(bytes.dt.0);
            bytes.bytes.splice(..0, ser.drain(..));
            bytes.bytes.insert(0, '=' as u8);
        }

        let mut cursor = binrw::io::Cursor::new(bytes.bytes);
        Ok(Ref(cursor.read_ne::<Types>()?))
    }
}

impl BinRead for DA {
    type Args = ();

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        _: &binrw::ReadOptions,
        _: Self::Args,
    ) -> binrw::BinResult<Self> {
        let mut a = 0;
        let mut b = 0;
        let mut da = 0;
        let mut base = 0;
        let mut nelem = 0;
        loop {
            let mut typ = reader.read_ne::<u8>()?;
            if typ & 0x80 == 0 {
                reader.seek(SeekFrom::Current(-1));
                break;
            }
            da = (da << 7) | typ & 0x7F;
            b += 1;
            if b >= 4 {
                let mut z = reader.read_ne::<u8>()?;
                reader.seek(SeekFrom::Current(-1));
                if z != 0 {
                    base = 0x10 * da | z & 0xF
                }
                nelem = (reader.read_ne::<u8>()? >> 4) & 7;
                loop {
                    let mut y = reader.read_ne::<u8>()?;
                    reader.seek(SeekFrom::Current(-1));
                    if (y & 0x80) == 0 {
                        break;
                    }
                    reader.seek(SeekFrom::Current(1));
                    nelem = (nelem << 7) | y & 0x7F;
                    a += 1;
                    if a >= 4 {
                        return Ok(Self { nelem, base });
                    }
                }
            }
        }
        return Ok(Self { nelem, base });
    }
}

impl BinRead for TypeAttribute {
    type Args = ();

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        _: &binrw::ReadOptions,
        _: Self::Args,
    ) -> binrw::BinResult<Self> {
        let mut val: u16 = 0;
        let mut tah: u8 = reader.read_ne()?;
        let mut tmp = ((tah & 1) | ((tah >> 3) & 6)) + 1;
        if tah == 0xFE || tmp == 8 {
            if tmp == 8 {
                val = tmp as u16;
            }
            let mut shift = 0;
            loop {
                let mut next_byte: u8 = reader.read_ne()?;
                if next_byte == 0 {
                    panic!("error");
                }
                val |= ((next_byte & 0x7F) as u16) << shift;
                if next_byte & 0x80 == 0 {
                    break;
                }
                shift += 7;
            }
        }
        let mut unk = Vec::new();
        if (val & 0x0010) > 0 {
            val = reader.read_ne::<DT>()?.0;
            for _ in 0..val {
                let string = reader.read_ne::<DTString>()?;
                let another_de = reader.read_ne::<DT>()?;
                reader.seek(SeekFrom::Current(another_de.0 as i64));
                unk.push(string.string);
            }
        }
        return Ok(TypeAttribute(val));
    }
}

impl BinRead for SDACL {
    type Args = ();

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        _: &binrw::ReadOptions,
        _: Self::Args,
    ) -> binrw::BinResult<Self> {
        let sdacl: u8 = reader.read_ne()?;
        if ((sdacl & !0x30) ^ 0xC0) <= 0x01 {
            reader.seek(SeekFrom::Current(-1));
            Ok(SDACL(reader.read_ne::<TypeAttribute>()?))
        } else {
            reader.seek(SeekFrom::Current(-1));
            Ok(SDACL::default())
        }
    }
}

impl BinRead for TAH {
    type Args = ();

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        _: &binrw::ReadOptions,
        _: Self::Args,
    ) -> binrw::BinResult<Self> {
        let tah: u8 = reader.read_ne()?;
        if tah == 0xFE {
            reader.seek(SeekFrom::Current(-1));
            Ok(TAH(reader.read_ne::<TypeAttribute>()?))
        } else {
            reader.seek(SeekFrom::Current(-1));
            Ok(TAH::default())
        }
    }
}

impl BinRead for DE {
    type Args = ();

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        _: &binrw::ReadOptions,
        _: Self::Args,
    ) -> binrw::BinResult<Self> {
        let mut val: u32 = 0;
        loop {
            let mut hi = val << 6;
            let mut b: u8 = reader.read_ne()?;
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
        return Ok(DE(val));
    }
}

impl BinRead for DT {
    type Args = ();

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        _: &binrw::ReadOptions,
        _: Self::Args,
    ) -> binrw::BinResult<Self> {
        let mut val__u8 = reader.read_ne::<u8>()?;
        let mut val = val__u8 as u16;
        let mut SEG = 1;
        if (val__u8 & 0x80) > 0 {
            let intermediate = reader.read_ne::<u8>()? as u16;
            val = val & 0x7F | intermediate << 7;
            SEG = 2;
        }
        return Ok(DT(val - 1, SEG));

        // let mut val: u8 = reader.read_ne()?;
        // if (val & 0x80) == 1 {
        //     val = val & 0x7f;
        //     let other: u8 = reader.read_ne()?;
        //     Ok(DT(((val as u16) | (other as u16) << 7) - 1, 2))
        // } else {
        //     val = val.overflowing_sub(1).0;
        //     Ok(DT((val) as u16, 1))
        // }
    }
}

#[derive(Clone, Default, Debug)]
// #[binread]
pub struct Pointer {
    pub metadata: TypeMetadata,
    // #[br(if(metadata.get_type_flag().is_type_closure()))]
    // closure_decision: u8,
    // #[br(if(metadata.get_type_flag().is_type_closure() && closure_decision == 0xFF))]
    pub closure: Option<Types>,
    // #[br(if(metadata.get_type_flag().is_type_closure() && closure_decision != 0xFF))]
    pub based_ptr_size: u8,
    pub tah: TAH,
    pub typ: Types,
}

impl BinRead for Pointer {
    type Args = ();

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        _: &binrw::ReadOptions,
        _: Self::Args,
    ) -> binrw::BinResult<Self> {
        let metadata = reader.read_ne::<TypeMetadata>()?;
        let mut ptr = Pointer::default();
        ptr.metadata = metadata;
        if ptr.metadata.get_type_flag().is_type_closure() {
            if reader.read_ne::<u8>()? == 0xFF {
                ptr.closure = Some(reader.read_ne::<Types>()?);
            } else {
                ptr.closure = None;
                ptr.based_ptr_size = reader.read_ne::<u8>()?;
            }
        }
        ptr.tah = reader.read_ne()?;
        ptr.typ = reader.read_ne()?;
        Ok(ptr)
    }
}

#[derive(Clone, Default, Debug)]
pub struct FuncArgs(pub Types);
#[derive(Clone, Default, Debug)]
pub struct Function {
    metadata: TypeMetadata,
    cc: TypeMetadata,
    pub ret: Types,
    pub args: Vec<FuncArgs>,
}
impl BinRead for Function {
    type Args = ();

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        _: &binrw::ReadOptions,
        _: Self::Args,
    ) -> binrw::BinResult<Self> {
        let metadata = reader.read_ne::<TypeMetadata>()?;
        let mut flags = 0;
        flags |= 4 * metadata.get_type_flag().0;

        let mut cm = reader.read_ne::<TypeMetadata>()?;
        if cm.get_calling_convention().is_spoiled() {
            loop {
                if !cm.get_calling_convention().is_spoiled() {
                    break;
                }

                reader.seek(SeekFrom::Current(1));
                let mut nspoiled = cm.0 & !0xf0;
                let mut f = 0_u8;
                if nspoiled == 15 {
                    f = 2 * (reader.read_ne::<u8>()? & 0x1F)
                }

                cm = reader.read_ne::<TypeMetadata>()?;
                reader.seek(SeekFrom::Current(-1));
                flags |= f;
            }
        }
        reader.seek(SeekFrom::Current(-1));
        let cc = reader.read_ne::<TypeMetadata>()?;
        let tah = reader.read_ne::<TAH>()?;
        let ret = reader.read_ne::<Types>()?;
        if cc.get_calling_convention().is_special_pe() {
            match &ret {
                Types::Unset(mdata) => {
                    if !mdata.get_full_type_flag().is_void() {
                        panic!("Special PE unhandled");
                    }
                }
                _ => {}
            }
        }

        if cc.get_calling_convention().is_void_arg() {
            Ok(Self {
                metadata,
                cc,
                ret,
                ..Default::default()
            })
        } else {
            let n = reader.read_ne::<DT>()?.0;
            let mut args = Vec::<FuncArgs>::new();
            for ind in 0..n {
                let temp = reader.read_ne::<u8>()?;
                reader.seek(SeekFrom::Current(-1));
                if temp == 0xFF {
                    reader.seek(SeekFrom::Current(1));
                    let flags = reader.read_ne::<DE>()?;
                }
                let fnarg = FuncArgs(reader.read_ne::<Types>()?);
                if cc.get_calling_convention().is_special_pe() {
                    panic!("Argloc unhandled");
                }
                args.push(fnarg);
            }

            Ok(Self {
                metadata,
                cc,
                ret,
                args,
            })
        }
    }
}

#[derive(Clone, Debug)]
// #[binread]
pub struct Array {
    pub metadata: TypeMetadata,
    // #[br(if(metadata.get_type_flag().is_non_based()), calc(1))]
    pub is_non_based: bool,
    pub base: u8,
    pub nelem: u16,
    // #[br(if(is_non_based==1), calc(0))]
    // non_based_base: u8,
    // #[br(if(is_non_based==1))]
    // non_based_nelem: DT,
    // #[br(if(is_non_based==0))]
    // based_info: DA, // contains base/nelem
    pub tah: TAH,
    pub elem_type: Types,
}

impl BinRead for Array {
    type Args = ();

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        _: &binrw::ReadOptions,
        _: Self::Args,
    ) -> binrw::BinResult<Self> {
        let metadata = reader.read_ne::<TypeMetadata>()?;
        let is_non_based = metadata.get_type_flag().is_non_based();
        if is_non_based {
            let base = 0;
            let nelem = reader.read_ne::<DT>()?.0;
            let tah = reader.read_ne::<TAH>()?;
            let elem_type = reader.read_ne::<Types>()?;
            Ok(Array {
                metadata,
                is_non_based,
                base,
                nelem,
                tah,
                elem_type,
            })
        } else {
            let da = reader.read_ne::<DA>()?;
            let base = da.base;
            let nelem = da.nelem as u16;
            let tah = reader.read_ne::<TAH>()?;
            let elem_type = reader.read_ne::<Types>()?;
            Ok(Array {
                metadata,
                is_non_based,
                base,
                nelem,
                tah,
                elem_type,
            })
        }
    }
}

#[derive(Clone, Default, Debug)]
// #[binread]
pub struct Typedef {
    pub metadata: TypeMetadata,
    pub buf: DTBytes,
    // #[br(if(buf.bytes[0] == '#' as u8), calc(1))]
    pub is_ordref: bool,
    // #[br(if(is_ordref == 1), seek_before(SeekFrom::Current(-((buf.dt.0 as i64)+(buf.dt.1 as i64)))), pad_after(buf.dt.0+buf.dt.1 as u16))]
    pub ordinal: DE,
    pub name: String,
}

impl BinRead for Typedef {
    type Args = ();

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        _: &binrw::ReadOptions,
        _: Self::Args,
    ) -> binrw::BinResult<Self> {
        let metadata = reader.read_ne::<TypeMetadata>()?;
        let buf = reader.read_ne::<DTBytes>()?;
        if !buf.bytes.is_empty() && buf.bytes[0] == '#' as u8 {
            let is_ordref = true;
            let mut cursor = binrw::io::Cursor::new(&buf.bytes[1..]);
            let ordinal = cursor.read_ne::<DE>()?;
            let name = String::from("");
            Ok(Typedef {
                metadata,
                buf,
                is_ordref,
                ordinal,
                name,
            })
        } else {
            let is_ordref = false;
            let ordinal = DE::default();
            let name = String::from_utf8_lossy(&buf.bytes).into_owned();
            Ok(Typedef {
                metadata,
                buf,
                is_ordref,
                ordinal,
                name,
            })
        }
    }
}

#[derive(Clone, Debug, Default)]
// #[binread]
pub struct Struct {
    pub metadata: TypeMetadata,
    // n: DT,
    // #[br(if(n.0==0), calc(1))]
    pub is_ref: bool,
    // #[br(if(is_ref==1))]
    pub ref_type: Ref,
    // #[br(if(is_ref==1))]
    // sdacl_attr: SDACL,
    // #[br(if(is_ref==0), calc(n.0 & 7))]
    // alpow: u16,
    // #[br(if(is_ref==0 && alpow != 0), calc(1 << (alpow - 1)))]
    pub effective_alignment: u16,
    // #[br(if(is_ref==0))]
    pub taudt_bits: SDACL,
    // #[br(if(is_ref==0), count=n.0>>3)]
    pub members: Vec<StructMember>,
}

#[derive(Clone, Debug, Default)]
// #[binread]
pub struct Union {
    pub metadata: TypeMetadata,
    // n: DT,
    // #[br(if(n.0==0), calc(1))]
    pub is_ref: bool,
    // #[br(if(is_ref==1))]
    pub ref_type: Ref,
    // #[br(if(is_ref==1))]
    // sdacl_attr: SDACL,
    // #[br(if(is_ref==0), calc(n.0 & 7))]
    // alpow: u16,
    // #[br(if(is_ref==0 && alpow != 0), calc(1 << (alpow - 1)))]
    pub effective_alignment: u16,
    // #[br(if(is_ref==0))]
    pub taudt_bits: SDACL,
    // #[br(if(is_ref==0), count=n.0>>3)]
    pub members: Vec<UnionMember>,
}

impl BinRead for Struct {
    type Args = ();

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        _: &binrw::ReadOptions,
        _: Self::Args,
    ) -> binrw::BinResult<Self> {
        let metadata = reader.read_ne::<TypeMetadata>()?;
        let mut n = reader.read_ne::<DT>()?.0 as u32;
        let mut res = Self::default();
        res.metadata = metadata;
        if n == 0 {
            res.is_ref = true;
            res.ref_type = reader.read_ne::<Ref>()?;
            res.taudt_bits = reader.read_ne::<SDACL>()?;
        } else {
            if n == 0x7FFE {
                n = reader.read_ne::<DE>()?.0;
            }
            let alpow = n & 7;
            let mem_cnt = n >> 3;
            if alpow == 0 {
                res.effective_alignment = 0;
            } else {
                res.effective_alignment = 1 << (alpow - 1);
            }
            res.taudt_bits = reader.read_ne::<SDACL>()?;
            let mut vec: Vec<StructMember> = Vec::new();
            for _ in 0..mem_cnt {
                vec.push(reader.read_ne::<StructMember>()?);
            }
            res.members = vec;
        }
        Ok(res)
    }
}

impl BinRead for Union {
    type Args = ();

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        _: &binrw::ReadOptions,
        _: Self::Args,
    ) -> binrw::BinResult<Self> {
        let metadata = reader.read_ne::<TypeMetadata>()?;
        let mut n = reader.read_ne::<DT>()?.0 as u32;
        let mut res = Self::default();
        res.metadata = metadata;
        if n == 0 {
            res.is_ref = true;
            res.ref_type = reader.read_ne::<Ref>()?;
            res.taudt_bits = reader.read_ne::<SDACL>()?;
        } else {
            if n == 0x7FFE {
                n = reader.read_ne::<DE>()?.0;
            }
            let alpow = n & 7;
            let mem_cnt = n >> 3;
            if alpow == 0 {
                res.effective_alignment = 0;
            } else {
                res.effective_alignment = 1 << (alpow - 1);
            }
            res.taudt_bits = reader.read_ne::<SDACL>()?;
            let mut vec: Vec<UnionMember> = Vec::new();
            for _ in 0..mem_cnt {
                vec.push(reader.read_ne::<UnionMember>()?);
            }
            res.members = vec;
        }
        Ok(res)
    }
}

#[derive(Clone, Default, Debug)]
pub struct EnumMember(pub u64);

#[derive(Clone, Default, Debug)]
pub struct Enum {
    pub metadata: TypeMetadata,
    pub group_sizes: Vec<DT>,
    pub taenum_bits: TypeAttribute,
    pub bte: u8,
    pub members: Vec<EnumMember>,
    pub ref_type: Ref,
    pub is_ref: bool,
    pub bytesize: u64,
}
impl BinRead for Enum {
    type Args = (u8,);

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        _: &binrw::ReadOptions,
        args: Self::Args,
    ) -> binrw::BinResult<Self> {
        let metadata = reader.read_ne::<TypeMetadata>()?;
        let mut n = reader.read_ne::<DT>()?.0 as u32;
        let mut is_ref = false;
        if n == 0 {
            let ref_type = reader.read_ne::<Ref>()?;
            let taenum_bits = reader.read_ne::<SDACL>()?.0;
            is_ref = true;
            return Ok(Enum {
                metadata,
                ref_type,
                taenum_bits,
                is_ref,
                ..Default::default()
            });
        } else {
            if n == 0x7FFE {
                n = reader.read_ne::<DE>()?.0;
            }
            let taenum_bits = reader.read_ne::<TAH>()?.0;
            let bte = reader.read_ne::<u8>()?;
            let mut cur: u64 = 0;
            let mut hi = DE::default();
            let mut bytesize = 0;
            let mask: u64 = {
                let emsize = bte & 0x07;
                let mut bitsize = 0_u64;
                if emsize != 0 {
                    bytesize = 1 << (emsize - 1);
                } else if args.0 != 0 {
                    bytesize = args.0 as u64;
                } else {
                    bytesize = 4;
                }
                bitsize = bytesize * 8;
                if bitsize < 64 {
                    (1 << bitsize) - 1
                } else {
                    0xFFFFFFFFFFFFFFFF
                }
            };
            let mut group_sizes = Vec::<DT>::new();
            let mut members = Vec::<EnumMember>::new();
            for _ in 0..n {
                let lo = reader.read_ne::<DE>()?;
                if (taenum_bits.0 & 0x0020) > 0 {
                    hi = reader.read_ne::<DE>()?;
                }
                if (bte & 0x10) > 0 {
                    group_sizes.push(reader.read_ne::<DT>()?);
                }
                cur = cur
                    .overflowing_add((lo.0 as u64) | ((hi.0 as u64) << 32) & mask)
                    .0;
                // cur += (lo.0 as u64) | ((hi.0 as u64) << 32) & mask;
                members.push(EnumMember(cur));
            }
            return Ok(Enum {
                metadata,
                group_sizes,
                taenum_bits,
                bte,
                members,
                is_ref,
                bytesize,
                ..Default::default()
            });
        }
        Ok(Default::default())
    }
}

#[derive(Debug, Clone)]
pub struct Bitfield {
    metadata: TypeMetadata,
    pub unsigned: bool,
    pub width: u16,
    pub nbytes: i32,
}

impl BinRead for Bitfield {
    type Args = ();

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        _: &binrw::ReadOptions,
        _: Self::Args,
    ) -> binrw::BinResult<Self> {
        let metadata = reader.read_ne::<TypeMetadata>()?;
        let nbytes = 1 << (metadata.get_type_flag().0 >> 4);
        let dt = reader.read_ne::<DT>()?;
        let width = &dt.0 >> 1;
        let unsigned = (&dt.0 & 1) > 0;
        let tah = reader.read_ne::<TAH>()?;
        Ok(Self {
            metadata,
            unsigned,
            width,
            nbytes,
        })
    }
}

impl BinRead for Types {
    type Args = (u8,);

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        _: &binrw::ReadOptions,
        args: Self::Args,
    ) -> binrw::BinResult<Self> {
        let metadata = TypeMetadata(reader.read_ne()?);
        if metadata.get_base_type_flag().is_typeid_last()
            || metadata.get_base_type_flag().is_reserved()
        {
            // reader.seek(SeekFrom::Current(1));
            Ok(Types::Unset(metadata))
        } else {
            reader.seek(SeekFrom::Current(-1));
            let mut collect_rest = || {
                reader
                    .bytes()
                    .take_while(|x| !matches!(x, Ok(0)))
                    .map(|x| x.unwrap())
                    .collect::<Vec<u8>>()
            };

            if metadata.get_base_type_flag().is_pointer() {
                Ok(Types::Pointer(Box::new(reader.read_ne()?)))
            } else if metadata.get_base_type_flag().is_function() {
                Ok(Types::Function(Box::new(reader.read_ne()?)))
            } else if metadata.get_base_type_flag().is_array() {
                Ok(Types::Array(Box::new(reader.read_ne()?)))
            } else if metadata.get_full_type_flag().is_typedef() {
                Ok(Types::Typedef(reader.read_ne()?))
            } else if metadata.get_full_type_flag().is_union() {
                Ok(Types::Union(Box::new(reader.read_ne()?)))
            } else if metadata.get_full_type_flag().is_struct() {
                Ok(Types::Struct(Box::new(reader.read_ne()?)))
            } else if metadata.get_full_type_flag().is_enum() {
                Ok(Types::Enum(Box::new(reader.read_ne_args(args)?)))
            } else if metadata.get_base_type_flag().is_bitfield() {
                Ok(Types::Bitfield(reader.read_ne()?))
            } else {
                Ok(Types::Unknown(collect_rest()))
            }
        }
    }
}

impl BinRead for NullVecLenString {
    type Args = ();

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        _: &binrw::ReadOptions,
        _: Self::Args,
    ) -> binrw::BinResult<Self> {
        let vec = reader
            .bytes()
            .take_while(|x| !matches!(x, Ok(0)))
            .map(|x| x.unwrap())
            .collect::<Vec<u8>>();

        let mut pos = 0;
        let mut nvec: Vec<String> = Vec::new();
        while pos < vec.len() {
            let len = vec[pos];
            nvec.push(String::from_utf8_lossy(&vec[pos + 1..pos + len as usize]).to_string());
            pos += len as usize;
        }

        Ok(NullVecLenString(nvec))
    }
}

#[derive(BinRead, Debug, Clone)]
#[br(import(size_e: u8))]
pub struct TILTypeInfo {
    flags: u32,
    pub name: binrw::NullString,
    #[br(args { is_u64: (flags >> 31u32) != 0})]
    pub ordinal: TILOrdinal,
    #[br(args(size_e), restore_position)]
    pub tinfo: Types,
    _info: binrw::NullString,
    cmt: binrw::NullString,
    pub fields: NullVecLenString,
    fieldcmts: binrw::NullString,
    sclass: u8,
}

#[derive(Debug)]
#[binread]
#[br(import { size_e: u8 })]
pub struct TILBucket {
    pub ndefs: u32,
    len: u32,
    #[br(args{ count: ndefs.try_into().unwrap(), inner: (size_e,) }, restore_position)]
    pub type_info: Vec<TILTypeInfo>,
    #[br(count = len)]
    data: Vec<u8>,
}

#[derive(Debug)]
pub struct TILBucketZip {
    pub ndefs: u32,
    len: u32,
    compressed_len: u32,
    // #[br(args{ count: ndefs.try_into().unwrap(), inner: (size_e,) },restore_position)]
    pub type_info: Vec<TILTypeInfo>,
    // #[br(count = compressed_len)]
    data: Vec<u8>,
}

impl TILBucketZip {
    pub fn unzip(&self) -> TILBucket {
        TILBucket {
            ndefs: self.ndefs,
            len: self.len,
            type_info: self.type_info.clone(),
            data: self.data.clone(),
        }
    }
}

enum DecompressionError {
    Error(TINFLStatus),
}

impl Debug for DecompressionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Decompression Error: {}",
            match self {
                DecompressionError::Error(status) => *status as u8,
                _ => 0,
            }
        )
    }
}

impl Display for DecompressionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Decompression Error: {}",
            match self {
                DecompressionError::Error(status) => *status as u8,
                _ => 0,
            }
        )
    }
}

impl std::error::Error for DecompressionError {}

fn stream_len<R: Read + Seek>(reader: &mut R) -> std::io::Result<u64> {
    let old_pos = reader.stream_position()?;
    let len = reader.seek(SeekFrom::End(0))?;

    // Avoid seeking a third time when we were already at the end of the
    // stream. The branch is usually way cheaper than a seek operation.
    if old_pos != len {
        reader.seek(SeekFrom::Start(old_pos))?;
    }

    Ok(len)
}

impl BinRead for TILBucketZip {
    type Args = <TILBucket as BinRead>::Args;

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        options: &ReadOptions,
        args: Self::Args,
    ) -> BinResult<Self> {
        let ndefs = reader.read_ne()?;
        let len = reader.read_ne()?;
        let compressed_len = reader.read_ne::<u32>()?;

        let restore = reader.stream_position()?;

        let data_compressed = reader.read_ne_args::<Vec<u8>>(binrw::VecArgs {
            count: compressed_len as usize,
            inner: (),
        })?;

        let data =
            miniz_oxide::inflate::decompress_to_vec_zlib(&data_compressed).map_err(|err| {
                binrw::Error::Custom {
                    pos: restore,
                    err: Box::new(DecompressionError::Error(err)),
                }
            })?;

        let post = reader.stream_position()?;
        reader.seek(SeekFrom::Start(restore));
        let mut cursor = binrw::io::Cursor::new(data.as_slice());
        // println!("START READ...");
        // let type_info = cursor.read_ne_args(binrw::VecArgs::<(u8,)> {
        //     count: ndefs as usize,
        //     inner: (args.size_e,),
        // })?;
        // println!("DONE...");

        let type_info = (0..ndefs)
            .map(|ind| {
                // println!(
                //     "{}->{} :: {}",
                //     cursor.stream_position().unwrap(),
                //     stream_len(&mut cursor).unwrap(),
                //     data.len()
                // );
                // let POS = cursor.stream_position().unwrap();
                // let _ = cursor.read_ne::<u32>().unwrap();
                // let str = cursor.read_ne::<binrw::NullString>().unwrap();
                // println!("GOINGTOPARSE:{} @ {}", str.clone().into_string(), ind);
                // cursor.seek(SeekFrom::Start(POS));

                // if str.clone().into_string() == "IN_DECLS" {
                //     println!("-MARKER");
                // }

                let ok = cursor.read_ne_args::<TILTypeInfo>((args.size_e,)).unwrap();
                // if ok.name.clone().into_string() == "-[NSPointerFunctions initWithOptions:]" {
                //     println!("{:#x?}", ok);
                // }
                ok
            })
            .collect::<Vec<TILTypeInfo>>();

        reader.seek(SeekFrom::Start(post));

        Ok(Self {
            ndefs,
            len,
            compressed_len,
            type_info,
            data,
        })
    }
}

#[derive(Debug)]
// #[binread]
// #[br(import { is_zip: bool })]
pub enum TILBucketType {
    // #[br(pre_assert(is_zip == false))]
    Default(TILBucket),
    // #[br(pre_assert(is_zip == true))]
    Zip(TILBucketZip),
}

impl BinRead for TILBucketType {
    type Args = (bool, u8);

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        options: &ReadOptions,
        args: Self::Args,
    ) -> BinResult<Self> {
        if args.0 == false {
            Ok(Self::Default(
                reader.read_ne_args(TILBucketBinReadArgs { size_e: args.1 })?,
            ))
        } else {
            Ok(Self::Zip(
                reader.read_ne_args(TILBucketBinReadArgs { size_e: args.1 })?,
            ))
        }
    }
}

#[binread]
#[derive(Debug)]
#[br(import(is_standalone: bool))]
pub struct TILSection {
    #[br(if(is_standalone == false))]
    header: IDBSectionHeader,
    #[br(
    count = 6,
    map = |bytes: Vec<u8>| String::from_utf8_lossy(&bytes).into_owned(),
    assert(signature == "IDATIL"))]
    signature: String,
    format: u32,
    flags: u32,
    #[br(temp)]
    title_len: u8,
    #[br(
    count = title_len,
    map = |bytes: Vec<u8>| String::from_utf8_lossy(&bytes).into_owned())]
    title: String,
    #[br(temp)]
    base_len: u8,
    #[br(
    count = base_len,
    map = |bytes: Vec<u8>| String::from_utf8_lossy(&bytes).into_owned())]
    base: String,
    id: u8,
    cm: u8,
    size_i: u8,
    size_b: u8,
    size_e: u8,
    def_align: u8,
    #[br(if((flags & TIL_ESI) > 0))]
    size_s: Option<u8>,
    #[br(if((flags & TIL_ESI) > 0))]
    size_l: Option<u8>,
    #[br(if((flags & TIL_ESI) > 0))]
    size_ll: Option<u8>,
    #[br(if((flags & TIL_SLD) > 0))]
    size_ldbl: Option<u8>,
    #[br(args((flags & TIL_ZIP) > 0, size_e))]
    pub symbols: TILBucketType,
    #[br(if((flags & TIL_ORD) > 0))]
    type_ordinal_numbers: Option<u32>,
    #[br(args((flags & TIL_ZIP) > 0, size_e))]
    pub types: TILBucketType,
    // TODO: Fix this, I think the structures differ from the other buckets.
    // #[br(args((flags & TIL_ZIP) > 0, size_e))]
    // macros: TILBucketType,
}

#[derive(BinRead, Debug)]
struct ID2Section {}

#[derive(BinRead, Debug)]
pub struct IDB {
    header: IDBHeader,
    #[br(seek_before = SeekFrom::Start(header.id0_offset), if(header.id0_offset != 0))]
    id0: Option<ID0Section>,
    #[br(seek_before = SeekFrom::Start(header.id1_offset), if(header.id1_offset != 0))]
    id1: Option<ID1Section>,
    #[br(seek_before = SeekFrom::Start(header.nam_offset), if(header.nam_offset != 0))]
    nam: Option<NAMSection>,
    #[br(seek_before = SeekFrom::Start(header.seg_offset), if(header.seg_offset != 0))]
    seg: Option<SEGSection>,
    #[br(seek_before = SeekFrom::Start(header.til_offset), if(header.til_offset != 0))]
    pub til: Option<TILSection>,
    #[br(seek_before = SeekFrom::Start(header.id2_offset), if(header.id2_offset != 0))]
    id2: Option<ID2Section>,
}

impl TILSection {
    pub fn parse(bytes: &[u8]) -> BinResult<Self> {
        let mut cursor = binrw::io::Cursor::new(bytes);
        Ok(cursor.read_ne_args((true,))?)
    }

    pub fn parse_from_file(path: String) -> BinResult<Self> {
        let file = File::open(path)?;
        let mut reader = std::io::BufReader::new(file);
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer)?;
        TILSection::parse(&buffer)
    }
}

impl IDB {
    pub fn parse(bytes: &[u8]) -> BinResult<Self> {
        let mut cursor = binrw::io::Cursor::new(bytes);
        Ok(cursor.read_ne()?)
    }

    pub fn parse_from_file(path: String) -> BinResult<Self> {
        let file = File::open(path)?;
        let mut reader = std::io::BufReader::new(file);
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer)?;
        IDB::parse(&buffer)
    }
}
