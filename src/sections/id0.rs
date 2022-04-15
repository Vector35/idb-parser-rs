use crate::sections::IDBSectionHeader;
use crate::{gen_field_opt, gen_parser, gen_parser_body};
use derivative::Derivative;
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::default::Default;

#[derive(Default, Derivative)]
#[derivative(Debug)]
pub struct ID0Section {
    pub header: IDBSectionHeader,
    pub next_free_offset: u32,
    pub page_size: u16,
    pub root_page: u32,
    pub record_count: u32,
    pub page_count: u32,
    pub _unk: u8,
    pub signature: String,
    pub btree_version: f32,
    #[derivative(Debug = "ignore")]
    pub page_buf: Vec<u8>,
    #[derivative(Debug = "ignore")]
    pub pages: Vec<Option<Page>>,
}

gen_parser!(
    parse <ID0Section> visit ID0SectionVisitor,
    |seq|<ID0Section>,
    [
        header, next_free_offset, page_size, root_page,
        record_count, page_count, _unk, signature,
        btree_version, page_buf, pages
    ],
    [
        header,
        next_free_offset,
        page_size,
        root_page,
        record_count,
        page_count,
        _unk,
        (signature => .
            String::from_utf8_lossy(
                (0..25).map(|_|{
                    seq.next_element().unwrap().unwrap()
                })
                .collect::<Vec<u8>>()
                .as_slice())
                .to_string()
        ),
        (btree_version => .
            signature.chars()
                .filter(|c| c.is_digit(10) || *c == '.')
                .take(3)
                .collect::<String>()
                .parse::<f32>()
                .unwrap()
        ),
        (mut page_buf => . {
            (0..page_count as usize * page_size as usize)
                .map(|_| -> u8 { seq.next_element().unwrap_or_default().unwrap_or(0) })
                .collect::<Vec<u8>>()
        }),
        (pages => . Page::collect_pages(page_size, page_count, page_buf.as_slice()))
    ]
);

#[derive(Deserialize, Default, Derivative)]
#[derivative(Debug)]
struct BranchEntryPointer {
    pub page: u32,
    pub offset: u16,
}

#[derive(Deserialize, Default, Derivative)]
#[derivative(Debug)]
struct LeafEntryPointer {
    pub common_prefix: u16,
    pub _pad: u16,
    pub offset: u16,
}

#[derive(Deserialize, Default, Derivative, Clone)]
#[derivative(Debug)]
pub struct KeyValueEntry {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub is_leaf: bool,
}

#[derive(Default, Derivative)]
#[derivative(Debug)]
pub struct Page {
    pub pointer: u32,
    pub entry_count: u16,
    pub kv_entries: Vec<KeyValueEntry>,
}

impl Page {
    pub fn collect_pages(page_size: u16, page_count: u32, bytes: &[u8]) -> Vec<Option<Page>> {
        (0..page_count)
            .map(|index| {
                let offset = page_size as usize * index as usize;
                if offset >= 44 {
                    Some(Page::new(&bytes[offset - 44..]))
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn new(data: &[u8]) -> Self {
        let pointer = bincode::deserialize(&data).unwrap();
        let entry_count = bincode::deserialize(&data[4..]).unwrap();
        let kv_entries = Page::parse_entries(entry_count, pointer == 0, data);
        Self {
            pointer,
            entry_count,
            kv_entries,
        }
    }

    fn parse_entries(entry_count: u16, is_leaf: bool, contents: &[u8]) -> Vec<KeyValueEntry> {
        let mut leaf_key = Vec::<u8>::new();
        (0..entry_count)
            .into_iter()
            .map(|index| {
                if is_leaf {
                    let leaf_ptr: LeafEntryPointer =
                        bincode::deserialize(&contents[6 + (index * 6) as usize..]).unwrap();
                    let key_length: u16 =
                        bincode::deserialize(&contents[leaf_ptr.offset as usize..]).unwrap();
                    let value_length: u16 = bincode::deserialize(
                        &contents[(leaf_ptr.offset + 2 + key_length) as usize..],
                    )
                    .unwrap();

                    let value_offset = (leaf_ptr.offset + 4 + key_length) as usize;
                    let value =
                        contents[value_offset..value_offset + value_length as usize].to_vec();

                    let key_offset = (leaf_ptr.offset + 2) as usize;
                    let key_no_prefix =
                        contents[key_offset..key_offset + key_length as usize].to_vec();
                    let key = if leaf_ptr.common_prefix == 0 {
                        [leaf_key.clone(), key_no_prefix].concat()
                    } else {
                        [
                            leaf_key[..leaf_ptr.common_prefix as usize].to_vec(),
                            key_no_prefix,
                        ]
                        .concat()
                    };
                    leaf_key = key.clone();

                    KeyValueEntry {
                        key,
                        value,
                        is_leaf: true,
                    }
                } else {
                    let branch_ptr: BranchEntryPointer =
                        bincode::deserialize(&contents[6 + (index * 6) as usize..]).unwrap();

                    let key_length: u16 =
                        bincode::deserialize(&contents[branch_ptr.offset as usize..]).unwrap();
                    let value_length: u16 = bincode::deserialize(
                        &contents[(branch_ptr.offset + 2 + key_length) as usize..],
                    )
                    .unwrap();

                    let value_offset = (branch_ptr.offset + 4 + key_length) as usize;
                    let value =
                        contents[value_offset..value_offset + value_length as usize].to_vec();
                    let key_offset = (branch_ptr.offset + 2) as usize;
                    let key = contents[key_offset..key_offset + key_length as usize].to_vec();
                    leaf_key = key.clone();

                    KeyValueEntry {
                        key,
                        value,
                        is_leaf: false,
                    }
                }
            })
            .collect()
    }
}
