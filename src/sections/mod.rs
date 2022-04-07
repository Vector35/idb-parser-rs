pub mod id0;
pub mod id1;
pub mod id2;
pub mod nam;
pub mod seg;
pub mod til;

use derivative::Derivative;
use serde::Deserialize;

#[derive(Default, Deserialize, Debug)]
pub struct IDBSectionHeader {
    pub compression_method: u8,
    pub length: u64,
}

#[derive(Deserialize, Default, Derivative)]
#[derivative(Debug)]
pub struct IDBSection {
    #[derivative(Debug = "ignore")]
    #[serde(skip)]
    pub section_buffer: Vec<u8>,
    pub header: IDBSectionHeader,
}
