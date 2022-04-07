use crate::sections::IDBSectionHeader;
use derivative::Derivative;
use serde::Deserialize;
use std::default::Default;

#[derive(Deserialize, Default, Derivative)]
#[derivative(Debug)]
pub struct ID1Section {
    #[derivative(Debug = "ignore")]
    #[serde(skip)]
    pub section_buffer: Vec<u8>,
    pub header: IDBSectionHeader,
}
