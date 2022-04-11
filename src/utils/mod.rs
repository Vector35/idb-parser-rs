pub mod consumer;
pub mod visitors;
use derivative::Derivative;
use serde::Deserialize;

#[derive(Deserialize, Default, Derivative)]
#[derivative(Debug)]
pub struct LengthPrefixVector {
    pub len: u32,
    #[derivative(Debug = "ignore")]
    pub data: Vec<u8>,
}

#[derive(Default, Debug)]
pub struct LengthPrefixString {
    pub len: u8,
    pub data: String,
}
