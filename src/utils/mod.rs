pub mod visitors;
use derivative::Derivative;
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::fmt;

#[derive(Deserialize, Default, Derivative)]
#[derivative(Debug)]
pub struct VectorWithLength {
    pub len: u32,
    #[derivative(Debug = "ignore")]
    pub data: Vec<u8>,
}
