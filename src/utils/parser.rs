use serde::de::SeqAccess;
#[macro_export]
macro_rules! gen_field_opt {
    ($field:ident, $seq:ident) => {
        let $field = $seq.next_element()?.unwrap();
    };
    (($field:ident<$ty:ty>), $seq:ident) => {
        let $field: $ty = $seq.next_element()?.unwrap();
    };
    ((? $field:ident), $seq:ident) => {
        let $field = match $seq.next_element() {
            Ok(ok) => ok,
            Err(_) => None,
        };
    };
    ((? $field:ident . $body:expr), $seq:ident) => {
        let mut $field: Option<_> = None;
        if $body {
            $field = Some($seq.next_element()?.unwrap());
        }
    };
    ((? $field:ident => $body:expr), $seq:ident) => {
        let $field = match $body {
            Ok(ok) => Some(ok),
            Err(_) => None,
        };
    };
    (($field:ident => $body:expr), $seq:ident) => {
        let $field = match $body {
            Ok(ok) => ok,
            Err(err) => panic!("{:?}", err),
        };
    };
    (($field:ident => . $body:expr), $seq:ident) => {
        let $field = $body;
    };
    ((mut $field:ident => . $body:expr), $seq:ident) => {
        let mut $field = $body;
    };
    ((($($fields:ident),*) => $body:expr), $seq:ident) => {
        let ($($fields,)*) = match $body {
            Ok(ok) => ok,
            Err(err) => panic!("{:?}", err),
        };
    };
}

#[macro_export]
macro_rules! gen_parser_body {
    (|$seq:ident|<$ret:ident>, [$($fields:ident),*], [$($tokens:tt),*]) => {
        fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut $seq = seq;
            $(
                gen_field_opt!($tokens, $seq);
            )*

            Ok($ret {
                $(
                    $fields,
                )*
            })
        }
    };
}

#[macro_export]
macro_rules! gen_parser {
    (parse <$ty:ty> visit $ident:ident, |$seq:ident|<$ret:ident>, [$($fields:ident),*], [$($tokens:tt),*]) => {
        struct $ident;
        impl<'de> Visitor<'de> for $ident {
            type Value = $ty;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("Unexpected data")
            }

            gen_parser_body!(
                |$seq|<$ret>,
                [$($fields),*],
                [$($tokens),*]
            );
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D>(deserializer: D) -> Result<$ty, D::Error>
            where
                D: Deserializer<'de>,
            {
                deserializer.deserialize_tuple(usize::MAX, $ident)
            }
        }
    };
}

pub fn consume_null_terminated_string<'de, A>(seq: &mut A) -> Result<String, A::Error>
where
    A: SeqAccess<'de>,
{
    Ok(String::from_utf8_lossy(consume_null_terminated(seq)?.as_slice()).to_string())
}

pub fn consume_null_terminated<'de, A>(seq: &mut A) -> Result<Vec<u8>, A::Error>
where
    A: SeqAccess<'de>,
{
    let mut vec: Vec<u8> = Vec::new();
    loop {
        let elem: u8 = seq.next_element()?.unwrap();
        if elem == '\x00' as u8 {
            break;
        }
        vec.push(elem);
    }
    Ok(vec)
}

pub fn consume_len_prefix_str<'de, A>(seq: &mut A) -> Result<(u8, String), A::Error>
where
    A: SeqAccess<'de>,
{
    let len = seq.next_element::<u8>()?.unwrap();
    let str = String::from_utf8_lossy(
        (0..len)
            .map(|_| seq.next_element::<u8>().unwrap().unwrap())
            .collect::<Vec<u8>>()
            .as_slice(),
    )
    .to_string();
    Ok((len, str))
}

pub fn parse_len_prefix_str_vec(vec: &Vec<u8>) -> Vec<String> {
    let mut pos = 0;
    let mut fields: Vec<String> = Vec::new();
    while pos < vec.len() {
        let len = vec[pos];
        fields.push(String::from_utf8_lossy(&vec[pos + 1..pos + len as usize]).to_string());
        pos += len as usize;
    }
    fields
}
