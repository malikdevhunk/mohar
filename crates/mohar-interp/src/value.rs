//! Runtime values. Labels are not stored: the checker already rejected
//! illegal flows. Crypto keys are opaque byte strings produced by `mohar-std`.

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cap {
    Console,
    FsRead(String),
    FsWrite(String),
    Net(String),
    Tool(String),
    Model,
    Rand,
    Clock,
    Declassify,
    Endorse,
}

#[derive(Clone, Debug)]
pub enum Value {
    Unit,
    Bool(bool),
    Int(i128),
    Text(String),
    Bytes(Vec<u8>),
    Array(Vec<Value>),
    List(Vec<Value>),
    Option(Option<Box<Value>>),
    Result(std::result::Result<Box<Value>, Box<Value>>),
    Tuple(Vec<Value>),
    Struct {
        name: String,
        fields: Vec<(String, Value)>,
    },
    Enum {
        name: String,
        variant: String,
        payload: Vec<Value>,
    },
    Cap(Cap),
    Kem(String),
    KemPk(Vec<u8>),
    KemSk(Vec<u8>),
    Sig(String),
    SigPk(Vec<u8>),
    SigSk(Vec<u8>),
    Email(String),
    Url(String),
    Id(String),
    Func(String),
}

impl Value {
    pub fn type_name(&self) -> String {
        match self {
            Self::Unit => "Unit".into(),
            Self::Bool(_) => "bool".into(),
            Self::Int(_) => "int".into(),
            Self::Text(_) => "Text".into(),
            Self::Bytes(_) => "Bytes".into(),
            Self::Array(xs) => format!("array[{}]", xs.len()),
            Self::List(_) => "List".into(),
            Self::Option(_) => "Option".into(),
            Self::Result(_) => "Result".into(),
            Self::Tuple(_) => "tuple".into(),
            Self::Struct { name, .. } => name.clone(),
            Self::Enum { name, variant, .. } => format!("{name}::{variant}"),
            Self::Cap(c) => format!("{c:?}"),
            Self::Kem(a) => format!("Kem({a})"),
            Self::KemPk(_) => "KemPublicKey".into(),
            Self::KemSk(_) => "KemSecretKey".into(),
            Self::Sig(a) => format!("Sig({a})"),
            Self::SigPk(_) => "SigPublicKey".into(),
            Self::SigSk(_) => "SigSecretKey".into(),
            Self::Email(_) => "Email".into(),
            Self::Url(_) => "Url".into(),
            Self::Id(_) => "Id".into(),
            Self::Func(n) => format!("fn {n}"),
        }
    }

    pub fn display(&self) -> String {
        match self {
            Self::Unit => "()".into(),
            Self::Bool(b) => b.to_string(),
            Self::Int(n) => n.to_string(),
            Self::Text(s) => s.clone(),
            Self::Bytes(b) => to_hex(b),
            Self::Array(xs) | Self::List(xs) => {
                let parts: Vec<_> = xs.iter().map(Value::display).collect();
                format!("[{}]", parts.join(", "))
            }
            Self::Option(None) => "None".into(),
            Self::Option(Some(v)) => format!("Some({})", v.display()),
            Self::Result(Ok(v)) => format!("Ok({})", v.display()),
            Self::Result(Err(v)) => format!("Err({})", v.display()),
            Self::Tuple(xs) => {
                let parts: Vec<_> = xs.iter().map(Value::display).collect();
                format!("({})", parts.join(", "))
            }
            Self::Email(s) | Self::Url(s) | Self::Id(s) => s.clone(),
            other => other.type_name(),
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(s) | Self::Email(s) | Self::Url(s) | Self::Id(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<Vec<u8>> {
        match self {
            Self::Bytes(b) => Some(b.clone()),
            Self::Text(s) => Some(s.as_bytes().to_vec()),
            Self::Array(xs) => {
                let mut out = Vec::new();
                for x in xs {
                    let Self::Int(n) = x else { return None };
                    if !(0..=255).contains(n) {
                        return None;
                    }
                    out.push(*n as u8);
                }
                Some(out)
            }
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i128> {
        match self {
            Self::Int(n) => Some(*n),
            _ => None,
        }
    }
}

pub fn bytes_value(bytes: Vec<u8>) -> Value {
    Value::Bytes(bytes)
}

pub fn array_u8(bytes: &[u8]) -> Value {
    Value::Array(bytes.iter().map(|b| Value::Int(*b as i128)).collect())
}

pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

/// Rough size used by the memory limit. This is an accounting upper bound,
/// not a measurement of the allocator.
pub fn weight(v: &Value) -> u64 {
    match v {
        Value::Text(s) => s.len() as u64,
        Value::Bytes(b) => b.len() as u64,
        Value::Array(xs) | Value::List(xs) | Value::Tuple(xs) => {
            8 + xs.iter().map(weight).sum::<u64>()
        }
        Value::Option(Some(x)) | Value::Result(Ok(x)) | Value::Result(Err(x)) => weight(x),
        Value::Struct { fields, .. } => fields.iter().map(|(_, v)| weight(v)).sum(),
        Value::Enum { payload, .. } => payload.iter().map(weight).sum(),
        Value::KemPk(b) | Value::KemSk(b) | Value::SigPk(b) | Value::SigSk(b) => b.len() as u64,
        _ => 8,
    }
}
