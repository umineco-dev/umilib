use core::ffi::c_void;

/// The C type of a value crossing the FFI boundary, as recorded in the manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Type {
    /// `void`; only valid as a return type or a pointer target.
    Void,
    Bool,
    /// `char`, used for NUL-terminated static strings.
    Char,
    U8,
    U16,
    U32,
    U64,
    USize,
    I8,
    I16,
    I32,
    I64,
    ISize,
    F32,
    F64,
    Pointer {
        target: &'static Type,
        mutable: bool,
    },
    /// A fixed number of elements, only as a field of a structure.
    Array {
        element: &'static Type,
        length: usize,
    },
    /// A type declared by a [`Definition`](super::Definition), referred to by its C name.
    Named(&'static str),
}

impl Type {
    /// The type name used in a JSON manifest.
    pub const fn kind(&self) -> &'static str {
        match self {
            Type::Void => "void",
            Type::Bool => "bool",
            Type::Char => "char",
            Type::U8 => "u8",
            Type::U16 => "u16",
            Type::U32 => "u32",
            Type::U64 => "u64",
            Type::USize => "usize",
            Type::I8 => "i8",
            Type::I16 => "i16",
            Type::I32 => "i32",
            Type::I64 => "i64",
            Type::ISize => "isize",
            Type::F32 => "f32",
            Type::F64 => "f64",
            Type::Pointer { .. } => "pointer",
            Type::Array { .. } => "array",
            Type::Named(_) => "named",
        }
    }
}

/// A Rust type that has a C equivalent.
pub trait Value {
    /// The C type of `Self`.
    const TYPE: Type;
}

macro_rules! value {
    ($($rust:ty => $type:expr),* $(,)?) => {
        $(
            impl Value for $rust {
                const TYPE: Type = $type;
            }
        )*
    };
}

value! {
    () => Type::Void,
    c_void => Type::Void,
    bool => Type::Bool,
    u8 => Type::U8,
    u16 => Type::U16,
    u32 => Type::U32,
    u64 => Type::U64,
    usize => Type::USize,
    i8 => Type::I8,
    i16 => Type::I16,
    i32 => Type::I32,
    i64 => Type::I64,
    isize => Type::ISize,
    f32 => Type::F32,
    f64 => Type::F64,
}

impl<T: Value> Value for *const T {
    const TYPE: Type = Type::Pointer { target: &T::TYPE, mutable: false };
}

impl<T: Value> Value for *mut T {
    const TYPE: Type = Type::Pointer { target: &T::TYPE, mutable: true };
}

impl<T: Value, const N: usize> Value for [T; N] {
    const TYPE: Type = Type::Array { element: &T::TYPE, length: N };
}
