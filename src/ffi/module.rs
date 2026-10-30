use alloc::vec::Vec;

use super::Type;

/// A named and typed value: a function parameter, a structure field or a callback parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parameter {
    pub name: &'static str,
    pub value: Type,
}

/// An exported C function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Function {
    pub name: &'static str,
    pub documentation: &'static str,
    pub parameters: &'static [Parameter],
    pub returns: Type,
}

impl Function {
    /// A function without name, parameters or result, used to fill arrays.
    pub const EMPTY: Function = Function { name: "", documentation: "", parameters: &[], returns: Type::Void };

    /// Concatenates lists of functions. `N` must be the total length.
    pub const fn concat<const N: usize>(lists: &[&[Function]]) -> [Function; N] {
        let mut result = [Function::EMPTY; N];
        let mut index = 0;
        let mut list = 0;
        while list < lists.len() {
            let mut item = 0;
            while item < lists[list].len() {
                result[index] = lists[list][item];
                index += 1;
                item += 1;
            }
            list += 1;
        }
        assert!(index == N, "N must equal the total number of functions");
        result
    }
}

/// A C type declared by a module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Definition {
    /// A type only handled through pointers.
    Opaque { name: &'static str, documentation: &'static str },
    /// A structure passed by value or read through a pointer.
    Structure { name: &'static str, documentation: &'static str, fields: &'static [Parameter] },
    /// A function pointer type for callbacks from umilib into the caller.
    Callback { name: &'static str, documentation: &'static str, parameters: &'static [Parameter], returns: Type },
}

impl Definition {
    /// The C name of the declared type.
    pub const fn name(&self) -> &'static str {
        match self {
            Definition::Opaque { name, .. }
            | Definition::Structure { name, .. }
            | Definition::Callback { name, .. } => name,
        }
    }
}

/// A node of the FFI manifest, mirroring one module of the crate.
///
/// The C name of every item in a module starts with the module path joined by
/// `_`, prefixed with `umilib`: functions of `bytes` are named
/// `umilib_bytes_reader_new` and so on, and types keep their Rust name after
/// the prefix, as in `umilib_bytes_Reader`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Module {
    pub name: &'static str,
    pub definitions: &'static [Definition],
    pub functions: &'static [Function],
    pub modules: &'static [Module],
}

impl Module {
    /// Calls `visitor` with the path and each module of the tree rooted at `self`, parents first.
    /// The path of the root is empty.
    pub fn visit<'a>(&'a self, mut visitor: impl FnMut(&[&'a str], &'a Module)) {
        // Each stack entry is a module and the index of its next child to visit.
        let mut stack: Vec<(&'a Module, usize)> = Vec::new();
        let mut path: Vec<&'a str> = Vec::new();
        visitor(&path, self);
        stack.push((self, 0));
        while let Some((module, next)) = stack.last_mut() {
            let child = module.modules.get(*next);
            *next += 1;
            match child {
                Some(child) => {
                    path.push(child.name);
                    visitor(&path, child);
                    stack.push((child, 0));
                }
                None => {
                    stack.pop();
                    path.pop();
                }
            }
        }
    }
}
