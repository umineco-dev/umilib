use alloc::string::String;
use core::fmt::Write;

use super::{Char, Definition, Function, Module, Parameter, Type};

/// The description of every C type and function exported by this build.
///
/// Bindings for other languages read it (as JSON from `umilib_ffi_manifest`)
/// to declare signatures, and `include/` is generated from it.
pub struct Manifest;

crate::ffi_functions! {
    /// Returns the version of the library as a static NUL-terminated string.
    pub unsafe extern "C" fn umilib_version() -> *const Char {
        concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
    }
}

impl Manifest {
    /// The root module, which mirrors the crate root.
    pub const ROOT: Module = Module {
        name: "umilib",
        definitions: &[],
        functions: FUNCTIONS,
        modules: &[
            super::MODULE,
            #[cfg(umilib_feature = "auth")]
            super::auth::MODULE,
            #[cfg(umilib_feature = "bytes")]
            super::bytes::MODULE,
            #[cfg(umilib_feature = "calendar")]
            super::calendar::MODULE,
            #[cfg(umilib_feature = "codec")]
            super::codec::MODULE,
            #[cfg(umilib_feature = "crypto")]
            super::crypto::MODULE,
            #[cfg(any(umilib_feature = "hash", umilib_feature = "crypto-hmac"))]
            super::hash::MODULE,
            #[cfg(umilib_feature = "math")]
            super::math::MODULE,
            #[cfg(umilib_feature = "platform")]
            super::platform::MODULE,
            #[cfg(umilib_feature = "protocol")]
            super::protocol::MODULE,
            #[cfg(umilib_feature = "runtime")]
            super::runtime::MODULE,
            #[cfg(umilib_feature = "secret")]
            super::secret::MODULE,
            #[cfg(umilib_feature = "service")]
            super::service::MODULE,
        ],
    };

    /// Serializes the tree rooted at `module` as JSON.
    pub fn json(module: &Module) -> String {
        let mut output = String::new();
        module.write_json(&mut output);
        output
    }

    /// Appends `text` to `output` as a JSON string literal.
    pub fn write_json_string(output: &mut String, text: &str) {
        output.push('"');
        for character in text.chars() {
            match character {
                '"' => output.push_str("\\\""),
                '\\' => output.push_str("\\\\"),
                '\n' => output.push_str("\\n"),
                '\r' => output.push_str("\\r"),
                '\t' => output.push_str("\\t"),
                character if (character as u32) < 0x20 => {
                    let _ = write!(output, "\\u{:04x}", character as u32);
                }
                character => output.push(character),
            }
        }
        output.push('"');
    }

    /// Joins documentation lines produced from `///` comments, removing the
    /// single leading space each line carries.
    pub fn documentation_lines(documentation: &str) -> impl Iterator<Item = &str> {
        documentation.lines().map(|line| line.strip_prefix(' ').unwrap_or(line))
    }

    /// Appends the documentation as a JSON string with leading spaces removed.
    pub fn write_json_documentation(output: &mut String, documentation: &str) {
        let mut text = String::new();
        for (index, line) in Manifest::documentation_lines(documentation).enumerate() {
            if index > 0 {
                text.push('\n');
            }
            text.push_str(line);
        }
        Manifest::write_json_string(output, &text);
    }
}

impl Type {
    /// Appends the type as a JSON object.
    pub fn write_json(&self, output: &mut String) {
        output.push_str("{\"kind\":");
        Manifest::write_json_string(output, self.kind());
        match self {
            Type::Pointer { target, mutable } => {
                let _ = write!(output, ",\"mutable\":{mutable},\"target\":");
                target.write_json(output);
            }
            Type::Array { element, length } => {
                let _ = write!(output, ",\"length\":{length},\"element\":");
                element.write_json(output);
            }
            Type::Named(name) => {
                output.push_str(",\"name\":");
                Manifest::write_json_string(output, name);
            }
            _ => {}
        }
        output.push('}');
    }
}

impl Parameter {
    /// Appends the parameter as a JSON object.
    pub fn write_json(&self, output: &mut String) {
        output.push_str("{\"name\":");
        Manifest::write_json_string(output, self.name);
        output.push_str(",\"type\":");
        self.value.write_json(output);
        output.push('}');
    }

    /// Appends `parameters` as a JSON array.
    pub fn write_json_list(output: &mut String, parameters: &[Parameter]) {
        output.push('[');
        for (index, parameter) in parameters.iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            parameter.write_json(output);
        }
        output.push(']');
    }
}

impl Function {
    /// Appends the function as a JSON object.
    pub fn write_json(&self, output: &mut String) {
        output.push_str("{\"name\":");
        Manifest::write_json_string(output, self.name);
        output.push_str(",\"documentation\":");
        Manifest::write_json_documentation(output, self.documentation);
        output.push_str(",\"parameters\":");
        Parameter::write_json_list(output, self.parameters);
        output.push_str(",\"returns\":");
        self.returns.write_json(output);
        output.push('}');
    }
}

impl Definition {
    /// Appends the definition as a JSON object.
    pub fn write_json(&self, output: &mut String) {
        match self {
            Definition::Opaque { name, documentation } => {
                output.push_str("{\"kind\":\"opaque\",\"name\":");
                Manifest::write_json_string(output, name);
                output.push_str(",\"documentation\":");
                Manifest::write_json_documentation(output, documentation);
            }
            Definition::Structure { name, documentation, fields } => {
                output.push_str("{\"kind\":\"structure\",\"name\":");
                Manifest::write_json_string(output, name);
                output.push_str(",\"documentation\":");
                Manifest::write_json_documentation(output, documentation);
                output.push_str(",\"fields\":");
                Parameter::write_json_list(output, fields);
            }
            Definition::Callback { name, documentation, parameters, returns } => {
                output.push_str("{\"kind\":\"callback\",\"name\":");
                Manifest::write_json_string(output, name);
                output.push_str(",\"documentation\":");
                Manifest::write_json_documentation(output, documentation);
                output.push_str(",\"parameters\":");
                Parameter::write_json_list(output, parameters);
                output.push_str(",\"returns\":");
                returns.write_json(output);
            }
        }
        output.push('}');
    }
}

impl Module {
    /// Appends the module and its descendants as a JSON object.
    pub fn write_json(&self, output: &mut String) {
        output.push_str("{\"name\":");
        Manifest::write_json_string(output, self.name);
        output.push_str(",\"definitions\":[");
        for (index, definition) in self.definitions.iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            definition.write_json(output);
        }
        output.push_str("],\"functions\":[");
        for (index, function) in self.functions.iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            function.write_json(output);
        }
        output.push_str("],\"modules\":[");
        for (index, module) in self.modules.iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            module.write_json(output);
        }
        output.push_str("]}");
    }
}
