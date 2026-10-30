use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

use super::{Definition, Function, Manifest, Module, Parameter, Type};

/// A C header generated from the manifest.
///
/// The root module becomes `umilib.h`, which includes every other header; a
/// module at path `a/b` becomes `umilib/a/b.h`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CHeader {
    /// The path relative to the include directory, with `/` separators.
    pub path: String,
    pub text: String,
}

impl CHeader {
    /// Generates one header per module of the tree rooted at `root`.
    pub fn generate(root: &Module) -> Vec<CHeader> {
        // The header that declares each type, so that a header can include the
        // headers of the types it uses from other modules.
        let mut owners: BTreeMap<&str, String> = BTreeMap::new();
        root.visit(|path, module| {
            for definition in module.definitions {
                owners.insert(definition.name(), CHeader::path_of(path));
            }
        });
        let mut headers = Vec::new();
        let mut descendants = Vec::new();
        root.visit(|path, module| {
            if !path.is_empty() {
                descendants.push(CHeader::path_of(path));
            }
            headers.push(CHeader::render(path, module, &owners));
        });
        // The root header also includes every descendant.
        let root_header = &mut headers[0];
        root_header.text = CHeader::render_root(&root_header.text, &descendants);
        headers
    }

    /// The header path of the module at `path`.
    pub fn path_of(path: &[&str]) -> String {
        if path.is_empty() { String::from("umilib.h") } else { format!("umilib/{}.h", path.join("/")) }
    }

    /// The C spelling of `value`.
    pub fn type_name(value: &Type) -> String {
        match value {
            Type::Void => String::from("void"),
            Type::Bool => String::from("bool"),
            Type::Char => String::from("char"),
            Type::U8 => String::from("uint8_t"),
            Type::U16 => String::from("uint16_t"),
            Type::U32 => String::from("uint32_t"),
            Type::U64 => String::from("uint64_t"),
            Type::USize => String::from("size_t"),
            Type::I8 => String::from("int8_t"),
            Type::I16 => String::from("int16_t"),
            Type::I32 => String::from("int32_t"),
            Type::I64 => String::from("int64_t"),
            Type::ISize => String::from("ptrdiff_t"),
            Type::F32 => String::from("float"),
            Type::F64 => String::from("double"),
            Type::Named(name) => String::from(*name),
            Type::Array { element, length } => format!("{}[{length}]", CHeader::type_name(element)),
            Type::Pointer { target, mutable } => match target {
                Type::Pointer { .. } => {
                    format!("{}{}*", CHeader::type_name(target), if *mutable { "" } else { " const" })
                }
                _ => format!("{}{}*", if *mutable { "" } else { "const " }, CHeader::type_name(target)),
            },
        }
    }

    /// The C declaration of `name` with the type `value`: `uint8_t salt[16]`
    /// for an array, `uint32_t depth` otherwise.
    pub fn declaration(value: &Type, name: &str) -> String {
        match value {
            Type::Array { element, length } => format!("{} {name}[{length}]", CHeader::type_name(element)),
            _ => format!("{} {name}", CHeader::type_name(value)),
        }
    }

    /// The C parameter list of `parameters`.
    pub fn parameter_list(parameters: &[Parameter]) -> String {
        if parameters.is_empty() {
            return String::from("void");
        }
        let parameters: Vec<String> =
            parameters.iter().map(|parameter| CHeader::declaration(&parameter.value, parameter.name)).collect();
        parameters.join(", ")
    }

    /// Appends `documentation` as a C comment indented by `indent`.
    pub fn write_documentation(output: &mut String, documentation: &str, indent: &str) {
        let lines: Vec<&str> = Manifest::documentation_lines(documentation).collect();
        if lines.is_empty() {
            return;
        }
        let _ = writeln!(output, "{indent}/**");
        for line in lines {
            if line.is_empty() {
                let _ = writeln!(output, "{indent} *");
            } else {
                // Neither `/*` nor `*/` may appear inside a C comment.
                let _ = writeln!(output, "{indent} * {}", line.replace("*/", "* /").replace("/*", "/ *"));
            }
        }
        let _ = writeln!(output, "{indent} */");
    }

    /// The include guard macro of the header at `path`.
    pub fn guard_of(path: &str) -> String {
        path.chars()
            .map(|character| if character.is_ascii_alphanumeric() { character.to_ascii_uppercase() } else { '_' })
            .collect()
    }

    /// The C names of the declared types `value` refers to.
    pub fn named_types<'a>(value: &'a Type, names: &mut BTreeSet<&'a str>) {
        match value {
            Type::Named(name) => {
                names.insert(name);
            }
            Type::Pointer { target, .. } => CHeader::named_types(target, names),
            Type::Array { element, .. } => CHeader::named_types(element, names),
            _ => {}
        }
    }

    /// The headers, other than its own, declaring the types `module` uses.
    pub fn dependencies(path: &str, module: &Module, owners: &BTreeMap<&str, String>) -> BTreeSet<String> {
        let mut names = BTreeSet::new();
        for definition in module.definitions {
            match definition {
                Definition::Structure { fields, .. } => {
                    fields.iter().for_each(|field| CHeader::named_types(&field.value, &mut names))
                }
                Definition::Callback { parameters, returns, .. } => {
                    parameters.iter().for_each(|parameter| CHeader::named_types(&parameter.value, &mut names));
                    CHeader::named_types(returns, &mut names);
                }
                Definition::Opaque { .. } => {}
            }
        }
        for function in module.functions {
            function.parameters.iter().for_each(|parameter| CHeader::named_types(&parameter.value, &mut names));
            CHeader::named_types(&function.returns, &mut names);
        }
        names.iter().filter_map(|name| owners.get(name)).filter(|owner| owner.as_str() != path).cloned().collect()
    }

    /// Renders the header of one module, without the includes of descendants.
    /// `owners` maps every type name to the header that declares it.
    pub fn render(path: &[&str], module: &Module, owners: &BTreeMap<&str, String>) -> CHeader {
        let header_path = CHeader::path_of(path);
        let guard = CHeader::guard_of(&header_path);
        let mut text = String::new();
        let _ = writeln!(text, "/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */");
        let _ = writeln!(text, "#ifndef {guard}");
        let _ = writeln!(text, "#define {guard}");
        let _ = writeln!(text);
        let _ = writeln!(text, "#include <stdbool.h>");
        let _ = writeln!(text, "#include <stddef.h>");
        let _ = writeln!(text, "#include <stdint.h>");
        let mut includes = CHeader::dependencies(&header_path, module, owners);
        if path != ["ffi"] && !path.is_empty() {
            // Every module uses the status and buffer types.
            includes.insert(CHeader::path_of(&["ffi"]));
        }
        if !includes.is_empty() {
            let _ = writeln!(text);
            for include in &includes {
                let _ = writeln!(text, "#include \"{include}\"");
            }
        }
        let _ = writeln!(text);
        let _ = writeln!(text, "#ifdef __cplusplus");
        let _ = writeln!(text, "extern \"C\" {{");
        let _ = writeln!(text, "#endif");
        for definition in module.definitions {
            let _ = writeln!(text);
            CHeader::write_definition(&mut text, definition);
        }
        for function in module.functions {
            let _ = writeln!(text);
            CHeader::write_function(&mut text, function);
        }
        let _ = writeln!(text);
        let _ = writeln!(text, "#ifdef __cplusplus");
        let _ = writeln!(text, "}}");
        let _ = writeln!(text, "#endif");
        let _ = writeln!(text);
        let _ = writeln!(text, "#endif");
        CHeader { path: header_path, text }
    }

    /// Inserts the includes of every descendant header into the rendered root header.
    pub fn render_root(text: &str, descendants: &[String]) -> String {
        let mut includes = String::new();
        for descendant in descendants {
            let _ = writeln!(includes, "#include \"{descendant}\"");
        }
        let marker = "#include <stdint.h>\n";
        match text.find(marker) {
            Some(index) => {
                let split = index + marker.len();
                format!("{}\n{}{}", &text[..split], includes, &text[split..])
            }
            None => String::from(text),
        }
    }

    /// Appends the C declaration of `definition`.
    pub fn write_definition(output: &mut String, definition: &Definition) {
        match definition {
            Definition::Opaque { name, documentation } => {
                CHeader::write_documentation(output, documentation, "");
                let _ = writeln!(output, "typedef struct {name} {name};");
            }
            Definition::Structure { name, documentation, fields } => {
                CHeader::write_documentation(output, documentation, "");
                let _ = writeln!(output, "typedef struct {name} {{");
                for field in *fields {
                    let _ = writeln!(output, "    {};", CHeader::declaration(&field.value, field.name));
                }
                let _ = writeln!(output, "}} {name};");
            }
            Definition::Callback { name, documentation, parameters, returns } => {
                CHeader::write_documentation(output, documentation, "");
                let _ = writeln!(
                    output,
                    "typedef {} (*{name})({});",
                    CHeader::type_name(returns),
                    CHeader::parameter_list(parameters)
                );
            }
        }
    }

    /// Appends the C prototype of `function`.
    pub fn write_function(output: &mut String, function: &Function) {
        CHeader::write_documentation(output, function.documentation, "");
        let _ = writeln!(
            output,
            "{} {}({});",
            CHeader::type_name(&function.returns),
            function.name,
            CHeader::parameter_list(function.parameters)
        );
    }
}
