//! Brownfield adapter for native Pinocchio programs.
//! Parses the entrypoint dispatch, handler accounts, instruction data structs,
//! and error enum to emit a starter `.qedspec`.

use anyhow::{Context, Result};
use regex::Regex;
use std::path::{Path, PathBuf};

pub fn adapt(program_root: &Path) -> Result<String> {
    let program_name = read_crate_name(program_root).unwrap_or_else(|| {
        program_root
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("program")
            .to_string()
    });

    let dispatch = parse_dispatch(program_root).with_context(|| {
        format!(
            "could not find a `match instruction_data.split_first()` dispatch in \
             {}/src/entrypoint.rs or {}/src/lib.rs. Is this a Pinocchio program?",
            program_root.display(),
            program_root.display()
        )
    })?;

    let mut instructions: Vec<PinocchioInstruction> = Vec::new();
    for (disc, fn_name) in &dispatch {
        let handler_name = strip_process_prefix(fn_name);
        let (accounts, args) = parse_handler(program_root, fn_name);
        instructions.push(PinocchioInstruction {
            name: handler_name,
            discriminator: *disc,
            accounts,
            args,
        });
    }

    let error_variants = discover_error_enum(program_root);
    let rendered = render_spec(&program_name, &instructions, error_variants.as_deref());

    crate::chumsky_adapter::parse_str(&rendered).context(
        "Generated .qedspec failed to parse: bug in `qedgen adapt` \
         for Pinocchio. Please report at https://github.com/qedgen/solana-skills/issues",
    )?;

    Ok(rendered)
}

pub fn adapt_to_file(program_root: &Path, output_path: &Path) -> Result<()> {
    let rendered = adapt(program_root)?;
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating output directory {}", parent.display()))?;
    }
    std::fs::write(output_path, &rendered)
        .with_context(|| format!("writing {}", output_path.display()))?;
    eprintln!("Wrote {} ({} bytes)", output_path.display(), rendered.len());
    Ok(())
}

/// Returns `true` when `pinocchio` appears as a dependency key in `Cargo.toml`.
pub fn is_pinocchio_project(program_root: &Path) -> bool {
    let Ok(src) = std::fs::read_to_string(program_root.join("Cargo.toml")) else {
        return false;
    };
    if !src.contains("pinocchio") {
        return false;
    }
    let Ok(doc) = src.parse::<toml::Value>() else {
        return src.contains("pinocchio");
    };
    doc.get("dependencies")
        .and_then(|d| d.as_table())
        .map(|t| t.contains_key("pinocchio"))
        .unwrap_or(false)
}

struct PinocchioInstruction {
    name: String,
    discriminator: u8,
    accounts: Vec<String>,
    args: Vec<(String, String)>,
}

fn read_crate_name(program_root: &Path) -> Option<String> {
    let src = std::fs::read_to_string(program_root.join("Cargo.toml")).ok()?;
    let doc: toml::Value = src.parse().ok()?;
    doc.get("package")?
        .get("name")?
        .as_str()
        .map(|s| s.replace('-', "_"))
}

fn dispatch_source(program_root: &Path) -> Option<(PathBuf, String)> {
    for candidate in &["src/entrypoint.rs", "src/lib.rs"] {
        let path = program_root.join(candidate);
        if let Ok(src) = std::fs::read_to_string(&path) {
            if src.contains("split_first") {
                return Some((path, src));
            }
        }
    }
    for candidate in &["src/entrypoint.rs", "src/lib.rs"] {
        let path = program_root.join(candidate);
        if let Ok(src) = std::fs::read_to_string(&path) {
            if !src.is_empty() {
                return Some((path, src));
            }
        }
    }
    None
}

fn parse_dispatch(program_root: &Path) -> Result<Vec<(u8, String)>> {
    let (_, src) = dispatch_source(program_root)
        .ok_or_else(|| anyhow::anyhow!("dispatch source not found"))?;

    let re = Regex::new(r"Some\s*\(\s*\(\s*(\d+)\s*,[^)]*\)\s*\)\s*=>\s*(\w+)\s*\(").unwrap();
    let mut entries: Vec<(u8, String)> = Vec::new();
    for cap in re.captures_iter(&src) {
        let disc: u8 = cap[1].parse().unwrap_or(u8::MAX);
        let fn_name = cap[2].to_string();
        if fn_name == "Err" || fn_name == "Ok" {
            continue;
        }
        entries.push((disc, fn_name));
    }

    if entries.is_empty() {
        anyhow::bail!("no `Some((N, ...)) => fn_name(` arms found in dispatch");
    }

    entries.sort_by_key(|(d, _)| *d);
    entries.dedup_by_key(|(d, _)| *d);
    Ok(entries)
}

fn parse_handler(program_root: &Path, fn_name: &str) -> (Vec<String>, Vec<(String, String)>) {
    let handler_name = strip_process_prefix(fn_name);
    let candidates = [
        program_root.join(format!("src/instructions/{}.rs", handler_name)),
        program_root.join(format!("src/instructions/{fn_name}.rs")),
        program_root.join(format!("src/{handler_name}.rs")),
    ];
    for path in &candidates {
        if let Ok(src) = std::fs::read_to_string(path) {
            return (extract_accounts(&src), extract_instruction_data_fields(&src));
        }
    }
    (Vec::new(), Vec::new())
}

fn extract_accounts(src: &str) -> Vec<String> {
    let bracket_re = Regex::new(r"let\s*\[([^\]]*)\]\s*=\s*accounts").unwrap();
    let Some(cap) = bracket_re.captures(src) else {
        return Vec::new();
    };
    let ident_re = Regex::new(r"\b([a-z][a-z0-9_]*)\b").unwrap();
    let skip = ["remaining", "rest", "accounts", "program", "id"];
    ident_re
        .captures_iter(&cap[1])
        .map(|c| c[1].to_string())
        .filter(|name| !name.starts_with('_') && !skip.contains(&name.as_str()) && name != "mut")
        .collect()
}

fn map_type(rust_ty: &str) -> &str {
    match rust_ty.trim() {
        "u8" => "U8",
        "u16" => "U16",
        "u32" => "U32",
        "u64" => "U64",
        "u128" => "U128",
        "i8" => "I8",
        "i16" => "I16",
        "i32" => "I32",
        "i64" => "I64",
        "i128" => "I128",
        "bool" => "Bool",
        _ => "U64",
    }
}

fn extract_instruction_data_fields(src: &str) -> Vec<(String, String)> {
    let Some(repr_pos) = src.find("#[repr(C") else {
        return Vec::new();
    };
    let tail = &src[repr_pos..];
    let Some(open) = tail.find('{') else {
        return Vec::new();
    };
    let body_start = repr_pos + open + 1;
    let mut depth = 1usize;
    let mut body_end = body_start;
    for (i, ch) in src[body_start..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    body_end = body_start + i;
                    break;
                }
            }
            _ => {}
        }
    }
    if body_end == body_start {
        return Vec::new();
    }
    let field_re =
        Regex::new(r"pub\s+([a-z][a-z0-9_]*)\s*:\s*([A-Za-z][A-Za-z0-9_<>\[\];]*)").unwrap();
    field_re
        .captures_iter(&src[body_start..body_end])
        .filter_map(|cap| {
            let name = cap[1].to_string();
            if name.starts_with('_') {
                return None;
            }
            Some((name, map_type(cap[2].trim()).to_string()))
        })
        .collect()
}

fn discover_error_enum(program_root: &Path) -> Option<Vec<String>> {
    let candidates: Vec<PathBuf> = {
        let error_rs = program_root.join("src/error.rs");
        if error_rs.exists() {
            vec![error_rs]
        } else {
            walk_rs_files(program_root)
        }
    };
    let enum_re = Regex::new(r"(?m)pub\s+enum\s+\w*[Ee]rror\s*\{([^}]*)\}").unwrap();
    let variant_re = Regex::new(r"\b([A-Z][A-Za-z0-9]*)\b").unwrap();
    for path in &candidates {
        let Ok(src) = std::fs::read_to_string(path) else {
            continue;
        };
        if let Some(cap) = enum_re.captures(&src) {
            let variants: Vec<String> = variant_re
                .captures_iter(&cap[1])
                .map(|c| c[1].to_string())
                .filter(|v| !v.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()))
                .collect();
            if !variants.is_empty() {
                return Some(variants);
            }
        }
    }
    None
}

fn walk_rs_files(program_root: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(program_root.join("src")) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = Vec::new();
    collect_rs_files(entries, &mut out);
    out
}

fn collect_rs_files(entries: std::fs::ReadDir, out: &mut Vec<PathBuf>) {
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Ok(sub) = std::fs::read_dir(&path) {
                collect_rs_files(sub, out);
            }
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn strip_process_prefix(fn_name: &str) -> String {
    fn_name.strip_prefix("process_").unwrap_or(fn_name).to_string()
}

fn render_spec(
    program_name: &str,
    instructions: &[PinocchioInstruction],
    error_variants: Option<&[String]>,
) -> String {
    let mut s = String::new();
    s.push_str("// Generated by `qedgen adapt` (Pinocchio). Fill in the TODOs to make this verifiable.\n\n");
    s.push_str(&format!("spec {}\n\n", to_pascal_case(program_name)));
    s.push_str("// TODO: replace with the actual lifecycle of your program.\n");
    s.push_str("type State\n  | Init\n  | Active\n\n");
    match error_variants {
        Some(variants) if !variants.is_empty() => {
            s.push_str("// Error variants discovered in src/error.rs.\n");
            s.push_str("type Error\n");
            for v in variants {
                s.push_str(&format!("  | {}\n", v));
            }
            s.push('\n');
        }
        _ => {
            s.push_str("// TODO: list domain errors raised by the handlers below.\n");
            s.push_str("type Error\n  | InvalidArgument\n\n");
        }
    }
    for ix in instructions {
        render_instruction(&mut s, ix);
        s.push('\n');
    }
    s
}

fn render_instruction(s: &mut String, ix: &PinocchioInstruction) {
    s.push_str(&format!(
        "/// `{}` (discriminator {}): native Pinocchio handler\n/// source: src/instructions/{}.rs\n",
        ix.name, ix.discriminator, ix.name
    ));
    s.push_str(&format!("handler {}", ix.name));
    for (arg, ty) in &ix.args {
        s.push_str(&format!(" ({} : {})", arg, ty));
    }
    s.push_str(" : State.Init -> State.Init {\n");
    if !ix.accounts.is_empty() {
        s.push_str(&format!("  // accounts: {}\n", ix.accounts.join(", ")));
    }
    s.push_str("  // TODO: accounts { ... }\n");
    s.push_str("  // TODO: auth <signer>\n");
    s.push_str("  // TODO: requires\n");
    s.push_str("  // TODO: effect { ... }\n");
    s.push_str("}\n");
}

fn to_pascal_case(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut upper_next = true;
    for ch in s.chars() {
        if ch == '_' {
            upper_next = true;
        } else if upper_next {
            out.push(ch.to_ascii_uppercase());
            upper_next = false;
        } else {
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_files(tmp: &tempfile::TempDir, files: &[(&str, &str)]) -> PathBuf {
        let root = tmp.path().to_path_buf();
        for (rel, contents) in files {
            let path = root.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, contents).unwrap();
        }
        root
    }

    #[test]
    fn is_pinocchio_project_detects_dep() {
        let tmp = tempfile::tempdir().unwrap();
        let root = write_files(&tmp, &[("Cargo.toml", "[package]\nname=\"p\"\n[dependencies]\npinocchio=\"0.7\"\n")]);
        assert!(is_pinocchio_project(&root));
    }

    #[test]
    fn is_pinocchio_project_rejects_anchor() {
        let tmp = tempfile::tempdir().unwrap();
        let root = write_files(&tmp, &[("Cargo.toml", "[package]\nname=\"p\"\n[dependencies]\nanchor-lang=\"0.30\"\n")]);
        assert!(!is_pinocchio_project(&root));
    }

    #[test]
    fn strip_process_prefix_works() {
        assert_eq!(strip_process_prefix("process_create_market"), "create_market");
        assert_eq!(strip_process_prefix("create_market"), "create_market");
    }

    #[test]
    fn extract_accounts_single_line() {
        let src = "let [authority, market, bid, ask, _remaining @ ..] = accounts else { return Err(e); };";
        assert_eq!(extract_accounts(src), vec!["authority", "market", "bid", "ask"]);
    }

    #[test]
    fn extract_accounts_multiline() {
        let src = "let [\n    authority,\n    market,\n    bid,\n    _remaining @ ..,\n] = accounts else {};";
        assert_eq!(extract_accounts(src), vec!["authority", "market", "bid"]);
    }

    #[test]
    fn extract_instruction_data_fields_basic() {
        let src = "#[repr(C, packed)]\npub struct Foo {\n    pub offset: i64,\n    pub size: u64,\n}\n";
        let got = extract_instruction_data_fields(src);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], ("offset".to_string(), "I64".to_string()));
        assert_eq!(got[1], ("size".to_string(), "U64".to_string()));
    }

    #[test]
    fn extract_instruction_data_skips_padding() {
        let src = "#[repr(C, packed)]\npub struct Foo {\n    pub amount: u64,\n    pub _padding: [u8; 6],\n}\n";
        let got = extract_instruction_data_fields(src);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, "amount");
    }

    #[test]
    fn parse_dispatch_basic() {
        let tmp = tempfile::tempdir().unwrap();
        let src = "fn process_instruction(...) {\n    match instruction_data.split_first() {\n        Some((0, rest)) => process_create_market(p, a, rest),\n        Some((1, rest)) => process_place_order(p, a, rest),\n        _ => Err(e),\n    }\n}";
        let root = write_files(&tmp, &[("src/entrypoint.rs", src)]);
        let dispatch = parse_dispatch(&root).unwrap();
        assert_eq!(dispatch.len(), 2);
        assert_eq!(dispatch[0], (0, "process_create_market".to_string()));
        assert_eq!(dispatch[1], (1, "process_place_order".to_string()));
    }

    #[test]
    fn discover_error_enum_finds_variants() {
        let tmp = tempfile::tempdir().unwrap();
        let root = write_files(&tmp, &[("src/error.rs", "#[repr(u8)]\npub enum OrdrError {\n    NotEnoughAccounts = 0,\n    Unauthorized = 3,\n}\n")]);
        let variants = discover_error_enum(&root).unwrap();
        assert!(variants.contains(&"NotEnoughAccounts".to_string()));
        assert!(variants.contains(&"Unauthorized".to_string()));
    }

    #[test]
    fn map_type_covers_primitives() {
        assert_eq!(map_type("u64"), "U64");
        assert_eq!(map_type("i64"), "I64");
        assert_eq!(map_type("bool"), "Bool");
        assert_eq!(map_type("MyCustomType"), "U64");
    }
}
