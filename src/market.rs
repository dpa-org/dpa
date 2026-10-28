//! Flow package support (prototype).
//!
//! A flow may carry a [`FlowMeta`] manifest (id, version, author, tags,
//! license) and be wrapped with it into a single `.dpaflow` YAML package.
//! Installing a package validates that every operation it references exists in
//! the local registry.
//!
//! The format is versioned and independent of any recipe format. The CLI
//! surface that exposed these functions (`dpa flow export` / `import` /
//! `manifest`) is disabled in 1.0: dpa stays local, with no remote registry and
//! no network. The package format, the manifest, and these APIs remain in place
//! as the basis for a future sharing mechanism.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::flow::{Flow, FlowMeta, from_yaml};
use crate::i18n;
use crate::ops;
use std::fmt::Write as FmtWrite;

/// Package format id.
pub const PACKAGE_FORMAT: &str = "dpa-flow";
/// Package format version (bump on breaking changes only).
pub const PACKAGE_VERSION: u32 = 1;
/// Default flow version used when a flow carries no manifest.
pub const DEFAULT_FLOW_VERSION: &str = "1.0.0";

/// A shareable flow package (`dpa flow export` output / `dpa flow import` input).
#[derive(Debug, Deserialize, Serialize)]
pub struct SharePackage {
    pub format: String,
    pub version: u32,
    #[serde(default)]
    pub meta: FlowMeta,
    #[serde(flatten)]
    pub flow: Flow,
}

/// `dpa flow manifest <flow.yaml>`: print manifest + per-step op availability.
pub fn cmd_manifest(flow_path: &str) -> anyhow::Result<String> {
    let mut buf = String::new();
    let flow = load_flow(flow_path)?;
    let meta = flow.meta.clone().unwrap_or_default();

    match (&flow.name, &flow.description) {
        (Some(n), Some(d)) => {
            writeln!(
                buf,
                "{}",
                i18n::tf("msg.flow_meta", &[n.as_str(), d.as_str()])
            )?;
        }
        (Some(n), None) => {
            writeln!(buf, "{}", i18n::tf("msg.flow_name", &[n.as_str()]))?;
        }
        (None, Some(d)) => {
            writeln!(buf, "{}", i18n::tf("msg.flow_desc", &[d.as_str()]))?;
        }
        (None, None) => {}
    }

    writeln!(
        buf,
        "{}",
        i18n::tf("msg.flow_id", &[meta.id.as_deref().unwrap_or("-")])
    )?;
    writeln!(
        buf,
        "{}",
        i18n::tf(
            "msg.flow_version",
            &[meta.version.as_deref().unwrap_or("-")]
        )
    )?;
    writeln!(
        buf,
        "{}",
        i18n::tf("msg.flow_author", &[meta.author.as_deref().unwrap_or("-")])
    )?;
    writeln!(
        buf,
        "{}",
        i18n::tf(
            "msg.flow_license",
            &[meta.license.as_deref().unwrap_or("-")]
        )
    )?;
    if meta.tags.is_empty() {
        writeln!(buf, "{}", i18n::t("msg.flow_tags_none"))?;
    } else {
        writeln!(
            buf,
            "{}",
            i18n::tf("msg.flow_tags", &[meta.tags.join(", ").as_str()])
        )?;
    }
    if let Some(h) = &meta.homepage {
        writeln!(buf, "{}", i18n::tf("msg.flow_homepage", &[h.as_str()]))?;
    }

    writeln!(
        buf,
        "{}",
        i18n::tf("msg.flow_steps", &[flow.steps.len().to_string().as_str()])
    )?;
    for (idx, step) in flow.steps.iter().enumerate() {
        let ok = ops::find_op(&step.op).is_some();
        let marker = if ok {
            i18n::t("msg.step_ok")
        } else {
            i18n::t("msg.step_missing")
        };
        writeln!(buf, "  [{}] {} ({})", idx + 1, step.op, marker)?;
    }
    Ok(buf)
}

/// `dpa flow export <flow.yaml> [-o out.dpaflow]`: wrap into a shareable package.
pub fn cmd_export(flow_path: &str, out_path: Option<&str>) -> anyhow::Result<String> {
    let mut buf = String::new();
    let flow = load_flow(flow_path)?;
    if flow.steps.is_empty() {
        anyhow::bail!("{}", i18n::t("err.empty_steps"));
    }

    // Build a manifest even when the source flow has none, so the package is
    // self-describing and importable elsewhere.
    let mut meta = flow.meta.clone().unwrap_or_default();
    if meta.id.is_none() {
        meta.id = Some(default_flow_id(flow_path));
    }
    if meta.version.is_none() {
        meta.version = Some(DEFAULT_FLOW_VERSION.to_string());
    }

    let pkg = SharePackage {
        format: PACKAGE_FORMAT.to_string(),
        version: PACKAGE_VERSION,
        meta: meta.clone(),
        // meta lives at package level; avoid a duplicate `meta` key when the
        // flow is flattened into the package YAML.
        flow: Flow { meta: None, ..flow },
    };
    let yaml = serde_saphyr::to_string(&pkg).map_err(|e| {
        anyhow::anyhow!(
            "{}",
            i18n::tf("err.pkg_serialize", &[e.to_string().as_str()])
        )
    })?;

    let out = match out_path {
        Some(p) => PathBuf::from(p),
        None => default_pkg_path(flow_path),
    };
    if let Some(parent) = out.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| {
            anyhow::anyhow!(
                "{}",
                i18n::tf("err.create_outdir_failed", &[i18n::os_error(&e).as_str()])
            )
        })?;
    }
    std::fs::write(&out, yaml).map_err(|e| {
        anyhow::anyhow!(
            "{}",
            i18n::tf("err.create_outfile_failed", &[i18n::os_error(&e).as_str()])
        )
    })?;

    writeln!(
        buf,
        "{}",
        i18n::tf("msg.flow_exported", &[out.display().to_string().as_str()])
    )?;
    Ok(buf)
}

/// `dpa flow import <file.dpaflow> [-o dir]`: validate and install a package.
///
/// Every step op must exist in the local registry; the flow is written into the
/// output directory (or next to the package) as a plain flow YAML, ready to run.
pub fn cmd_import(pkg_path: &str, out_dir: Option<&str>) -> anyhow::Result<String> {
    let mut buf = String::new();
    let yaml = std::fs::read_to_string(pkg_path).map_err(|e| {
        anyhow::anyhow!(
            "{}",
            i18n::tf("err.read_pkg_failed", &[i18n::os_error(&e).as_str()])
        )
    })?;
    let pkg: SharePackage = from_yaml(&yaml)
        .map_err(|e| anyhow::anyhow!("{}", i18n::tf("err.pkg_parse", &[e.to_string().as_str()])))?;

    if pkg.format != PACKAGE_FORMAT {
        anyhow::bail!(
            "{}",
            i18n::tf("err.pkg_format", &[pkg.format.as_str(), PACKAGE_FORMAT])
        );
    }
    if pkg.version != PACKAGE_VERSION {
        anyhow::bail!(
            "{}",
            i18n::tf(
                "err.pkg_version",
                &[
                    pkg.version.to_string().as_str(),
                    PACKAGE_VERSION.to_string().as_str()
                ]
            )
        );
    }
    if pkg.flow.steps.is_empty() {
        anyhow::bail!("{}", i18n::t("err.empty_steps"));
    }

    // Validate every referenced op before touching the filesystem.
    for (idx, step) in pkg.flow.steps.iter().enumerate() {
        if ops::find_op(&step.op).is_none() {
            anyhow::bail!(
                "{}",
                i18n::tf(
                    "err.pkg_unknown_op",
                    &[(idx + 1).to_string().as_str(), step.op.as_str()]
                )
            );
        }
    }

    let id = pkg
        .meta
        .id
        .clone()
        .unwrap_or_else(|| default_flow_id(pkg_path));
    let dir = match out_dir {
        Some(d) => PathBuf::from(d),
        None => {
            let p = Path::new(pkg_path);
            p.parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("."))
        }
    };
    std::fs::create_dir_all(&dir).map_err(|e| {
        anyhow::anyhow!(
            "{}",
            i18n::tf("err.create_outdir_failed", &[i18n::os_error(&e).as_str()])
        )
    })?;

    let file_name = format!("{}.yaml", safe_name(&id));
    let out = dir.join(file_name);
    // Restore package-level meta into the installed flow so the flow remains
    // self-describing once the package wrapper is gone.
    let mut flow = pkg.flow;
    flow.meta = Some(pkg.meta.clone());
    let flow_yaml = serde_saphyr::to_string(&flow).map_err(|e| {
        anyhow::anyhow!(
            "{}",
            i18n::tf("err.pkg_serialize", &[e.to_string().as_str()])
        )
    })?;
    std::fs::write(&out, flow_yaml).map_err(|e| {
        anyhow::anyhow!(
            "{}",
            i18n::tf("err.create_outfile_failed", &[i18n::os_error(&e).as_str()])
        )
    })?;

    writeln!(
        buf,
        "{}",
        i18n::tf(
            "msg.flow_imported",
            &[out.display().to_string().as_str(), id.as_str()]
        )
    )?;
    Ok(buf)
}

/// Load and parse a flow file.
fn load_flow(path: &str) -> anyhow::Result<Flow> {
    let yaml = std::fs::read_to_string(path).map_err(|e| {
        anyhow::anyhow!(
            "{}",
            i18n::tf("err.read_flow_failed", &[path, i18n::os_error(&e).as_str()])
        )
    })?;
    from_yaml(&yaml).map_err(|e| {
        anyhow::anyhow!(
            "{}",
            i18n::tf("err.parse_flow_failed", &[e.to_string().as_str()])
        )
    })
}

/// Default namespaced flow id from a file path stem, e.g. `dpa:flow:base64-decode`.
fn default_flow_id(path: &str) -> String {
    let stem = Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("flow");
    format!("dpa:flow:{}", safe_name(stem))
}

/// Default package path next to the source flow (`<stem>.dpaflow`).
fn default_pkg_path(path: &str) -> PathBuf {
    let p = Path::new(path);
    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("flow");
    match p.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(format!("{stem}.dpaflow")),
        _ => PathBuf::from(format!("{stem}.dpaflow")),
    }
}

/// Make a string filesystem-safe: keep alphanumerics, `-`, `_`, `.`; collapse others to `-`.
fn safe_name(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
            out.push(c);
        } else {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "flow".to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("dpa_market_{}_{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn export_import_roundtrip() {
        let dir = temp_dir("roundtrip");
        let flow_path = dir.join("demo.yaml");
        let mut f = std::fs::File::create(&flow_path).unwrap();
        writeln!(f, "name: demo").unwrap();
        writeln!(f, "description: roundtrip test").unwrap();
        writeln!(f, "steps:").unwrap();
        writeln!(f, "  - op: dpa:base64:decode").unwrap();
        writeln!(f, "  - op: dpa:upper").unwrap();
        drop(f);

        let pkg_path = dir.join("demo.dpaflow");
        cmd_export(
            flow_path.to_str().unwrap(),
            Some(pkg_path.to_str().unwrap()),
        )
        .unwrap();
        assert!(pkg_path.exists());

        // Package carries manifest defaults.
        let pkg_text = std::fs::read_to_string(&pkg_path).unwrap();
        assert!(pkg_text.contains("format: dpa-flow"));
        assert!(pkg_text.contains("version: 1"));
        assert!(pkg_text.contains("dpa:flow:demo"));

        // Import into a fresh directory and verify the flow file.
        let out_dir = dir.join("installed");
        cmd_import(pkg_path.to_str().unwrap(), Some(out_dir.to_str().unwrap())).unwrap();
        let installed = out_dir.join("dpa-flow-demo.yaml");
        assert!(installed.exists());
        let flow: Flow = from_yaml(&std::fs::read_to_string(&installed).unwrap()).unwrap();
        assert_eq!(flow.steps.len(), 2);
        assert_eq!(flow.steps[0].op, "dpa:base64:decode");
        let meta = flow.meta.unwrap();
        assert_eq!(meta.id.as_deref(), Some("dpa:flow:demo"));
        assert_eq!(meta.version.as_deref(), Some("1.0.0"));
    }

    #[test]
    fn import_rejects_unknown_op() {
        let dir = temp_dir("unknown_op");
        let pkg_path = dir.join("bad.dpaflow");
        let pkg = SharePackage {
            format: PACKAGE_FORMAT.to_string(),
            version: PACKAGE_VERSION,
            meta: FlowMeta {
                id: Some("dpa:flow:bad".to_string()),
                ..Default::default()
            },
            flow: Flow {
                name: Some("bad".to_string()),
                steps: vec![crate::flow::Step {
                    op: "dpa:no:such-op".to_string(),
                    args: Default::default(),
                }],
                ..Default::default()
            },
        };
        std::fs::write(&pkg_path, serde_saphyr::to_string(&pkg).unwrap()).unwrap();

        let err = cmd_import(pkg_path.to_str().unwrap(), Some(dir.to_str().unwrap())).unwrap_err();
        assert!(err.to_string().contains("dpa:no:such-op"));
    }

    #[test]
    fn import_rejects_wrong_format() {
        let dir = temp_dir("wrong_format");
        let pkg_path = dir.join("evil.dpaflow");
        std::fs::write(&pkg_path, "format: recipe\nversion: 1\n").unwrap();
        let err = cmd_import(pkg_path.to_str().unwrap(), Some(dir.to_str().unwrap())).unwrap_err();
        assert!(err.to_string().contains("dpa-flow"));
    }

    #[test]
    fn safe_name_collapses_special_chars() {
        assert_eq!(safe_name("base64 decode!"), "base64-decode");
        assert_eq!(safe_name("!!!"), "flow");
        assert_eq!(safe_name("a/b:c"), "a-b-c");
    }
}
