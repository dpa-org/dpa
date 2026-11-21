// Restrict the cdylib export surface to the explicit
// whitelist in dpa.def. Without this, statically linked C libraries (bzip2)
// can leak symbols (e.g. bz_internal_error) into the DLL export table.
//
// MSVC linker semantics: once /DEF: is given, only symbols named in the
// EXPORTS section are exported. The whitelist is intentionally EMPTY today.
fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    // `/DEF:` is an MSVC linker option. Sending it to GNU/lld linkers makes
    // every non-Windows build of the cdylib fail, so gate it on the target.
    let target = std::env::var("TARGET").unwrap_or_default();
    if target.ends_with("-windows-msvc") {
        // The python binding's module entry (PyInit_dpa) is produced by the
        // pyo3 #[pymodule] macro as a #[no_mangle] export, but an empty
        // /DEF: whitelist hides *every* symbol - including PyInit_dpa - so
        // `import dpa` would fail with "cannot find module entry point".
        // With the python feature enabled, generate a temporary def that
        // re-exports PyInit_dpa on top of the base whitelist; otherwise keep
        // the deliberately-empty dpa.def (zero C ABI surface).
        let def_path = if std::env::var("CARGO_FEATURE_PYTHON").is_ok() {
            let out_dir = std::env::var("OUT_DIR").unwrap();
            let def = std::path::Path::new(&out_dir).join("dpa_python.def");
            let mut text = String::from("EXPORTS\n    PyInit_dpa\n");
            if let Ok(base) =
                std::fs::read_to_string(std::path::Path::new(&manifest_dir).join("dpa.def"))
            {
                for line in base.lines() {
                    let t = line.trim();
                    if !t.is_empty() && !t.starts_with(';') && t != "EXPORTS" {
                        text.push_str(t);
                        text.push('\n');
                    }
                }
            }
            std::fs::write(&def, text).expect("write dpa_python.def");
            def.display().to_string()
        } else {
            format!("{}\\dpa.def", manifest_dir.replace('/', "\\"))
        };
        println!("cargo:rustc-link-arg=/DEF:{}", def_path.replace('/', "\\"));
    }
    println!("cargo:rerun-if-changed=dpa.def");

    // Embed the git commit (and its date) for `dpa --version`
    // when building from a git checkout; sources without .git (release
    // tarballs) fall back to the bare version line. The date comes from the
    // commit itself (%cs), so the embedded value is deterministic per commit.
    //
    // cargo's `rerun-if-changed` cannot be relied on to watch
    // files under `.git/` (verified on Windows: touching
    // `.git/refs/heads/main` after a commit does not rerun build.rs), so the
    // declarations below are best-effort only. The authoritative trigger is
    // touching `build.rs` itself (which cargo tracks reliably): the
    // repository-local post-commit hook (.githooks/post-commit, installed by
    // scripts/setup-git-hooks.ps1) touches it after every commit, and
    // scripts/release.ps1 touches it before packaging builds. Together they
    // guarantee the embedded hash stays at the current HEAD on incremental
    // builds.
    let git_dir = std::path::Path::new(&manifest_dir).join(".git/HEAD");
    if git_dir.exists() {
        println!("cargo:rerun-if-changed={}", git_dir.display());
        // .git/HEAD content is constant ("ref: refs/heads/main") across
        // commits, so also watch the branch ref file to force a rebuild
        // (and a fresh embedded hash) after each commit.
        if let Some(branch) =
            git_capture(&["rev-parse", "--abbrev-ref", "HEAD"]).filter(|b| b != "HEAD")
        {
            let ref_file =
                std::path::Path::new(&manifest_dir).join(format!(".git/refs/heads/{branch}"));
            println!("cargo:rerun-if-changed={}", ref_file.display());
        }
    }
    if let Some(h) = git_capture(&["rev-parse", "--short=12", "HEAD"]) {
        // Mark builds from a dirty working tree so the
        // embedded hash never silently claims a clean commit. The release
        // script hard-fails on dirty trees; the -dirty suffix is for ad-hoc
        // local builds where `dpa --version` must not lie about its commit.
        let dirty = git_capture(&["status", "--porcelain"])
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        if dirty {
            println!("cargo:rustc-env=DPA_GIT_HASH={h}-dirty");
        } else {
            println!("cargo:rustc-env=DPA_GIT_HASH={h}");
        }
    }
    if let Some(d) = git_capture(&["show", "-s", "--format=%cs", "HEAD"]) {
        println!("cargo:rustc-env=DPA_GIT_DATE={d}");
    }
}

fn git_capture(args: &[&str]) -> Option<String> {
    let out = std::process::Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}
