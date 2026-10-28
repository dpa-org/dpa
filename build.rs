// Restrict the cdylib export surface to the explicit
// whitelist in dpa.def. Without this, statically linked C libraries (bzip2)
// can leak symbols (e.g. bz_internal_error) into the DLL export table.
//
// MSVC linker semantics: once /DEF: is given, only symbols named in the
// EXPORTS section are exported. The whitelist is intentionally EMPTY today.
fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!(
        "cargo:rustc-link-arg=/DEF:{}\\dpa.def",
        manifest_dir.replace('/', "\\")
    );
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
