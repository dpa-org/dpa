//! dpa - Data Processing & Analysis, flows as code. (CLI entry point)

use std::collections::HashMap;
use std::str::FromStr;

use dpa::{cli, engine, flow, i18n, ops, plugin, recipe, registry};

/// Parse `--jobs`: a non-negative integer; `0` means auto (by CPU cores).
/// Rejects non-numeric values instead of silently falling back
/// to the auto thread count.
fn parse_jobs(s: &str) -> Result<usize, String> {
    s.parse::<usize>().map_err(|_| {
        format!("invalid --jobs value '{s}': expected a non-negative integer (0 = auto)")
    })
}

/// Pre-scan argv for `--lang` and apply it *before* `build_cli` runs, so that
/// `--lang zh --help` renders the help text in Chinese (clap resolves help
/// strings at build time). Falls back to environment detection when the flag
/// is absent. The post-parse block below re-applies the same value (idempotent).
fn apply_lang_from_args() {
    let mut args = std::env::args().skip(1);
    let mut lang: Option<String> = None;
    while let Some(a) = args.next() {
        if a == "--lang" {
            lang = args.next();
            break;
        }
        if let Some(v) = a.strip_prefix("--lang=") {
            lang = Some(v.to_string());
            break;
        }
    }
    match lang.as_deref().map(|l| l.to_ascii_lowercase()) {
        Some(l) if l.starts_with("zh") => {
            i18n::set_lang(i18n::LANG_ZH);
        }
        Some(l) if l.starts_with("en") => {
            i18n::set_lang(i18n::LANG_EN);
        }
        _ => i18n::set_lang(i18n::detect_lang()),
    }
}

/// Localize clap parse errors (#9): under `zh`, the four common error classes
/// get a full Chinese message with the offending argument / value / subcommand
/// extracted via clap's error context (no more "Chinese prefix + English
/// body"). Errors without usable context fall back to clap's original text.
fn localize_clap_error(e: &clap::Error) -> String {
    use clap::error::{ContextKind, ContextValue, ErrorKind};
    if i18n::lang() != i18n::LANG_ZH {
        return e.to_string();
    }
    // clap does not expose the missing argument names as a usable context
    // value for MissingRequiredArgument; emit a fixed localized sentence
    // instead of leaking the English body.
    if e.kind() == ErrorKind::MissingRequiredArgument {
        return i18n::t("err.clap.missing_required_plain").to_string();
    }
    let ctx = |k: ContextKind| -> Option<String> {
        e.get(k).and_then(|v| match v {
            ContextValue::String(s) if !s.trim().is_empty() => Some(s.clone()),
            _ => None,
        })
    };
    let (key, ck) = match e.kind() {
        ErrorKind::UnknownArgument => ("err.clap.unknown_argument", ContextKind::InvalidArg),
        ErrorKind::InvalidValue | ErrorKind::ValueValidation => {
            ("err.clap.invalid_value", ContextKind::InvalidValue)
        }
        ErrorKind::InvalidSubcommand => (
            "err.clap.invalid_subcommand",
            ContextKind::InvalidSubcommand,
        ),
        _ => return e.to_string(),
    };
    match ctx(ck) {
        Some(v) => i18n::tf(key, &[v.as_str()]),
        None => e.to_string(),
    }
}

/// Print a usage-class error to stderr and exit with clap's usage exit code
/// (2), matching the Unix/CLI convention: argument/usage errors exit 2 while
/// runtime failures exit 1. Used for errors clap cannot classify itself
/// because the offending value is validated after parsing (bare `dpa op`,
/// unknown op name, bad dynamic op args, unsupported recipe output format).
fn usage_error(msg: impl std::fmt::Display) -> ! {
    eprintln!("{msg}");
    std::process::exit(2);
}

/// On Windows, when the console codepage is not UTF-8 (65001),
/// print a one-time hint on stderr suggesting `chcp 65001`. It fires only when
/// stdout is an actual console (GetConsoleMode-backed `is_terminal`), so
/// piped/redirected (non-interactive) runs never see it and scripts stay
/// silent.
#[cfg(windows)]
fn warn_non_utf8_codepage() {
    use std::io::IsTerminal;
    if !std::io::stdout().is_terminal() {
        return;
    }
    // SAFETY: plain Win32 query, no pointers, no side effects.
    let cp = unsafe { windows_sys::Win32::System::Console::GetConsoleOutputCP() };
    if cp != 65001 {
        eprintln!("{}", i18n::t("msg.codepage_hint"));
    }
}

#[cfg(not(windows))]
fn warn_non_utf8_codepage() {}

fn main() -> anyhow::Result<()> {
    apply_lang_from_args();
    warn_non_utf8_codepage();
    let matches = match dpa::cli::build_cli().try_get_matches() {
        Ok(m) => m,
        Err(e) => {
            // #9: wrap the four high-frequency clap error classes under zh.
            if e.use_stderr() {
                eprintln!("{}", localize_clap_error(&e));
            } else {
                println!("{}", localize_clap_error(&e));
            }
            std::process::exit(e.exit_code());
        }
    };

    // Language: --lang flag wins, then env detection (default English).
    if let Some(l) = matches.get_one::<String>("lang") {
        let l = l.to_ascii_lowercase();
        if l.starts_with("zh") {
            i18n::set_lang(i18n::LANG_ZH);
        } else if l.starts_with("en") {
            i18n::set_lang(i18n::LANG_EN);
        } else {
            // Invalid --lang values warn instead of silently falling back.
            eprintln!("{}", i18n::tf("err.bad_lang", &[l.as_str()]));
            i18n::set_lang(i18n::detect_lang());
        }
    } else {
        i18n::set_lang(i18n::detect_lang());
    }

    // Plugins are never discovered implicitly: only an explicit `--plugins <dir>`
    // is loaded by default. `--discover-plugins` is the opt-in for scanning the
    // default directories, and it warns first, because whatever it finds is
    // native code that runs with the user's privileges.
    if matches.get_flag("discover-plugins") {
        let dirs = plugin::default_plugin_dirs();
        if !dirs.is_empty() {
            let list = dirs
                .iter()
                .map(|d| d.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            eprintln!(
                "{}",
                i18n::tf("msg.discover_plugins_warning", &[list.as_str()])
            );
        }
        let n = plugin::load_default_plugins()?;
        if n > 0 {
            eprintln!(
                "{}",
                i18n::tf("msg.default_plugins_loaded", &[n.to_string().as_str()])
            );
        }
    }
    if let Some(dir) = matches.get_one::<String>("plugins") {
        let n = plugin::load_plugins(std::path::Path::new(dir))?;
        if n > 0 {
            eprintln!(
                "{}",
                i18n::tf(
                    "msg.plugins_loaded",
                    &[n.to_string().as_str(), dir.as_str()]
                )
            );
        }
    }

    // Per-step observability (--verbose / -v). The flag is
    // threaded into each run call's EngineConfig instead of a global switch.
    let verbose_flag = matches.get_flag("verbose");

    // --version prints one clean line (clap's default render trailed an
    // extra blank line that tripped up `dpa --version | cut` style scripts).
    // When built from a git checkout, build.rs embeds the commit
    // hash and date (DPA_GIT_HASH / DPA_GIT_DATE); fall back to the bare
    // version line for source trees without .git.
    if matches.get_flag("version") {
        let version = env!("CARGO_PKG_VERSION");
        match (option_env!("DPA_GIT_HASH"), option_env!("DPA_GIT_DATE")) {
            (Some(h), Some(d)) if !h.is_empty() && !d.is_empty() => {
                println!("dpa {version} (commit {h}, {d})");
            }
            _ => println!("dpa {version}"),
        }
        return Ok(());
    }

    // Shell completion generation (clap_complete). Handled before
    // subcommand dispatch: it only needs the CLI model, not an actual run.
    if let Some(shell) = matches.get_one::<String>("generate-completion") {
        let mut cli = dpa::cli::build_cli();
        if let Ok(sh) = clap_complete::Shell::from_str(shell) {
            clap_complete::generate(sh, &mut cli, "dpa", &mut std::io::stdout());
            return Ok(());
        }
        return Err(anyhow::anyhow!(
            "{}",
            i18n::tf("err.bad_shell", &[shell.as_str()])
        ));
    }

    match matches.subcommand() {
        Some(("run", m)) => {
            let mut inputs: Vec<String> = m
                .get_many::<String>("inputs")
                .map(|v| v.cloned().collect())
                .unwrap_or_default();
            let common = |inputs: Vec<String>| {
                (
                    inputs,
                    m.get_one::<String>("output").map(String::as_str),
                    m.get_one::<String>("output_format").cloned(),
                    m.get_flag("recursive"),
                    // clap validated via `parse_jobs`; non-numeric
                    // inputs fail at parse time, unwrap_or(0) covers the default.
                    m.get_one::<usize>("jobs").copied().unwrap_or(0),
                    m.get_one::<usize>("to_step").copied(),
                    m.get_flag("explain"),
                    // Optional explicit framing between batch
                    // stdout outputs (None = no framing, binary-integrity-first).
                    m.get_one::<String>("batch-separator").cloned(),
                    // Optional per-output label line on batch
                    // stdout (false = off by default, byte-exact stream).
                    m.get_flag("batch-label"),
                )
            };
            // Apply the resource cap before running the flow
            // (per-call EngineConfig, no process-wide state).
            let mut cfg = engine::EngineConfig::default().with_verbose(verbose_flag);
            if let Some(n) = m.get_one::<usize>("max-input-bytes") {
                cfg = cfg.with_max_input_bytes(*n);
            }
            if let Some(n) = m.get_one::<usize>("max-step-output-bytes") {
                cfg = cfg.with_max_step_output_bytes(*n);
            }
            if let Some(names) = m.get_many::<String>("allow-env") {
                let set = names
                    .flat_map(|s| s.split(','))
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect::<std::collections::HashSet<_>>();
                cfg = cfg.with_allow_env(set);
            }
            if let Some(s) = m.get_one::<String>("batch-separator") {
                cfg = cfg.with_batch_separator(Some(s.clone()));
            }
            if m.get_flag("batch-label") {
                cfg = cfg.with_batch_label(true);
            }
            if let Some(yaml) = m.get_one::<String>("eval") {
                // With `--eval` the flow comes from the flag, so the first
                // positional is an input rather than a flow path.
                if let Some(first) = m.get_one::<String>("flow") {
                    inputs.insert(0, first.clone());
                }
                let (inputs, output, output_format, recursive, jobs, to_step, explain, ..) =
                    common(inputs);
                engine::run_flow_yaml(
                    yaml,
                    &inputs,
                    output,
                    output_format,
                    recursive,
                    jobs,
                    to_step,
                    explain,
                    &cfg,
                )
            } else {
                let flow = m.get_one::<String>("flow").cloned().unwrap_or_default();
                let (inputs, output, output_format, recursive, jobs, to_step, explain, ..) =
                    common(inputs);
                engine::run_flow(
                    &flow,
                    &inputs,
                    output,
                    output_format,
                    recursive,
                    jobs,
                    to_step,
                    explain,
                    &cfg,
                )
            }
        }
        Some(("list", m)) => {
            let out = registry::list_ops(
                m.get_one::<String>("category").map(String::as_str),
                m.get_one::<String>("group").map(String::as_str),
                m.get_one::<String>("search").map(String::as_str),
                m.get_one::<bool>("full").copied().unwrap_or(false),
            )?;
            println!("{out}");
            Ok(())
        }
        Some(("ops", m)) => {
            let name = m.get_one::<String>("name").unwrap();
            match registry::show_op(name) {
                Ok(out) => {
                    println!("{out}");
                    Ok(())
                }
                Err(e) => usage_error(e),
            }
        }
        Some(("op", m)) => run_single_op(m),
        Some(("recipe", m)) => match m.subcommand() {
            Some(("convert", sm)) => {
                let input = sm.get_one::<String>("input").unwrap();
                let from = sm
                    .get_one::<String>("from")
                    .map(String::as_str)
                    .unwrap_or("auto");
                let to = sm.get_one::<String>("to").map(String::as_str).unwrap();
                let lang = sm
                    .get_one::<String>("lang")
                    .map(String::as_str)
                    .and_then(recipe::Lang::parse);

                let (from_fmt, auto) = match recipe::Format::parse(from) {
                    Some(f) => (f, false),
                    None => (recipe::Format::Chef, true),
                };
                let to_fmt = match recipe::Format::parse(to) {
                    Some(f) => f,
                    None => usage_error(format!(
                        "unsupported output format: {to} (url | chef | json)"
                    )),
                };

                let from_fmt = if auto {
                    recipe::detect_format(input)
                } else {
                    from_fmt
                };

                let out = recipe::convert(input, from_fmt, to_fmt, lang)?;
                println!("{out}");
                Ok(())
            }
            _ => unreachable!("recipe subcommand required"),
        },
        _ => {
            // Bare `dpa` with no subcommand used to panic via
            // unreachable!(); print the long help instead so first-run users
            // see how the tool is used.
            let mut cli = dpa::cli::build_cli();
            cli.print_long_help()?;
            println!();
            Ok(())
        }
    }
}

/// Common options accepted by `dpa op` in addition to the op's own arguments.
/// Kept in one place so a collision with an op argument name can be detected
/// before clap sees a duplicate.
const OP_COMMON_FLAGS: &[&str] = &[
    "input",
    "output",
    "output-format",
    "hex",
    "recursive",
    "jobs",
    "max-input-bytes",
];

/// zh-CN help template for the dynamic op help (`dpa op <name> --help`).
/// The static CLI uses `ZH_TEMPLATE` in cli.rs, but the dynamic command built
/// here is a bare `Command::new("dpa op <name>")` with no about text and no
/// subcommands, so it uses a reduced template (no `{before-help}` about /
/// `{subcommands}` sections). Usage:/Options:/Arguments: are the three localized
/// labels; the `help` argument exists on this command (it is not disabled),
/// so `{options}` renders `-h, --help` with its localized help text.
const OP_ZH_TEMPLATE: &str = "\
{before-help}{about-with-newline}用法: {usage}\n\n选项:\n{options}\n\n参数:\n{positionals}\n{after-help}";

/// `dpa op <name> [--arg value]... [INPUT]...`: run one operation without
/// writing a flow file.
///
/// The op's arguments come from its `ArgSpec` in the registry, so they are not
/// declared anywhere in the CLI definition: the name is resolved first, a
/// parser is built from that op's spec, and the remaining arguments are parsed
/// with it. The resulting single step then runs through the same engine path as
/// a flow, so batch mode, output handling, and the type check behave the same.
fn run_single_op(m: &clap::ArgMatches) -> anyhow::Result<()> {
    let name = m.get_one::<String>("name");
    // Explicit `dpa op --help` / `dpa op -h`: show this command's help.
    if name.map(|n| n == "-h" || n == "--help").unwrap_or(false) {
        let mut cli = dpa::cli::build_cli();
        cli.find_subcommand_mut("op")
            .expect("op subcommand")
            .print_long_help()?;
        println!();
        return Ok(());
    }
    // Bare `dpa op` (no name) is a usage error: exit 2 like clap's
    // other missing-argument cases instead of silently printing help / 0.
    let name = match name {
        Some(n) => n,
        None => usage_error(i18n::t("err.op_missing_name")),
    };
    // An unknown op name surfaces the closest registered names
    // (e.g. `json:to:yaml` -> "did you mean json:to-yaml?") instead of a
    // bare `Unknown op`; it is a usage error too (exit 2).
    // `op list` is a common user guess; tell them it is not an op
    // name and point to the real `dpa list` command instead of echoing
    // the misleading generic not-found hint.
    let op = match ops::find_op(name) {
        Some(op) => op,
        None if name.eq_ignore_ascii_case("list") => usage_error(i18n::t("err.op_list_hint")),
        None => usage_error(registry::op_not_found_with_suggestions(name)),
    };

    let rest: Vec<String> = m
        .get_many::<String>("rest")
        .map(|v| v.cloned().collect())
        .unwrap_or_default();

    // The usage line carries the resolved op name so `dpa op sort --help`
    // shows `Usage: dpa op sort ...` instead of a generic template. clap's
    // `Command::new` only accepts 'static text; run_single_op runs at most
    // once per process, so leaking one short op-name string is safe and keeps
    // clap's auto-rendered usage (flags/args) byte-accurate.
    let cmd_name: &'static str = format!("dpa op {name}").leak();
    let mut cmd = clap::Command::new(cmd_name).no_binary_name(true);

    // An op argument wins over a common flag of the same name; none collide
    // today, and this keeps a future addition from panicking clap.
    let op_arg_names: Vec<&str> = op.args.iter().map(|a| a.name).collect();
    for reserved in OP_COMMON_FLAGS {
        if op_arg_names.contains(reserved) {
            return Err(anyhow::anyhow!(
                "{}",
                i18n::tf("err.op_arg_reserved", &[*reserved, op.name.as_str()])
            ));
        }
    }

    // #26: op-specific arguments are declared first so they render at the top
    // of the help output; the shared options follow in their own section.
    for a in op.args {
        let mut arg = clap::Arg::new(a.name)
            .long(a.name)
            .help(i18n::t_str(a.description));
        // GNU-style CLI conveniences for select arguments - `-n` short
        // flag and `--lines` long alias on dpa:head/dpa:tail. Both resolve to
        // the same argument as `--n`; the long form remains canonical.
        if let Some(c) = cli::arg_short(&op.name, a.name) {
            arg = arg.short(c);
        }
        if let Some(aliases) = cli::arg_visible_aliases(&op.name, a.name) {
            for al in aliases {
                arg = arg.visible_alias(al);
            }
        }
        if a.required {
            arg = arg.required(true);
        }
        if a.format == ops::ArgFormat::Bool {
            // #5: boolean flags accept a bare `--flag` (implies true) and an
            // optional `--flag true|false`; error text tells the user the
            // accepted values. Flows keep the string form unchanged.
            arg = arg
                .num_args(0..=1)
                .default_missing_value("true")
                .value_parser(clap::builder::ValueParser::new(
                    |s: &str| match ops::parse_bool(s) {
                        Ok(_) => Ok(s.to_string()),
                        Err(_) => Err(format!("invalid bool value: {s}, expected true|false")),
                    },
                ));
        }
        cmd = cmd.arg(arg);
        // Short aliases declared by the op spec (e.g. `--loose` for
        // `strict_mode=false` on base64/base32 decoders) become standalone
        // flags: they set the mapped argument to its lenient value unless the
        // long form was given explicitly. Registered as a separate Arg (not a
        // `visible_alias`) so `--loose` never swallows the next token as a
        // value and always means "lenient" regardless of clap's default-value
        // rules for the boolean long form.
        if let Some(alias) = cli::arg_alias(&op.name, a.name) {
            cmd = cmd.arg(
                clap::Arg::new(alias)
                    .long(alias)
                    .action(clap::ArgAction::SetTrue)
                    .help(i18n::t("cli.loose_help")),
            );
        }
    }
    cmd = cmd.arg(
        clap::Arg::new("input")
            .num_args(0..)
            .value_name("INPUT")
            .help(i18n::t("cli.input_help")),
    );

    // Common options, folded into a single "Common options" section (#26).
    // `--hex` is a shorthand for `--output-format hex` (#10).
    cmd = cmd
        .next_help_heading(i18n::t("cli.common_options_heading"))
        .arg(
            clap::Arg::new("output")
                .short('o')
                .long("output")
                .help(i18n::t("cli.output_help")),
        )
        .arg(
            clap::Arg::new("output_format")
                .long("output-format")
                .help(i18n::t("cli.output_format_help")),
        )
        .arg(
            clap::Arg::new("hex")
                .long("hex")
                .action(clap::ArgAction::SetTrue)
                .help(i18n::t("cli.hex_help")),
        )
        .arg(
            clap::Arg::new("recursive")
                .short('r')
                .long("recursive")
                .action(clap::ArgAction::SetTrue)
                .help(i18n::t("cli.recursive_help")),
        )
        .arg(
            clap::Arg::new("jobs")
                .short('j')
                .long("jobs")
                .default_value("0")
                .value_parser(parse_jobs)
                .help(i18n::t("cli.jobs_help")),
        )
        .arg(
            clap::Arg::new("max-input-bytes")
                .long("max-input-bytes")
                .value_parser(clap::value_parser!(usize))
                .help(i18n::t("cli.max_input_bytes_help")),
        )
        .arg(
            clap::Arg::new("max-step-output-bytes")
                .long("max-step-output-bytes")
                .value_parser(clap::value_parser!(usize))
                .help(i18n::t("cli.max_step_output_bytes_help")),
        )
        .arg(
            clap::Arg::new("explain")
                .long("explain")
                .action(clap::ArgAction::SetTrue)
                .help(i18n::t("cli.explain_help")),
        );

    // An `Examples:` section (from the op registry's example
    // key) and the raw-output hint (for every op whose declared output is Raw,
    // matching `random`) are appended to the op help. sm4:mac keeps its own
    // length-extension warning; all three share the after-help block.
    let mut extra = String::new();
    if let Some(ek) = op.example {
        extra.push_str(i18n::t("cli.examples_label"));
        extra.push('\n');
        // The examples are bash-flavoured; Windows users need
        // the caveat right where the examples are rendered.
        extra.push_str(i18n::t("cli.examples_bash_note"));
        extra.push('\n');
        for line in i18n::t(ek).split('\n') {
            extra.push_str("  ");
            extra.push_str(line);
            extra.push('\n');
        }
        extra.push('\n');
    }
    if op.output == ops::OpIO::Raw {
        extra.push_str(i18n::t("msg.raw_output_hint"));
    }
    if op.name == "dpa:sm4:mac" {
        if !extra.is_empty() {
            extra.push('\n');
        }
        extra.push_str(i18n::t("op.sm4.mac.help_note"));
    }
    if !extra.is_empty() {
        // run_single_op runs at most once per process (like the cmd_name leak
        // above), so leaking the after-help text is safe and keeps clap's
        // requirement for `'static` text.
        let extra_static: &'static str = Box::leak(extra.into_boxed_str());
        cmd = cmd.after_help(extra_static);
    }
    // zh-CN op help localizes the Usage:/Options:/Arguments: labels. The
    // dynamic command keeps its help flag (unlike the static `op`
    // subcommand); clap injects that flag lazily during parsing, so only the
    // template is swapped (no `mut_arg("help")`, which would panic on the
    // unbuilt command).
    if i18n::lang() == i18n::LANG_ZH {
        // Localize the injected `-h, --help` flag line too.
        // clap injects that flag lazily during parsing, so `mut_arg("help")`
        // would panic on the unbuilt command; declaring the arg explicitly
        // (with ArgAction::Help) and disabling the lazy injection yields one
        // localized line instead of two duplicate `-h, --help` entries.
        cmd = cmd
            .disable_help_flag(true)
            .arg(
                clap::Arg::new("help")
                    .short('h')
                    .long("help")
                    .action(clap::ArgAction::Help)
                    .help(i18n::t("cli.help_help")),
            )
            .help_template(OP_ZH_TEMPLATE);
    }

    let parsed = match cmd.try_get_matches_from(&rest) {
        Ok(v) => v,
        // `dpa op <name> --help` / `-h`: rendered from the op's own spec.
        Err(e) if e.kind() == clap::error::ErrorKind::DisplayHelp => {
            e.print()?;
            return Ok(());
        }
        // Usage-class parse errors on the dynamic op args (unknown flag,
        // invalid value, ...) exit 2, matching clap's own exit code for the
        // static CLI; the message stays localized.
        Err(e) => {
            eprintln!("{}", localize_clap_error(&e));
            std::process::exit(e.exit_code());
        }
    };

    let mut args: HashMap<String, String> = HashMap::new();
    for a in op.args {
        if let Some(v) = parsed.get_one::<String>(a.name) {
            args.insert(a.name.to_string(), v.clone());
        }
        // Alias flags (e.g. `--loose`) map to a *different* value than the
        // long form on purpose (`--loose` == `strict_mode=false`); an
        // explicitly given long form always wins over the alias.
        if let Some(alias) = cli::arg_alias(&op.name, a.name)
            && parsed.get_flag(alias)
            && !parsed.contains_id(a.name)
        {
            args.insert(a.name.to_string(), "false".to_string());
        }
    }
    let inputs: Vec<String> = parsed
        .get_many::<String>("input")
        .map(|v| v.cloned().collect())
        .unwrap_or_default();
    let output = parsed.get_one::<String>("output").map(String::as_str);
    // #10: `--hex` is a shorthand for `--output-format hex`; an explicit
    // `--output-format` wins if both are given.
    let output_format = parsed
        .get_one::<String>("output_format")
        .cloned()
        .or_else(|| {
            if parsed.get_flag("hex") {
                Some("hex".to_string())
            } else {
                None
            }
        });
    let recursive = parsed.get_flag("recursive");
    // clap already validated the value via `parse_jobs`; a
    // non-numeric input fails at parse time, so unwrap_or(0) is unreachable
    // defensive code for the auto (0) default.
    let jobs = parsed.get_one::<usize>("jobs").copied().unwrap_or(0);
    // The single-op path never consumed the global verbose switch
    // (only `run` did), so it keeps the default EngineConfig and just applies
    // the two size caps the user explicitly passed.
    let mut cfg = engine::EngineConfig::default();
    if let Some(n) = parsed.get_one::<usize>("max-input-bytes") {
        cfg = cfg.with_max_input_bytes(*n);
    }
    if let Some(n) = parsed.get_one::<usize>("max-step-output-bytes") {
        cfg = cfg.with_max_step_output_bytes(*n);
    }

    let single = flow::Flow {
        name: None,
        description: None,
        output: None,
        steps: vec![flow::Step {
            op: op.name.to_string(),
            args,
        }],
        meta: None,
    };
    // Serializing keeps a single execution path: everything from here on is
    // the same code that runs a flow file.
    let yaml = serde_saphyr::to_string(&single)?;
    engine::run_flow_yaml(
        &yaml,
        &inputs,
        output,
        output_format,
        recursive,
        jobs,
        None,
        parsed.get_flag("explain"),
        &cfg,
    )
}
