//! dpa — Data Processing & Analysis, flows as code. (CLI entry point)

use std::collections::HashMap;

use dpa::{engine, flow, i18n, ops, plugin, recipe, registry};

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

fn main() -> anyhow::Result<()> {
    apply_lang_from_args();
    let matches = dpa::cli::build_cli().get_matches();

    // Language: --lang flag wins, then env detection (default English).
    if let Some(l) = matches.get_one::<String>("lang") {
        let l = l.to_ascii_lowercase();
        if l.starts_with("zh") {
            i18n::set_lang(i18n::LANG_ZH);
        } else if l.starts_with("en") {
            i18n::set_lang(i18n::LANG_EN);
        } else {
            // Review residue fix: invalid --lang values warn instead of silently falling back.
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

    // Review G11: per-step observability (--verbose / -v).
    if matches.get_flag("verbose") {
        dpa::engine::set_verbose(true);
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
                    m.get_one::<String>("jobs")
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0),
                )
            };
            // Review §3-F: apply the resource cap before running the flow.
            if let Some(n) = m.get_one::<usize>("max-input-bytes") {
                engine::set_max_input_bytes(*n);
            }
            if let Some(yaml) = m.get_one::<String>("eval") {
                // With `--eval` the flow comes from the flag, so the first
                // positional is an input rather than a flow path.
                if let Some(first) = m.get_one::<String>("flow") {
                    inputs.insert(0, first.clone());
                }
                let (inputs, output, output_format, recursive, jobs) = common(inputs);
                engine::run_flow_yaml(yaml, &inputs, output, output_format, recursive, jobs)
            } else {
                let flow = m.get_one::<String>("flow").cloned().unwrap_or_default();
                let (inputs, output, output_format, recursive, jobs) = common(inputs);
                engine::run_flow(&flow, &inputs, output, output_format, recursive, jobs)
            }
        }
        Some(("list", m)) => registry::list_ops(
            m.get_one::<String>("category").map(String::as_str),
            m.get_one::<String>("group").map(String::as_str),
            m.get_one::<String>("search").map(String::as_str),
        ),
        Some(("ops", m)) => registry::show_op(m.get_one::<String>("name").unwrap()),
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
                let to_fmt = recipe::Format::parse(to).ok_or_else(|| {
                    anyhow::anyhow!("unsupported output format: {to} (url | chef | json)")
                })?;

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
        _ => unreachable!("subcommand required"),
    }
}

/// Common options accepted by `dpa op` in addition to the op's own arguments.
/// Kept in one place so a collision with an op argument name can be detected
/// before clap sees a duplicate.
const OP_COMMON_FLAGS: &[&str] = &[
    "input",
    "output",
    "output-format",
    "recursive",
    "jobs",
    "max-input-bytes",
];

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
    // `dpa op` or `dpa op --help`: nothing to run, so show this command's help.
    if name.map(|n| n == "-h" || n == "--help").unwrap_or(true) {
        let mut cli = dpa::cli::build_cli();
        cli.find_subcommand_mut("op")
            .expect("op subcommand")
            .print_long_help()?;
        println!();
        return Ok(());
    }
    let name = name.expect("op name");
    let op = ops::find_op(name)
        .ok_or_else(|| anyhow::anyhow!("{}", i18n::tf("err.unknown_op_name", &[name.as_str()])))?;

    let rest: Vec<String> = m
        .get_many::<String>("rest")
        .map(|v| v.cloned().collect())
        .unwrap_or_default();

    let mut cmd = clap::Command::new("dpa op")
        .no_binary_name(true)
        .arg(
            clap::Arg::new("input")
                .num_args(0..)
                .value_name("INPUT")
                .help(i18n::t("cli.input_help")),
        )
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
                .help(i18n::t("cli.jobs_help")),
        )
        .arg(
            clap::Arg::new("max-input-bytes")
                .long("max-input-bytes")
                .value_parser(clap::value_parser!(usize))
                .help(i18n::t("cli.max_input_bytes_help")),
        );

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
    for a in op.args {
        let mut arg = clap::Arg::new(a.name)
            .long(a.name)
            .help(i18n::t_str(a.description));
        if a.required {
            arg = arg.required(true);
        }
        cmd = cmd.arg(arg);
    }

    let parsed = match cmd.try_get_matches_from(&rest) {
        Ok(v) => v,
        // `dpa op <name> --help` / `-h`: rendered from the op's own spec.
        Err(e) if e.kind() == clap::error::ErrorKind::DisplayHelp => {
            e.print()?;
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    let mut args: HashMap<String, String> = HashMap::new();
    for a in op.args {
        if let Some(v) = parsed.get_one::<String>(a.name) {
            args.insert(a.name.to_string(), v.clone());
        }
    }
    let inputs: Vec<String> = parsed
        .get_many::<String>("input")
        .map(|v| v.cloned().collect())
        .unwrap_or_default();
    let output = parsed.get_one::<String>("output").map(String::as_str);
    let output_format = parsed.get_one::<String>("output_format").cloned();
    let recursive = parsed.get_flag("recursive");
    let jobs = parsed
        .get_one::<String>("jobs")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if let Some(n) = parsed.get_one::<usize>("max-input-bytes") {
        engine::set_max_input_bytes(*n);
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
    let yaml = serde_yaml::to_string(&single)?;
    engine::run_flow_yaml(&yaml, &inputs, output, output_format, recursive, jobs)
}
