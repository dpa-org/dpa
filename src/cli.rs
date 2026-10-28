//! CLI definition (clap builder).
//!
//! Help texts are resolved at runtime via [`crate::i18n`], so `--help` output
//! follows the active language (default English).

use clap::{Arg, ArgAction, Command};

use crate::i18n;
use crate::ops;

use std::collections::BTreeSet;

/// Runtime-generated category list for `dpa list -c/--category` help
/// Derived from the built-in op set via `ops::builtin_ops()`,
/// so the help never advertises ghost categories that differ from the actual
/// built-in op set (previously a hard-coded `cli.category_help` text).
///
/// This deliberately does NOT call `ops::all_ops()`: `build_cli` runs before
/// plugin directories are loaded, and touching the process-wide registry here
/// would freeze it to built-ins only, silently dropping plugin ops for the
/// rest of the process (plugin ops are loaded into the registry lazily, on
/// first registry access after plugin loading). Plugin categories are dynamic
/// and appear in `dpa list` output itself; the static help is a built-in
/// snapshot.
fn category_help_text() -> String {
    let builtin = ops::builtin_ops();
    let cats: BTreeSet<&str> = builtin.iter().map(|o| o.category.as_str()).collect();
    format!(
        "{} ({})",
        i18n::t_str("cli.category_help_prefix"),
        cats.iter().copied().collect::<Vec<_>>().join(" / ")
    )
}

/// CLI short aliases for op arguments (presentation layer only).
///
/// These helpers live here so the core op
/// domain model stays free of presentation-layer concerns.
///
/// A side table keeps `ArgSpec` untouched: it is a plain 'static-friendly
/// record shared with the plugin ABI, and aliases are few and static.
/// Each alias maps to a *different* value than the long form on purpose:
/// `--loose` is the lenient-mode alias of `--strict_mode` and therefore
/// sets `strict_mode=false`.
pub fn arg_alias(op_name: &str, arg_name: &str) -> Option<&'static str> {
    match (op_name, arg_name) {
        ("dpa:base64:decode" | "dpa:base64:url:decode" | "dpa:base32:decode", "strict_mode") => {
            Some("loose")
        }
        _ => None,
    }
}

/// Short flags for op arguments (presentation layer only), following Unix
/// coreutils conventions. `-n` on `dpa:head` / `dpa:tail` mirrors GNU
/// head/tail and resolves to the exact same `n` argument as the long form,
/// so the default behavior is unchanged.
pub fn arg_short(op_name: &str, arg_name: &str) -> Option<char> {
    match (op_name, arg_name) {
        ("dpa:head" | "dpa:tail", "n") => Some('n'),
        _ => None,
    }
}

/// Additional long aliases for op arguments (presentation layer only).
/// `--lines` on `dpa:head` / `dpa:tail` is the GNU-style long alias of `--n`
/// and keeps the same value semantics (no behavior change).
pub fn arg_visible_aliases(op_name: &str, arg_name: &str) -> Option<&'static [&'static str]> {
    match (op_name, arg_name) {
        ("dpa:head" | "dpa:tail", "n") => Some(&["lines"]),
        _ => None,
    }
}

/// Parse `--jobs`: a non-negative integer; `0` means auto (by CPU cores).
/// Rejects non-numeric values instead of silently falling back
/// to the auto thread count.
fn parse_jobs(s: &str) -> Result<usize, String> {
    s.parse::<usize>().map_err(|_| {
        format!("invalid --jobs value '{s}': expected a non-negative integer (0 = auto)")
    })
}

/// zh-CN clap help template - localizes the clap-generated help chrome
/// (Usage:/Options:/Arguments:/Commands: headings) with minimal intrusion.
/// English keeps clap's default rendering; the template is only applied when
/// the active language is zh-CN.
const ZH_TEMPLATE: &str = "\
{before-help}{about-with-newline}\n用法: {usage}\n\n选项:\n{options}\n\n参数:\n{positionals}\n\n子命令:\n{subcommands}\n{after-help}";

/// Build the top-level dpa CLI command.
pub fn build_cli() -> Command {
    // Apply the zh-CN help template only for Chinese. The built-in
    // `-h/--help` flag is injected lazily by clap during parsing, so
    // `mut_arg("help")` on an unbuilt Command panics with "Argument `help`
    // is undefined" (clap_builder 4.6). We therefore localize the template
    // headings only and leave clap's own flag line untouched.
    let zh = |c: Command| {
        if i18n::lang() == i18n::LANG_ZH {
            c.help_template(ZH_TEMPLATE)
        } else {
            c
        }
    };
    // `op` disables the built-in help flag (its own help is rendered by
    // show_op once the op name is resolved), so only the template applies.
    let zh_no_help = |c: Command| {
        if i18n::lang() == i18n::LANG_ZH {
            c.help_template(ZH_TEMPLATE)
        } else {
            c
        }
    };
    let cmd = Command::new("dpa")
        // --version is a custom flag handled in main (one clean line,
        // no trailing blank line from clap's default render).
        .disable_version_flag(true)
        .about(i18n::t("cli.about_short"))
        .long_about(i18n::t("cli.about_long"))
        .arg(
            Arg::new("lang")
                .long("lang")
                .global(true)
                .value_name("LANG")
                .help(i18n::t("cli.lang_help")),
        )
        .arg(
            Arg::new("version")
                .long("version")
                .action(clap::ArgAction::SetTrue)
                .help(i18n::t("cli.version_help")),
        )
        .arg(
            // Shell completion via clap_complete. A global flag handled
            // in main before subcommand dispatch; supported shells are the
            // standard clap_complete set.
            Arg::new("generate-completion")
                .long("generate-completion")
                .global(true)
                .value_name("SHELL")
                .value_parser(["bash", "zsh", "fish", "powershell"])
                .help(i18n::t("cli.generate_completion_help")),
        )
        .arg(
            Arg::new("verbose")
                .long("verbose")
                .short('v')
                .global(true)
                .action(clap::ArgAction::SetTrue)
                .help(i18n::t("cli.verbose_help")),
        )
        .arg(
            Arg::new("plugins")
                .long("plugins")
                .global(true)
                .value_name("DIR")
                .help(i18n::t("cli.plugins_help")),
        )
        .arg(
            Arg::new("discover-plugins")
                .long("discover-plugins")
                .global(true)
                .action(clap::ArgAction::SetTrue)
                .help(i18n::t("cli.discover_plugins_help")),
        )
        .subcommand(
            zh_no_help(Command::new("run"))
                .about(i18n::t("cli.run_about"))
                .arg(
                    Arg::new("flow")
                        .required_unless_present("eval")
                        .help(i18n::t("cli.run_flow_help")),
                )
                .arg(
                    Arg::new("eval")
                        .short('e')
                        .long("eval")
                        .value_name("YAML")
                        .help(i18n::t("cli.run_eval_help")),
                )
                .arg(
                    Arg::new("inputs")
                        .num_args(0..)
                        .value_name("INPUT")
                        .help(i18n::t("cli.input_help")),
                )
                .arg(
                    Arg::new("output")
                        .short('o')
                        .long("output")
                        .help(i18n::t("cli.output_help")),
                )
                .arg(
                    Arg::new("output_format")
                        .long("output-format")
                        .help(i18n::t("cli.output_format_help")),
                )
                .arg(
                    Arg::new("recursive")
                        .short('r')
                        .long("recursive")
                        .action(ArgAction::SetTrue)
                        .help(i18n::t("cli.recursive_help")),
                )
                .arg(
                    Arg::new("jobs")
                        .short('j')
                        .long("jobs")
                        .default_value("0")
                        .value_parser(parse_jobs)
                        .help(i18n::t("cli.jobs_help")),
                )
                .arg(
                    // Optional explicit framing between batch
                    // stdout outputs. Default is no framing at all so binary
                    // chains stay byte-exact; text scenes can opt in.
                    Arg::new("batch-separator")
                        .long("batch-separator")
                        .value_name("SEP")
                        // Accept a separator that starts with
                        // `-` (e.g. `--batch-separator "---"`) as a value
                        // instead of treating it as a flag/stdin marker.
                        .allow_hyphen_values(true)
                        .help(i18n::t("cli.batch_separator_help")),
                )
                .arg(
                    // Optional per-output label line on batch
                    // stdout. Default off so binary chains stay byte-exact;
                    // text scenes can opt into readable attribution.
                    Arg::new("batch-label")
                        .long("batch-label")
                        .action(ArgAction::SetTrue)
                        .help(i18n::t("cli.batch_label_help")),
                )
                .arg(
                    Arg::new("max-input-bytes")
                        .long("max-input-bytes")
                        .value_parser(clap::value_parser!(usize))
                        .help(i18n::t("cli.max_input_bytes_help")),
                )
                .arg(
                    Arg::new("max-step-output-bytes")
                        .long("max-step-output-bytes")
                        .value_parser(clap::value_parser!(usize))
                        .help(i18n::t("cli.max_step_output_bytes_help")),
                )
                .arg(
                    Arg::new("allow-env")
                        .long("allow-env")
                        .value_name("NAMES")
                        .action(ArgAction::Append)
                        .value_parser(clap::value_parser!(String))
                        .help(i18n::t("cli.allow_env_help")),
                )
                .arg(
                    Arg::new("to_step")
                        .long("to-step")
                        .value_name("N")
                        .value_parser(clap::value_parser!(usize))
                        .help(i18n::t("cli.to_step_help")),
                )
                .arg(
                    Arg::new("explain")
                        .long("explain")
                        .action(ArgAction::SetTrue)
                        .help(i18n::t("cli.explain_help")),
                ),
        )
        .subcommand(
            zh_no_help(Command::new("op"))
                // The usage line is fixed so the top-level help
                // says `dpa op <name> [ARGS]...` instead of implying a
                // static usage template; the resolved op name is then
                // spliced in by run_single_op for `--help`.
                .override_usage("dpa op <name> [ARGS]...")
                .about(i18n::t("cli.op_run_about"))
                .trailing_var_arg(true)
                // `--help` after the op name belongs to the op, not to this
                // command: the arguments are only known once the name is
                // resolved. The handler renders this command's own help when no
                // name (or `--help`) is given.
                .disable_help_flag(true)
                .arg(
                    Arg::new("name")
                        .required(false)
                        .allow_hyphen_values(true)
                        .help(i18n::t("cli.op_run_name_help")),
                )
                .arg(
                    Arg::new("rest")
                        .num_args(0..)
                        .allow_hyphen_values(true)
                        .value_name("ARGS")
                        .help(i18n::t("cli.op_run_args_help")),
                ),
        )
        .subcommand(zh(Command::new("list")
            .about(i18n::t("cli.list_about"))
            .arg(
                Arg::new("category")
                    .short('c')
                    .long("category")
                    .help(category_help_text()),
            )
            .arg(
                Arg::new("search")
                    .short('s')
                    .long("search")
                    .value_name("KW")
                    .help(i18n::t("cli.list_search_help")),
            )
            .arg(
                Arg::new("group")
                    .long("group")
                    .value_parser(["family", "kind", "category"])
                    .help(i18n::t("cli.list_group_help")),
            )
            .arg(
                Arg::new("full")
                    .long("full")
                    // `--full` is a bare switch (no value): it lifts the
                    // hard truncation on long op descriptions. A missing
                    // SetTrue action made clap treat it as `--full <full>` and
                    // reject `dpa list --full` with "a value is required".
                    .action(ArgAction::SetTrue)
                    .help(i18n::t("cli.list_full_help")),
            )))
        .subcommand(
            zh_no_help(Command::new("ops"))
                .about(i18n::t("cli.op_about"))
                .arg(
                    Arg::new("name")
                        .required(true)
                        .help(i18n::t("cli.op_name_help")),
                ),
        )
        .subcommand(
            zh(Command::new("recipe"))
                .about(i18n::t("cli.recipe_about"))
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    zh(Command::new("convert"))
                        .about(i18n::t("cli.recipe_convert_about"))
                        .arg(
                            Arg::new("input")
                                .required(true)
                                .help(i18n::t("cli.recipe_input_help")),
                        )
                        .arg(
                            Arg::new("from")
                                .long("from")
                                .default_value(i18n::t("cli.recipe_from_default"))
                                .value_name("FORMAT")
                                .help(i18n::t("cli.recipe_from_help")),
                        )
                        .arg(
                            Arg::new("to")
                                .long("to")
                                .required(true)
                                .value_name("FORMAT")
                                .help(i18n::t("cli.recipe_to_help")),
                        )
                        .arg(
                            Arg::new("lang")
                                .long("lang")
                                .value_name("LANG")
                                .help(i18n::t("cli.recipe_lang_help")),
                        ),
                ),
        );
    // The top-level help also gets the zh-CN template headings.
    zh(cmd)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `--category` help must be generated from the real op
    /// registry (`ops::all_ops()`), so no ghost category can sneak in and the
    /// en/zh tables stay consistent (fixed `cli.category_help` key removed).
    #[test]
    fn category_help_matches_all_ops() {
        let help = category_help_text();
        // Built-in category set, sorted, deduped. The static help is a
        // built-in snapshot; plugin categories are dynamic and cannot be
        // known while the CLI is being built (see `category_help_text`).
        let builtin = ops::builtin_ops();
        let mut real: Vec<&str> = builtin.iter().map(|o| o.category.as_str()).collect();
        real.sort_unstable();
        real.dedup();

        // Extract the parenthesized list from the generated help.
        let start = help.find('(').expect("help contains (") + 1;
        let end = help.rfind(')').expect("help contains )");
        let shown: Vec<&str> = help[start..end]
            .split(" / ")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();

        assert_eq!(
            shown, real,
            "help categories must equal all_ops() categories"
        );
        assert!(
            help.starts_with(&i18n::t_str("cli.category_help_prefix")),
            "prefix for current language: {}",
            help
        );
    }
}
