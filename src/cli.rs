//! CLI definition (clap builder).
//!
//! Help texts are resolved at runtime via [`crate::i18n`], so `--help` output
//! follows the active language (default English).

use clap::{Arg, ArgAction, Command};

use crate::i18n;
use crate::ops;

use std::collections::BTreeSet;

/// Runtime-generated category list for `dpa list -c/--category` help
/// (review fix C-5): derived from the built-in op set via `ops::builtin_ops()`,
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

/// Build the top-level dpa CLI command.
pub fn build_cli() -> Command {
    Command::new("dpa")
        .version(env!("CARGO_PKG_VERSION"))
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
            Command::new("run")
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
                        .help(i18n::t("cli.jobs_help")),
                )
                .arg(
                    Arg::new("max-input-bytes")
                        .long("max-input-bytes")
                        .value_parser(clap::value_parser!(usize))
                        .help(i18n::t("cli.max_input_bytes_help")),
                ),
        )
        .subcommand(
            Command::new("op")
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
        .subcommand(
            Command::new("list")
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
                ),
        )
        .subcommand(
            Command::new("ops").about(i18n::t("cli.op_about")).arg(
                Arg::new("name")
                    .required(true)
                    .help(i18n::t("cli.op_name_help")),
            ),
        )
        .subcommand(
            Command::new("recipe")
                .about(i18n::t("cli.recipe_about"))
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    Command::new("convert")
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
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review fix C-5: the `--category` help must be generated from the real op
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
