//! Op registry queries: `dpa list` and `dpa ops <name>`.

use crate::i18n;
use crate::ops;

pub fn list_ops(
    category: Option<&str>,
    group: Option<&str>,
    search: Option<&str>,
) -> anyhow::Result<()> {
    use crate::ops::Op;
    let all = ops::all_ops();

    // Unknown category: fail fast with the real category set so the user can
    // correct the flag instead of getting an empty table.
    if let Some(c) = category {
        let valid: Vec<&str> = {
            let mut s: Vec<&str> = all.iter().map(|o| o.category.as_str()).collect();
            s.sort_unstable();
            s.dedup();
            s
        };
        if !valid.contains(&c) {
            return Err(anyhow::anyhow!(
                "{}",
                i18n::tf("err.invalid_category", &[c, valid.join(" / ").as_str()])
            ));
        }
    }

    let mut filtered: Vec<&Op> = match category {
        Some(c) => all.iter().filter(|o| o.category == c).collect(),
        None => all.iter().collect(),
    };

    // Keyword filter: case-insensitive match against name / category / family /
    // kind / localized description.
    if let Some(kw) = search {
        let kw = kw.to_lowercase();
        filtered.retain(|o| {
            o.name.to_lowercase().contains(&kw)
                || o.category.to_lowercase().contains(&kw)
                || o.family.to_lowercase().contains(&kw)
                || o.kind.to_lowercase().contains(&kw)
                || i18n::t(o.description.as_str()).to_lowercase().contains(&kw)
        });
    }
    filtered.sort_by(|a, b| a.name.cmp(&b.name));

    if filtered.is_empty() {
        println!("{}", i18n::t("msg.no_match"));
        return Ok(());
    }

    let display_name = |o: &Op| -> String {
        // Display layer strips only the official `dpa:` namespace prefix
        // (`dpa:aes:encrypt` -> `aes:encrypt`); plugin ops under other
        // namespaces (`my:foo`) keep their full ID so they stay
        // distinguishable and round-trip correctly.
        o.name
            .strip_prefix("dpa:")
            .map(|rest| rest.to_string())
            .unwrap_or_else(|| o.name.clone())
    };

    match group {
        Some("family") | Some("kind") | Some("category") => {
            use std::collections::BTreeMap;
            let key = |o: &Op| -> String {
                match group.unwrap() {
                    "kind" => o.kind.clone(),
                    "category" => o.category.clone(),
                    _ => o.family.clone(),
                }
            };
            let mut buckets: BTreeMap<String, Vec<&Op>> = BTreeMap::new();
            for o in &filtered {
                buckets.entry(key(o)).or_default().push(o);
            }
            let mut total = 0;
            for (g, members) in &buckets {
                println!("{}", i18n::tf("msg.group_header", &[g.as_str()]));
                for o in members {
                    total += 1;
                    println!(
                        "  {:<12} {:<28} {:<40}",
                        o.kind,
                        display_name(o),
                        i18n::t(o.description.as_str())
                    );
                }
            }
            println!(
                "{}",
                i18n::tf("msg.op_count", &[total.to_string().as_str()])
            );
            Ok(())
        }
        _ => {
            // Dynamic column widths: align to the widest cell (capped) so long
            // categories/names do not break the table, and short ones do not
            // leave huge gaps.
            let titles = [
                i18n::t("msg.col_category"),
                i18n::t("msg.col_family"),
                i18n::t("msg.col_kind"),
                i18n::t("msg.col_op"),
                i18n::t("msg.col_desc"),
            ];
            let cell = |f: &dyn Fn(&Op) -> String, idx: usize| -> usize {
                let mut w = titles[idx].chars().count();
                for o in &filtered {
                    w = w.max(f(o).chars().count());
                }
                w.clamp(4, 40)
            };
            let w_cat = cell(&|o: &Op| o.category.clone(), 0);
            let w_fam = cell(&|o: &Op| o.family.clone(), 1);
            let w_kind = cell(&|o: &Op| o.kind.clone(), 2);
            let w_op = cell(&|o: &Op| display_name(o), 3);
            let mut w_desc = titles[4].chars().count();
            for o in &filtered {
                w_desc = w_desc.max(i18n::t(o.description.as_str()).chars().count());
            }
            let w_desc = w_desc.clamp(4, 40);

            let row = |a: &str, b: &str, c: &str, d: &str, e: &str| {
                println!(
                    "{:<w_cat$} {:<w_fam$} {:<w_kind$} {:<w_op$} {:<w_desc$}",
                    a,
                    b,
                    c,
                    d,
                    e,
                    w_cat = w_cat,
                    w_fam = w_fam,
                    w_kind = w_kind,
                    w_op = w_op,
                    w_desc = w_desc
                );
            };
            row(titles[0], titles[1], titles[2], titles[3], titles[4]);
            row(
                &"-".repeat(w_cat),
                &"-".repeat(w_fam),
                &"-".repeat(w_kind),
                &"-".repeat(w_op),
                &"-".repeat(w_desc),
            );
            for o in &filtered {
                row(
                    &o.category,
                    &o.family,
                    &o.kind,
                    &display_name(o),
                    i18n::t(o.description.as_str()),
                );
            }
            println!(
                "{}",
                i18n::tf("msg.op_count", &[filtered.len().to_string().as_str()])
            );
            Ok(())
        }
    }
}

/// Levenshtein distance over Unicode scalar values (used only for
/// suggestion ranking, small alphabets; O(n*m) is fine here).
fn lev(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut cur = vec![i + 1; b.len() + 1];
        for (j, cb) in b.iter().enumerate() {
            cur[j + 1] = (prev[j + 1] + 1)
                .min(cur[j] + 1)
                .min(prev[j] + usize::from(ca != cb));
        }
        prev = cur;
    }
    prev[b.len()]
}

/// Error message for an unknown op, plus up to 3 close suggestions.
/// Substring matches rank ahead of pure edit distance so a typo like
/// `dpa:sha256` still surfaces `dpa:sha2:256`-style names first.
fn op_not_found_with_suggestions(name: &str) -> String {
    let base = i18n::tf("err.op_not_found", &[name]);
    let name_l = name.to_lowercase();
    let mut scored: Vec<(usize, &str)> = ops::all_ops()
        .iter()
        .map(|o| {
            let cand = o.name.as_str();
            let cand_l = cand.to_lowercase();
            let d = lev(&cand_l, &name_l);
            let sub = cand_l.contains(&name_l) || name_l.contains(&cand_l);
            (if sub { d.saturating_sub(50) } else { d }, cand)
        })
        .collect();
    scored.sort_by_key(|(d, _)| *d);
    let sugg: Vec<&str> = scored.iter().take(3).map(|(_, n)| *n).collect();
    format!(
        "{} {}",
        base,
        i18n::tf("msg.op_suggest", &[sugg.join(", ").as_str()])
    )
}

pub fn show_op(name: &str) -> anyhow::Result<()> {
    let op = match ops::find_op(name) {
        Some(op) => op,
        None => return Err(anyhow::anyhow!("{}", op_not_found_with_suggestions(name))),
    };
    println!("{}", i18n::tf("msg.op_name", &[op.name.as_str()]));
    println!("{}", i18n::tf("msg.op_category", &[op.category.as_str()]));
    println!("{}", i18n::tf("msg.op_family", &[op.family.as_str()]));
    println!("{}", i18n::tf("msg.op_kind", &[op.kind.as_str()]));
    println!("{}", i18n::tf("msg.op_level", &[op.level.display()]));
    if op.input != crate::ops::OpIO::Unspecified {
        println!("{}", i18n::tf("msg.op_input", &[op.input.display()]));
    }
    if op.output != crate::ops::OpIO::Unspecified {
        println!("{}", i18n::tf("msg.op_output", &[op.output.display()]));
    }
    println!(
        "{}",
        i18n::tf("msg.op_description", &[i18n::t(op.description.as_str())])
    );
    if op.args.is_empty() {
        println!("{}", i18n::t("msg.no_args"));
    } else {
        println!("{}", i18n::t("msg.args_header"));
        for a in op.args {
            let req = if a.required {
                i18n::t("msg.req")
            } else {
                i18n::t("msg.opt")
            };
            let fmt = if a.format == crate::ops::ArgFormat::Utf8 {
                String::new()
            } else {
                format!(" (format: {}) ", a.format.display())
            };
            println!("  - {} [{}]{}{}", a.name, req, fmt, i18n::t(a.description));
        }
    }
    Ok(())
}
