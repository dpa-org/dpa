//! Op registry queries: `dpa list` and `dpa ops <name>`.

use crate::i18n;
use crate::ops;
use std::fmt::Write as FmtWrite;

/// Render one description cell: when truncation is active and the text is
/// wider than `w_desc`, keep `w_desc - 1` chars and append an ellipsis so the
/// partial nature stays visible. Otherwise unchanged.
fn truncate_desc(s: &str, w_desc: usize, no_truncate: bool) -> String {
    if !no_truncate && s.chars().count() > w_desc {
        let take = w_desc.saturating_sub(1);
        let mut t: String = s.chars().take(take).collect();
        t.push('…');
        t
    } else {
        s.to_string()
    }
}

pub fn list_ops(
    category: Option<&str>,
    group: Option<&str>,
    search: Option<&str>,
    full: bool,
) -> anyhow::Result<String> {
    use crate::ops::Op;
    let mut buf = String::new();
    // `fork` is an engine-level control step (see engine.rs): it must not show
    // up as an ordinary data op in listings. It stays fully available in flow
    // contexts (`dpa run` / `-e`), and `ops` / `op` lookups keep resolving it.
    let all: Vec<&Op> = ops::all_ops()
        .iter()
        .filter(|o| o.name != "dpa:fork")
        .collect();

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
        Some(c) => all.iter().filter(|o| o.category == c).copied().collect(),
        None => all.to_vec(),
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
        writeln!(buf, "{}", i18n::t("msg.no_match"))?;
        return Ok(buf);
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
                // `group` is `Some` in this arm; bind it once instead of
                // unwrap (the match above already constrained the value).
                match group {
                    Some("kind") => o.kind.clone(),
                    Some("category") => o.category.clone(),
                    _ => o.family.clone(),
                }
            };
            let mut buckets: BTreeMap<String, Vec<&Op>> = BTreeMap::new();
            for o in &filtered {
                buckets.entry(key(o)).or_default().push(o);
            }
            let mut total = 0;
            for (g, members) in &buckets {
                writeln!(buf, "{}", i18n::tf("msg.group_header", &[g.as_str()]))?;
                for o in members {
                    total += 1;
                    writeln!(
                        buf,
                        "  {:<12} {:<28} {:<40}",
                        o.kind,
                        display_name(o),
                        i18n::t(o.description.as_str())
                    )?;
                }
            }
            writeln!(
                buf,
                "{}",
                i18n::tf("msg.op_count", &[total.to_string().as_str()])
            )?;
            Ok(buf)
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
            // `--full` or a non-TTY stdout removes the description cap;
            // truncated cells get a trailing ellipsis so users can tell the
            // text is partial (previously long descriptions were cut with no
            // marker, e.g. `adler32 ... hex via dpa:he`).
            let no_truncate = full || !std::io::IsTerminal::is_terminal(&std::io::stdout());
            let w_desc = if no_truncate {
                w_desc.max(4)
            } else {
                // Default interactive truncation is 60 chars so long op
                // descriptions stay readable while the
                // table still fits a regular terminal (`--full` lifts it).
                w_desc.clamp(4, 60)
            };
            let desc_cell = |s: &str| -> String { truncate_desc(s, w_desc, no_truncate) };

            let mut row = |a: &str, b: &str, c: &str, d: &str, e: &str| -> std::fmt::Result {
                writeln!(
                    buf,
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
                )?;
                Ok(())
            };
            row(titles[0], titles[1], titles[2], titles[3], titles[4])?;
            row(
                &"-".repeat(w_cat),
                &"-".repeat(w_fam),
                &"-".repeat(w_kind),
                &"-".repeat(w_op),
                &"-".repeat(w_desc),
            )?;
            for o in &filtered {
                row(
                    &o.category,
                    &o.family,
                    &o.kind,
                    &display_name(o),
                    &desc_cell(i18n::t(o.description.as_str())),
                )?;
            }
            writeln!(
                buf,
                "{}",
                i18n::tf("msg.op_count", &[filtered.len().to_string().as_str()])
            )?;
            Ok(buf)
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
/// Unrelated candidates are not suggested: a suggestion is
/// shown only when it is within edit distance 2 of the input or shares a
/// case/substring relationship with it, otherwise the plain not-found
/// message is returned (avoids noise like `nope:op -> upper, lower, not`).
pub fn op_not_found_with_suggestions(name: &str) -> String {
    // Cap the diagnostic length and skip edit-distance scoring for
    // absurdly long inputs. lev() is O(n*m) per candidate and a 30k-character
    // typo previously cost >1s on the error path (script-reachable DoS).
    const MAX_NAME_LEN: usize = 64;
    let shown = if name.chars().count() > MAX_NAME_LEN {
        let head: String = name.chars().take(MAX_NAME_LEN).collect();
        format!("{head}...")
    } else {
        name.to_string()
    };
    let base = i18n::tf("err.op_not_found", &[&shown]);
    // A user typing the canonical `dpa:` prefix (e.g.
    // `dpa:sha25`) must still get suggestions; strip the prefix before
    // scoring so `dpa:hex:encod` matches `hex:encode` instead of scoring
    // against the prefixed literal (which never contains a candidate).
    let name_l = name.strip_prefix("dpa:").unwrap_or(name).to_lowercase();
    if name_l.chars().count() > MAX_NAME_LEN {
        return base;
    }
    let mut scored: Vec<(usize, &str)> = ops::all_ops()
        .iter()
        .map(|o| {
            let cand = o.name.strip_prefix("dpa:").unwrap_or(o.name.as_str());
            let cand_l = cand.to_lowercase();
            let d = lev(&cand_l, &name_l);
            let sub = cand_l.contains(&name_l) || name_l.contains(&cand_l);
            (if sub { d.saturating_sub(50) } else { d }, cand)
        })
        .filter(|(d, cand)| {
            *d <= 2
                || cand.to_lowercase().contains(&name_l)
                || name_l.contains(&cand.to_lowercase())
        })
        .collect();
    scored.sort_by_key(|(d, _)| *d);
    let sugg: Vec<&str> = scored.iter().take(3).map(|(_, n)| *n).collect();
    if sugg.is_empty() {
        return base;
    }
    format!(
        "{} {}",
        base,
        i18n::tf("msg.op_suggest", &[sugg.join(", ").as_str()])
    )
}

pub fn show_op(name: &str) -> anyhow::Result<String> {
    let mut buf = String::new();
    let op = match ops::find_op(name) {
        Some(op) => op,
        None => return Err(anyhow::anyhow!("{}", op_not_found_with_suggestions(name))),
    };
    writeln!(buf, "{}", i18n::tf("msg.op_name", &[op.name.as_str()]))?;
    writeln!(
        buf,
        "{}",
        i18n::tf("msg.op_category", &[op.category.as_str()])
    )?;
    writeln!(buf, "{}", i18n::tf("msg.op_family", &[op.family.as_str()]))?;
    writeln!(buf, "{}", i18n::tf("msg.op_kind", &[op.kind.as_str()]))?;
    writeln!(buf, "{}", i18n::tf("msg.op_level", &[op.level.display()]))?;
    if op.input != crate::ops::OpIO::Unspecified {
        writeln!(buf, "{}", i18n::tf("msg.op_input", &[op.input.display()]))?;
    }
    if op.output != crate::ops::OpIO::Unspecified {
        writeln!(buf, "{}", i18n::tf("msg.op_output", &[op.output.display()]))?;
    }
    // Every op that emits raw binary by default carries the same
    // "pipe to hex/utf8:escape to view" hint that `random` already had.
    if op.output == crate::ops::OpIO::Raw {
        writeln!(buf, "{}", i18n::t("msg.raw_output_hint"))?;
    }
    writeln!(
        buf,
        "{}",
        i18n::tf("msg.op_description", &[i18n::t(op.description.as_str())])
    )?;
    if op.args.is_empty() {
        writeln!(buf, "{}", i18n::t("msg.no_args"))?;
    } else {
        writeln!(buf, "{}", i18n::t("msg.args_header"))?;
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
            writeln!(
                buf,
                "  - {} [{}]{}{}",
                a.name,
                req,
                fmt,
                i18n::t(a.description)
            )?;
        }
    }
    // Optional `Examples:` block, sourced from the centralized
    // `op.<name>.example` i18n key (see `apply_examples` in ops/mod.rs).
    if let Some(ek) = op.example {
        writeln!(buf, "{}", i18n::t("cli.examples_label"))?;
        for line in i18n::t(ek).split('\n') {
            writeln!(buf, "  {}", line)?;
        }
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::{op_not_found_with_suggestions, truncate_desc};

    #[test]
    fn truncate_desc_applies_cap_and_ellipsis() {
        // Interactive (no_truncate=false) long text is capped
        // at `w_desc` (60 by default, minus 1 for the ellipsis); `--full` and
        // non-TTY passes through unchanged.
        let long = "a".repeat(67);
        let t = truncate_desc(&long, 60, false);
        assert_eq!(t.chars().count(), 60, "got {t:?}");
        assert!(t.ends_with('…'), "got {t:?}");
        assert_eq!(truncate_desc(&long, 60, true), long);
        assert_eq!(truncate_desc("short", 60, false), "short");
    }

    #[test]
    fn suggestions_work_for_prefixed_typos() {
        // Prefixed typos still get suggestions; the prefix is
        // stripped before scoring so `dpa:hex:encod` matches `hex:encode`.
        let msg = op_not_found_with_suggestions("dpa:hex:encod");
        assert!(msg.contains("Did you mean"), "{msg}");
        assert!(msg.contains("hex:encode"), "{msg}");
        let msg2 = op_not_found_with_suggestions("dpa:sha25");
        assert!(msg2.contains("sha256"), "{msg2}");
        // An unrelated prefixed name stays silent (no noisy suggestions).
        let msg3 = op_not_found_with_suggestions("dpa:nosuch");
        assert!(!msg3.contains("Did you mean"), "{msg3}");
    }

    /// An absurdly long op name returns fast (no edit-distance scoring)
    /// and the diagnostic is truncated instead of echoing the full input.
    #[test]
    fn huge_unknown_op_returns_fast() {
        let long = format!("dpa:{}", "x".repeat(30_000));
        let t = std::time::Instant::now();
        let msg = op_not_found_with_suggestions(&long);
        assert!(t.elapsed().as_millis() < 500, "took {:?}", t.elapsed());
        assert!(
            !msg.contains("Did you mean"),
            "no suggestions for huge input"
        );
        assert!(msg.contains("..."), "{msg}");
        assert!(!msg.contains(&long), "diagnostic must not echo full input");
        // Names at the threshold stay untruncated and return fast.
        let ok = format!("dpa:{}", "a".repeat(50));
        let t2 = std::time::Instant::now();
        let msg2 = op_not_found_with_suggestions(&ok);
        assert!(t2.elapsed().as_millis() < 500, "took {:?}", t2.elapsed());
        assert!(!msg2.contains("..."), "{msg2}");
    }

    #[test]
    fn suggestions_are_silent_for_unrelated_names() {
        // Totally unrelated inputs get the plain not-found message,
        // not a noisy "did you mean" list.
        let msg = op_not_found_with_suggestions("nope:op");
        assert!(!msg.contains("Did you mean"), "{msg}");
        assert!(msg.contains("nope:op"), "{msg}");
        let msg = op_not_found_with_suggestions("dpa:nosuch");
        assert!(!msg.contains("Did you mean"), "{msg}");
    }

    #[test]
    fn suggestions_survive_case_and_small_typos() {
        // Case-only difference still helps (Base64:Encode -> base64:encode).
        let msg = op_not_found_with_suggestions("Base64:Encode");
        assert!(msg.contains("Did you mean"), "{msg}");
        assert!(msg.contains("base64:encode"), "{msg}");
        // A one-character typo is still worth a suggestion.
        let msg = op_not_found_with_suggestions("base64:encod");
        assert!(msg.contains("Did you mean"), "{msg}");
    }
}
