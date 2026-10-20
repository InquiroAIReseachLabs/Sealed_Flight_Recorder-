//! review_metrics: line ranges, test-only ranges, code lines and branch counts of Rust sources.
//!
//! Usage: `review-metrics <root> <file>...` where each `<file>` is a path relative to `<root>`.
//! It prints one JSON array, one object per file, in the order given:
//!
//! ```text
//! { "file": "crates/x/src/a.rs", "lines": 120,
//!   "code_lines": [[1,9],[11,40]],          // runs of lines that hold code
//!   "items": [ item, ... ] }                // top-level items, in source order
//!
//! item = { "kind": "fn", "name": "read", "attr_start": 10, "start": 12, "end": 80,
//!          "test": false, "branches": 14,   // branches: functions only
//!          "stmts": [[13,20],...],          // functions only: top-level statements of the body
//!          "children": [ item, ... ] }      // impl, trait and inline module members
//! ```
//!
//! A line "holds code" when a token other than a comment (documentation comments included) starts,
//! ends or spans it; blank lines and comment-only lines do not. `test` is true for an item that is
//! only compiled for tests: `#[test]`, or `#[cfg(...)]` that is true only when `test` is set.
//! `branches` counts decision points in a function body: each `if`, each `match` arm, each match
//! guard, each `while` and `for`, each `&&` and `||`, each `?`, and each `let ... else`. Nested
//! functions are items of their own and are not added to the function around them.
#![forbid(unsafe_code)]

use proc_macro2::{TokenStream, TokenTree};
use quote::ToTokens;
use std::fmt::Write as _;
use std::str::FromStr;
use syn::visit::{self, Visit};
use syn::{BinOp, ImplItem, Item, TraitItem};

/// Smallest start line and largest end line over every token (group delimiters included).
fn bounds<T: ToTokens>(t: &T) -> Option<(usize, usize)> {
    let mut lo = usize::MAX;
    let mut hi = 0usize;
    walk(t.to_token_stream(), &mut |tt| {
        let s = tt.span();
        lo = lo.min(s.start().line);
        hi = hi.max(s.end().line);
    });
    (hi != 0).then_some((lo, hi))
}

fn walk(ts: TokenStream, f: &mut impl FnMut(&TokenTree)) {
    for tt in ts {
        f(&tt);
        if let TokenTree::Group(g) = &tt {
            walk(g.stream(), f);
        }
    }
}

struct Node {
    kind: &'static str,
    name: String,
    attr_start: usize,
    start: usize,
    end: usize,
    test: bool,
    branches: Option<u32>,
    stmts: Vec<(usize, usize)>,
    children: Vec<Node>,
}

/// Counts decision points; does not descend into nested functions.
#[derive(Default)]
struct Branches(u32);

impl<'ast> Visit<'ast> for Branches {
    fn visit_expr_if(&mut self, i: &'ast syn::ExprIf) {
        self.0 += 1;
        visit::visit_expr_if(self, i);
    }
    fn visit_expr_match(&mut self, m: &'ast syn::ExprMatch) {
        self.0 += u32::try_from(m.arms.len()).unwrap_or(u32::MAX);
        visit::visit_expr_match(self, m);
    }
    fn visit_arm(&mut self, a: &'ast syn::Arm) {
        if a.guard.is_some() {
            self.0 += 1;
        }
        visit::visit_arm(self, a);
    }
    fn visit_expr_while(&mut self, w: &'ast syn::ExprWhile) {
        self.0 += 1;
        visit::visit_expr_while(self, w);
    }
    fn visit_expr_for_loop(&mut self, f: &'ast syn::ExprForLoop) {
        self.0 += 1;
        visit::visit_expr_for_loop(self, f);
    }
    fn visit_expr_binary(&mut self, b: &'ast syn::ExprBinary) {
        if matches!(b.op, BinOp::And(_) | BinOp::Or(_)) {
            self.0 += 1;
        }
        visit::visit_expr_binary(self, b);
    }
    fn visit_expr_try(&mut self, t: &'ast syn::ExprTry) {
        self.0 += 1;
        visit::visit_expr_try(self, t);
    }
    fn visit_local(&mut self, l: &'ast syn::Local) {
        if l.init.as_ref().is_some_and(|i| i.diverge.is_some()) {
            self.0 += 1;
        }
        visit::visit_local(self, l);
    }
    fn visit_item_fn(&mut self, _: &'ast syn::ItemFn) {}
}

/// Whether a `cfg` predicate is true only when the `test` cfg is set.
fn cfg_only_test(ts: TokenStream) -> bool {
    let toks: Vec<TokenTree> = ts.into_iter().collect();
    match toks.as_slice() {
        [TokenTree::Ident(i)] => i == "test",
        [TokenTree::Ident(f), TokenTree::Group(g)] => {
            let args = split_commas(g.stream());
            match f.to_string().as_str() {
                "all" => args.into_iter().any(cfg_only_test),
                "any" => !args.is_empty() && args.into_iter().all(cfg_only_test),
                _ => false,
            }
        }
        _ => false,
    }
}

fn split_commas(ts: TokenStream) -> Vec<TokenStream> {
    let mut out = vec![TokenStream::new()];
    for tt in ts {
        match &tt {
            TokenTree::Punct(p) if p.as_char() == ',' => out.push(TokenStream::new()),
            _ => out.last_mut().expect("never empty").extend([tt]),
        }
    }
    out.retain(|s| !s.is_empty());
    out
}

fn attrs_are_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        if a.path().is_ident("test") {
            return true;
        }
        if a.path().is_ident("cfg")
            && let syn::Meta::List(l) = &a.meta
        {
            return cfg_only_test(l.tokens.clone());
        }
        false
    })
}

fn attr_start(attrs: &[syn::Attribute], start: usize) -> usize {
    attrs
        .iter()
        .filter_map(|a| bounds(a).map(|b| b.0))
        .min()
        .map_or(start, |s| s.min(start))
}

fn stmt_spans(block: &syn::Block) -> Vec<(usize, usize)> {
    block.stmts.iter().filter_map(bounds).collect()
}

fn branches_of(block: &syn::Block) -> u32 {
    let mut v = Branches::default();
    v.visit_block(block);
    v.0
}

#[allow(clippy::too_many_arguments)]
fn fn_item(
    attrs: &[syn::Attribute],
    vis: &syn::Visibility,
    sig: &syn::Signature,
    block: Option<&syn::Block>,
    whole: (usize, usize),
    in_test: bool,
    kind: &'static str,
) -> Node {
    let head = [bounds(vis), bounds(sig)]
        .into_iter()
        .flatten()
        .map(|b| b.0)
        .min();
    let start = head.unwrap_or(whole.0);
    Node {
        kind,
        name: sig.ident.to_string(),
        attr_start: attr_start(attrs, start),
        start,
        end: whole.1,
        test: in_test || attrs_are_test(attrs),
        branches: Some(block.map_or(0, branches_of)),
        stmts: block.map(stmt_spans).unwrap_or_default(),
        children: Vec::new(),
    }
}

/// Tokens printed on one line the way a person writes them: `Parser<'_>`, `std::fmt::Display`.
fn type_text<T: ToTokens>(t: &T) -> String {
    t.to_token_stream()
        .to_string()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace(" :: ", "::")
        .replace(" < ", "<")
        .replace("< ", "<")
        .replace(" >", ">")
        .replace(" ,", ",")
        .replace("& ", "&")
}

fn convert(item: &Item, in_test: bool) -> Option<Node> {
    let whole = bounds(item)?;
    let simple = |kind: &'static str, name: String, attrs: &[syn::Attribute]| Node {
        kind,
        name,
        attr_start: attr_start(attrs, whole.0),
        start: whole.0,
        end: whole.1,
        test: in_test || attrs_are_test(attrs),
        branches: None,
        stmts: Vec::new(),
        children: Vec::new(),
    };
    Some(match item {
        Item::Fn(f) => {
            let mut out = fn_item(
                &f.attrs,
                &f.vis,
                &f.sig,
                Some(&f.block),
                whole,
                in_test,
                "fn",
            );
            // Functions nested in the body are items of their own.
            let mut nested = NestedFns(Vec::new());
            nested.visit_block(&f.block);
            out.children = nested
                .0
                .iter()
                .filter_map(|n| convert(&Item::Fn((*n).clone()), out.test))
                .collect();
            out
        }
        Item::Impl(i) => {
            let name = match &i.trait_ {
                Some((bang, path, _)) => {
                    format!(
                        "impl {}{} for {}",
                        if bang.is_some() { "!" } else { "" },
                        type_text(path),
                        type_text(&i.self_ty)
                    )
                }
                None => format!("impl {}", type_text(&i.self_ty)),
            };
            let mut out = simple("impl", name, &i.attrs);
            for m in &i.items {
                if let ImplItem::Fn(f) = m {
                    if let Some(w) = bounds(f) {
                        out.children.push(fn_item(
                            &f.attrs,
                            &f.vis,
                            &f.sig,
                            Some(&f.block),
                            w,
                            out.test,
                            "fn",
                        ));
                    }
                } else if let Some(w) = bounds(m) {
                    let attrs: &[syn::Attribute] = match m {
                        ImplItem::Const(c) => &c.attrs,
                        ImplItem::Type(t) => &t.attrs,
                        ImplItem::Macro(x) => &x.attrs,
                        _ => &[],
                    };
                    out.children.push(Node {
                        kind: "assoc",
                        name: String::new(),
                        attr_start: attr_start(attrs, w.0),
                        start: w.0,
                        end: w.1,
                        test: out.test || attrs_are_test(attrs),
                        branches: None,
                        stmts: Vec::new(),
                        children: Vec::new(),
                    });
                }
            }
            out
        }
        Item::Trait(t) => {
            let mut out = simple("trait", t.ident.to_string(), &t.attrs);
            for m in &t.items {
                if let TraitItem::Fn(f) = m {
                    if let Some(w) = bounds(f) {
                        out.children.push(fn_item(
                            &f.attrs,
                            &syn::Visibility::Inherited,
                            &f.sig,
                            f.default.as_ref(),
                            w,
                            out.test,
                            "fn",
                        ));
                    }
                } else if let Some(w) = bounds(m) {
                    out.children.push(Node {
                        kind: "assoc",
                        name: String::new(),
                        attr_start: w.0,
                        start: w.0,
                        end: w.1,
                        test: out.test,
                        branches: None,
                        stmts: Vec::new(),
                        children: Vec::new(),
                    });
                }
            }
            out
        }
        Item::Mod(m) => {
            let mut out = simple("mod", m.ident.to_string(), &m.attrs);
            if let Some((_, items)) = &m.content {
                out.children = items.iter().filter_map(|i| convert(i, out.test)).collect();
            }
            out
        }
        Item::Struct(s) => simple("struct", s.ident.to_string(), &s.attrs),
        Item::Enum(e) => simple("enum", e.ident.to_string(), &e.attrs),
        Item::Union(u) => simple("union", u.ident.to_string(), &u.attrs),
        Item::Const(c) => simple("const", c.ident.to_string(), &c.attrs),
        Item::Static(s) => simple("static", s.ident.to_string(), &s.attrs),
        Item::Type(t) => simple("type", t.ident.to_string(), &t.attrs),
        Item::Use(u) => simple("use", type_text(&u.tree), &u.attrs),
        Item::Macro(m) => simple(
            "macro",
            m.mac
                .path
                .get_ident()
                .map(ToString::to_string)
                .unwrap_or_default(),
            &m.attrs,
        ),
        Item::ExternCrate(e) => simple("extern_crate", e.ident.to_string(), &e.attrs),
        Item::ForeignMod(f) => simple("foreign_mod", String::new(), &f.attrs),
        Item::TraitAlias(t) => simple("trait_alias", t.ident.to_string(), &t.attrs),
        _ => simple("other", String::new(), &[]),
    })
}

struct NestedFns<'a>(Vec<&'a syn::ItemFn>);

impl<'ast> Visit<'ast> for NestedFns<'ast> {
    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        self.0.push(f);
    }
}

/// Lines that hold a token other than a documentation comment, as inclusive runs.
fn code_lines(src: &str) -> Result<Vec<(usize, usize)>, String> {
    let ts = TokenStream::from_str(src).map_err(|e| e.to_string())?;
    let total = src.lines().count().max(1) + 1;
    let mut mark = vec![false; total + 1];
    mark_tokens(ts, &mut mark);
    let mut runs = Vec::new();
    let mut i = 1;
    while i < mark.len() {
        if mark[i] {
            let s = i;
            while i + 1 < mark.len() && mark[i + 1] {
                i += 1;
            }
            runs.push((s, i));
        }
        i += 1;
    }
    Ok(runs)
}

fn mark_range(mark: &mut [bool], a: usize, b: usize) {
    for l in a..=b {
        if let Some(m) = mark.get_mut(l) {
            *m = true;
        }
    }
}

fn mark_tokens(ts: TokenStream, mark: &mut [bool]) {
    let toks: Vec<TokenTree> = ts.into_iter().collect();
    let mut i = 0;
    while i < toks.len() {
        // `///` and `//!` comments arrive as `#[doc = "..."]` and `#![doc = "..."]`: not code.
        // The tokenizer cannot tell them from a doc attribute written by hand, and this
        // repository writes none, so every doc attribute counts as a comment.
        if let TokenTree::Punct(p) = &toks[i]
            && p.as_char() == '#'
        {
            let mut j = i + 1;
            if matches!(toks.get(j), Some(TokenTree::Punct(b)) if b.as_char() == '!') {
                j += 1;
            }
            if let Some(TokenTree::Group(g)) = toks.get(j)
                && g.delimiter() == proc_macro2::Delimiter::Bracket
                && matches!(g.stream().into_iter().next(), Some(TokenTree::Ident(d)) if d == "doc")
            {
                i = j + 1;
                continue;
            }
        }
        match &toks[i] {
            TokenTree::Group(g) => {
                mark_range(mark, g.span_open().start().line, g.span_open().end().line);
                mark_range(mark, g.span_close().start().line, g.span_close().end().line);
                mark_tokens(g.stream(), mark);
            }
            tt => mark_range(mark, tt.span().start().line, tt.span().end().line),
        }
        i += 1;
    }
}

fn json_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn json_item(out: &mut String, it: &Node) {
    out.push_str("{\"kind\":");
    json_str(out, it.kind);
    out.push_str(",\"name\":");
    json_str(out, &it.name);
    let _ = write!(
        out,
        ",\"attr_start\":{},\"start\":{},\"end\":{},\"test\":{}",
        it.attr_start, it.start, it.end, it.test
    );
    if let Some(b) = it.branches {
        let _ = write!(out, ",\"branches\":{b}");
        if !it.stmts.is_empty() && it.end - it.start >= 150 {
            out.push_str(",\"stmts\":[");
            for (i, (a, b)) in it.stmts.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                let _ = write!(out, "[{a},{b}]");
            }
            out.push(']');
        }
    }
    out.push_str(",\"children\":[");
    for (i, c) in it.children.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        json_item(out, c);
    }
    out.push_str("]}");
}

type Analysis = (Vec<(usize, usize)>, Vec<Node>);

fn analyze(src: &str) -> Result<Analysis, String> {
    let file =
        syn::parse_file(src).map_err(|e| format!("{e} at line {}", e.span().start().line))?;
    let items = file
        .items
        .iter()
        .filter_map(|i| convert(i, false))
        .collect();
    Ok((code_lines(src)?, items))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((root, files)) = args.split_first() else {
        eprintln!("usage: review-metrics <root> <file>...");
        std::process::exit(2);
    };
    let mut out = String::from("[");
    for (n, f) in files.iter().enumerate() {
        let path = std::path::Path::new(root).join(f);
        let src = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{}: {e}", path.display());
                std::process::exit(1);
            }
        };
        let (runs, items) = match analyze(&src) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("{f}: {e}");
                std::process::exit(1);
            }
        };
        if n > 0 {
            out.push(',');
        }
        out.push_str("{\"file\":");
        json_str(&mut out, f);
        let _ = write!(out, ",\"lines\":{},\"code_lines\":[", src.lines().count());
        for (i, (a, b)) in runs.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            let _ = write!(out, "[{a},{b}]");
        }
        out.push_str("],\"items\":[");
        for (i, it) in items.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            json_item(&mut out, it);
        }
        out.push_str("]}");
    }
    out.push(']');
    println!("{out}");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(src: &str) -> Analysis {
        analyze(src).expect("parses")
    }

    #[test]
    fn code_lines_skip_blank_comment_and_doc_lines() {
        let src = "//! crate doc\n\n// plain\n/// item doc\nfn a() {\n    // inside\n    let x = 1;\n\n    /* block\n       comment */\n    x\n}\n";
        let (runs, _) = run(src);
        assert_eq!(runs, vec![(5, 5), (7, 7), (11, 12)]);
    }

    #[test]
    fn multi_line_string_lines_are_code() {
        let src = "fn a() -> &'static str {\n    \"one\ntwo\nthree\"\n}\n";
        let (runs, _) = run(src);
        assert_eq!(runs, vec![(1, 5)]);
    }

    #[test]
    fn test_modules_and_fns_are_marked() {
        let src = "fn p() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {}\n}\n#[cfg(not(test))]\nfn q() {}\n#[cfg(all(test, unix))]\nfn r() {}\n#[cfg(any(test, unix))]\nfn s() {}\n";
        let (_, items) = run(src);
        let flags: Vec<(String, bool)> = items.iter().map(|i| (i.name.clone(), i.test)).collect();
        assert_eq!(
            flags,
            vec![
                ("p".into(), false),
                ("tests".into(), true),
                ("q".into(), false),
                ("r".into(), true),
                ("s".into(), false),
            ]
        );
        assert!(items[1].children[0].test);
    }

    #[test]
    fn branches_count_decision_points() {
        let src = "fn f(a: Option<u8>, b: bool) -> Option<u8> {\n    let Some(x) = a else { return None };\n    if b && x > 1 || x == 0 {\n        match x {\n            0 => {}\n            n if n > 5 => {}\n            _ => {}\n        }\n    }\n    for _ in 0..x {}\n    let y = a?;\n    Some(y)\n}\n";
        let (_, items) = run(src);
        // let-else 1, if 1, && 1, || 1, match arms 3, guard 1, for 1, ? 1
        assert_eq!(items[0].branches, Some(10));
    }

    #[test]
    fn impl_methods_have_ranges_with_attributes_and_docs() {
        let src = "struct S;\nimpl S {\n    /// doc\n    #[inline]\n    pub fn m(&self) {\n        let _ = 1;\n    }\n}\n";
        let (_, items) = run(src);
        let m = &items[1].children[0];
        assert_eq!((m.attr_start, m.start, m.end), (3, 5, 7));
        assert_eq!(items[1].name, "impl S");
    }
}
