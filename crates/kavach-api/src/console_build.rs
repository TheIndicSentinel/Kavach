// Whether `console/dist` holds a real console build. Shared with
// `build.rs` (through `include!`), which embeds the console only when this
// says so, so a stub `index.html` left in `dist/` is never served as a
// blank page. Standard library only: the build script has no dependencies
// of its own.

/// The `/assets/...` files a built `index.html` references through `src="..."`
/// or `href="..."`, without the leading slash (the `src` ones first).
#[must_use]
pub fn referenced_assets(index_html: &str) -> Vec<String> {
    let mut out = Vec::new();
    for attr in ["src=\"", "href=\""] {
        let mut rest = index_html;
        while let Some(at) = rest.find(attr) {
            rest = &rest[at + attr.len()..];
            let Some(end) = rest.find('"') else { break };
            if let Some(asset) = rest[..end].strip_prefix("/assets/") {
                if !asset.is_empty() {
                    out.push(format!("assets/{asset}"));
                }
            }
            rest = &rest[end..];
        }
    }
    out
}

/// Why `index.html` is not a real build, or `None` when it is: it loads at
/// least one script from `/assets/`, and every `/assets/` file it names
/// exists according to `exists`.
pub fn not_a_build(index_html: &str, exists: impl Fn(&str) -> bool) -> Option<String> {
    let assets = referenced_assets(index_html);
    if !assets.iter().any(|asset| {
        std::path::Path::new(asset)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("js"))
    }) {
        return Some("index.html loads no script from /assets/ (a stub, not a build)".into());
    }
    if let Some(missing) = assets.iter().find(|asset| !exists(asset)) {
        return Some(format!("index.html names {missing}, which is not in dist/"));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUILT: &str = r#"<!doctype html><html><head>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
    <script type="module" crossorigin src="/assets/index-DZ00pijL.js"></script>
    <link rel="stylesheet" crossorigin href="/assets/index-TTJG_7AI.css">
    </head><body><div id="root"></div></body></html>"#;

    #[test]
    fn a_real_build_names_its_hashed_assets() {
        assert_eq!(
            referenced_assets(BUILT),
            ["assets/index-DZ00pijL.js", "assets/index-TTJG_7AI.css"]
        );
        assert_eq!(not_a_build(BUILT, |_| true), None);
    }

    #[test]
    fn the_source_index_is_not_a_build() {
        // console/index.html as Vite reads it: it loads /src/main.tsx.
        let source = r#"<div id="root"></div><script type="module" src="/src/main.tsx"></script>"#;
        assert!(not_a_build(source, |_| true).is_some());
    }

    #[test]
    fn an_empty_or_stub_index_is_not_a_build() {
        assert!(not_a_build("", |_| true).is_some());
        assert!(not_a_build("<html><body></body></html>", |_| true).is_some());
        // Styles alone render nothing: a script is required.
        let css_only = r#"<link rel="stylesheet" href="/assets/index.css">"#;
        assert!(not_a_build(css_only, |_| true).is_some());
    }

    #[test]
    fn a_missing_asset_is_not_a_build() {
        let why =
            not_a_build(BUILT, |asset| asset != "assets/index-TTJG_7AI.css").expect("refused");
        assert!(why.contains("assets/index-TTJG_7AI.css"), "{why}");
    }
}
