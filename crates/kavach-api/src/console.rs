//! The governance console (built from `console/`), embedded when `build.rs`
//! found a real build in `console/dist`; otherwise a plain page that says
//! it was not built. Every console response carries the security headers
//! in [`security_headers`]. API paths (`/v1/...`) and missing assets are
//! never answered with the console page: they stay problems.

use axum::{
    body::Body,
    http::{header, HeaderName, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
};

/// The console's Content-Security-Policy: everything from this origin, no
/// inline script or style, no framing.
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self'; \
     style-src 'self'; img-src 'self' data:; connect-src 'self'; \
     frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

/// Hashed build output (`assets/index-<hash>.js`): a new build changes the
/// name, so it can be cached for good.
pub const CACHE_IMMUTABLE: &str = "public, max-age=31536000, immutable";
/// The page itself (`index.html` and every single-page route), and the
/// "not built" page: never stored, so a new build is picked up at once.
pub const CACHE_NO_STORE: &str = "no-store";
/// Unhashed files beside the page (`favicon.svg`): revalidated each time.
pub const CACHE_REVALIDATE: &str = "no-cache";

/// What the console fallback does with a path that no route matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target<'a> {
    /// An API path or a method other than GET/HEAD: the unknown-path problem.
    Problem,
    /// A file of the build, by its path in `dist/`; missing is a problem.
    File(&'a str),
    /// A single-page route (`/`, `/agents/...`): the console page.
    Page,
}

/// Routes `method path` for the console fallback.
#[must_use]
pub fn target<'a>(method: &Method, path: &'a str) -> Target<'a> {
    if method != Method::GET && method != Method::HEAD {
        return Target::Problem;
    }
    let trimmed = path.trim_start_matches('/');
    if trimmed == "v1" || trimmed.starts_with("v1/") {
        return Target::Problem;
    }
    if trimmed.is_empty() || trimmed == "index.html" {
        return Target::Page;
    }
    // Anything with a file name (assets/x.js, favicon.svg, a typo'd .css)
    // is a file or nothing: an HTML page under a script's name would only
    // be refused by the browser (nosniff).
    let last = trimmed.rsplit('/').next().unwrap_or_default();
    if trimmed.starts_with("assets/") || last.contains('.') {
        return Target::File(trimmed);
    }
    Target::Page
}

/// The cache policy for a file of the build.
#[must_use]
pub fn cache_control_for(file: &str) -> &'static str {
    if file == "index.html" {
        CACHE_NO_STORE
    } else if file.starts_with("assets/") {
        CACHE_IMMUTABLE
    } else {
        CACHE_REVALIDATE
    }
}

/// The headers on every console response, with its cache policy.
#[must_use]
pub fn security_headers(cache_control: &'static str) -> [(HeaderName, HeaderValue); 4] {
    [
        (
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(CONTENT_SECURITY_POLICY),
        ),
        (
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ),
        (
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ),
        (
            header::CACHE_CONTROL,
            HeaderValue::from_static(cache_control),
        ),
    ]
}

fn console_response(
    status: StatusCode,
    content_type: &'static str,
    cache_control: &'static str,
    body: Body,
) -> Response {
    (
        status,
        security_headers(cache_control),
        [(header::CONTENT_TYPE, content_type)],
        body,
    )
        .into_response()
}

/// The page served in place of the console when this binary was built
/// without one, so the operator sees why instead of a blank page.
pub const NOT_BUILT: &str = "Kavach console not built into this binary.\n\
     Run `npm run build` in console/ (or scripts/build-console.sh), then rebuild kavach-api.\n\
     The API is unaffected.\n";

#[cfg(console_embedded)]
mod embedded {
    use super::{cache_control_for, console_response, target, Target, CACHE_NO_STORE};
    use axum::{body::Body, http::StatusCode, response::Response};
    use include_dir::{include_dir, Dir};

    static DIST: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../../console/dist");

    /// Static files and the single-page fallback, for reads only.
    pub async fn fallback(req: axum::extract::Request) -> Response {
        let path = req.uri().path().to_owned();
        match target(req.method(), &path) {
            Target::Problem => crate::problem::not_found(req).await,
            Target::Page => page(),
            // `target` routes index.html as the page, so a file here never is.
            Target::File(file) => match DIST.get_file(file) {
                Some(found) => console_response(
                    StatusCode::OK,
                    content_type_for(file),
                    cache_control_for(file),
                    Body::from(found.contents()),
                ),
                None => crate::problem::not_found(req).await,
            },
        }
    }

    fn page() -> Response {
        // build.rs embeds only a dist/ that has index.html.
        let index = DIST
            .get_file("index.html")
            .map_or(&[][..], include_dir::File::contents);
        console_response(
            StatusCode::OK,
            "text/html; charset=utf-8",
            CACHE_NO_STORE,
            Body::from(index),
        )
    }

    fn content_type_for(path: &str) -> &'static str {
        match path.rsplit('.').next() {
            Some("html") => "text/html; charset=utf-8",
            Some("js") => "application/javascript; charset=utf-8",
            Some("css") => "text/css; charset=utf-8",
            Some("svg") => "image/svg+xml",
            Some("png") => "image/png",
            Some("json") => "application/json; charset=utf-8",
            Some("woff2") => "font/woff2",
            Some("woff") => "font/woff",
            _ => "application/octet-stream",
        }
    }
}

#[cfg(console_embedded)]
pub use embedded::fallback;

/// Without an embedded console, the page paths say so in plain text; every
/// other unknown path is the unknown-path problem.
#[cfg(not(console_embedded))]
pub async fn fallback(req: axum::extract::Request) -> Response {
    let path = req.uri().path().to_owned();
    match target(req.method(), &path) {
        Target::Page => console_response(
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            CACHE_NO_STORE,
            Body::from(NOT_BUILT),
        ),
        Target::Problem | Target::File(_) => crate::problem::not_found(req).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_paths_and_writes_are_never_the_console() {
        for path in ["/v1", "/v1/", "/v1/packs", "/v1/agents/a-1", "//v1/x"] {
            assert_eq!(target(&Method::GET, path), Target::Problem, "{path}");
        }
        for method in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
            assert_eq!(target(&method, "/"), Target::Problem, "{method}");
            assert_eq!(target(&method, "/agents"), Target::Problem, "{method}");
        }
    }

    #[test]
    fn page_routes_and_files_are_told_apart() {
        assert_eq!(target(&Method::GET, "/"), Target::Page);
        assert_eq!(target(&Method::HEAD, "/"), Target::Page);
        assert_eq!(target(&Method::GET, "/index.html"), Target::Page);
        assert_eq!(target(&Method::GET, "/agents"), Target::Page);
        assert_eq!(target(&Method::GET, "/agents/a-1/detail"), Target::Page);
        // "v1x" is a page route, not the API prefix.
        assert_eq!(target(&Method::GET, "/v1x"), Target::Page);
        assert_eq!(
            target(&Method::GET, "/assets/index-abc.js"),
            Target::File("assets/index-abc.js")
        );
        assert_eq!(target(&Method::GET, "/assets/x"), Target::File("assets/x"));
        assert_eq!(
            target(&Method::GET, "/favicon.svg"),
            Target::File("favicon.svg")
        );
    }

    #[test]
    fn cache_policy_by_file() {
        assert_eq!(cache_control_for("index.html"), "no-store");
        assert_eq!(
            cache_control_for("assets/index-abc.js"),
            "public, max-age=31536000, immutable"
        );
        assert_eq!(cache_control_for("favicon.svg"), "no-cache");
    }

    #[test]
    fn the_policy_is_the_strict_one() {
        assert_eq!(
            CONTENT_SECURITY_POLICY,
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
             connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        );
    }
}
