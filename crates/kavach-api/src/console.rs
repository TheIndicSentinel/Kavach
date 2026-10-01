//! Embedded static console assets (built from `console/`).

#[cfg(console_embedded)]
mod embedded {
    use axum::{
        body::Body,
        http::{header, StatusCode},
        response::{IntoResponse, Response},
    };
    use include_dir::{include_dir, Dir};

    static DIST: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../../console/dist");

    /// Static files and the single-page fallback, for reads only: any other
    /// method on an unknown path is 404, never the console page.
    pub async fn fallback(method: axum::http::Method, uri: axum::http::Uri) -> Response {
        if method != axum::http::Method::GET && method != axum::http::Method::HEAD {
            return StatusCode::NOT_FOUND.into_response();
        }
        match lookup(uri.path()) {
            Some((content_type, bytes)) => (
                StatusCode::OK,
                [(header::CONTENT_TYPE, content_type)],
                bytes,
            )
                .into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        }
    }

    fn lookup(path: &str) -> Option<(&'static str, Body)> {
        let trimmed = path.trim_start_matches('/');
        let file_path = if trimmed.is_empty() {
            "index.html"
        } else {
            trimmed
        };

        if let Some(file) = DIST.get_file(file_path) {
            return Some((content_type_for(file_path), body_from(file.contents())));
        }

        DIST.get_file("index.html")
            .map(|file| ("text/html; charset=utf-8", body_from(file.contents())))
    }

    fn body_from(bytes: &'static [u8]) -> Body {
        Body::from(bytes.to_vec())
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
