use axum::{extract::Request, http::HeaderValue, middleware::Next, response::Response};

pub async fn security_headers_middleware(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    // Prevent MIME type sniffing
    headers.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );

    // Prevent clickjacking
    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));

    // Control referrer information
    headers.insert(
        "referrer-policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );

    // Disable unnecessary browser features
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("geolocation=(), camera=(), microphone=(), payment=()"),
    );

    // Prevent XSS attacks (legacy header, but still useful for older browsers)
    headers.insert(
        "x-xss-protection",
        HeaderValue::from_static("1; mode=block"),
    );

    // Cache control for API responses
    headers.insert(
        "cache-control",
        HeaderValue::from_static("no-store, no-cache, must-revalidate, private"),
    );

    // Prevent caching of sensitive data
    headers.insert("pragma", HeaderValue::from_static("no-cache"));

    // Content Security Policy - strict policy for API responses
    // Since this is an API, we restrict everything
    headers.insert(
        "Content-Security-Policy",
        HeaderValue::from_static(
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        ),
    );

    response
}
