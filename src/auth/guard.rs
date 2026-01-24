use axum::response::Redirect;
use axum_extra::extract::cookie::CookieJar;
use std::env;

use crate::auth::jwt::JwtConfig;

pub fn require_user(jar: &CookieJar) -> Result<i32, Redirect> {
    let cookie = match jar.get("access_token") {
        Some(c) => c,
        None => {
            return Err(Redirect::to("/auth/refresh"));
        }
    };

    let token = cookie.value().to_string();

    let jwt_secret = match env::var("JWT_SECRET") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("JWT_SECRET missing in require_user");
            return Err(Redirect::to("/auth/refresh"));
        }
    };
    let jwt = JwtConfig::new(jwt_secret);

    let claims = match jwt.decode_access_token(&token) {
        Ok(c) => c,
        Err(_) => {
            return Err(Redirect::to("/auth/refresh"));
        }
    };

    Ok(claims.sub)
}