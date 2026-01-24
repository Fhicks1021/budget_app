use axum::{
    extract::State,
    response::Redirect,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use chrono::Utc;
use sqlx::PgPool;
use std::env;
use rand::{distributions::Alphanumeric, Rng};

use crate::auth::jwt::JwtConfig;

pub async fn refresh_session(
    State(pool): State<PgPool>,
    jar: CookieJar,
) -> Result<(CookieJar, Redirect), Redirect> {
    let refresh_cookie = jar
        .get("refresh_token")
        .ok_or_else(|| Redirect::to("/login"))?;

    let old_token = refresh_cookie.value().to_string();

    let session = sqlx::query!(
        r#"
        SELECT user_id, expires_at
        FROM user_sessions
        WHERE token = $1
        "#,
        old_token,
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        eprintln!("DB error in refresh_session: {e}");
        Redirect::to("/login")
    })?;

    let session = match session {
        Some(s) => s,
        None => return Err(Redirect::to("/login")),
    };

    let now = Utc::now();
    if session.expires_at < now {
        let _ = sqlx::query!(
            r#"DELETE FROM user_sessions WHERE token = $1"#,
            old_token
        )
        .execute(&pool)
        .await;

        return Err(Redirect::to("/login"));
    }

    let jwt_secret = env::var("JWT_SECRET").map_err(|e| {
        eprintln!("JWT_SECRET not set in refresh_session: {e}");
        Redirect::to("/login")
    })?;
    let jwt = JwtConfig::new(jwt_secret);

    let new_access = jwt
        .encode_access_token(session.user_id)
        .map_err(|e| {
            eprintln!("JWT encode failure in refresh_session: {e}");
            Redirect::to("/login")
        })?;

    let new_refresh: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();

    let new_expires_at = session.expires_at;

    sqlx::query!(
        r#"
        UPDATE user_sessions
        SET token = $1, expires_at = $2
        WHERE token = $3
        "#,
        new_refresh,
        new_expires_at,
        old_token,
    )
    .execute(&pool)
    .await
    .map_err(|e| {
        eprintln!("DB update error in refresh_session: {e}");
        Redirect::to("/login")
    })?;

    let secure = !cfg!(debug_assertions);

    let mut access_cookie = Cookie::new("access_token", new_access);
    access_cookie.set_http_only(true);
    access_cookie.set_secure(secure);
    access_cookie.set_same_site(SameSite::Lax);
    access_cookie.set_path("/");

    let mut refresh_cookie = Cookie::new("refresh_token", new_refresh);
    refresh_cookie.set_http_only(true);
    refresh_cookie.set_secure(secure);
    refresh_cookie.set_same_site(SameSite::Lax);
    refresh_cookie.set_path("/");

    let jar = jar.add(access_cookie).add(refresh_cookie);

    Ok((jar, Redirect::to("/budget")))
}
