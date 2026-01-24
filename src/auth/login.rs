use axum::{
    extract::{Form, State},
    http::StatusCode,
    response::Redirect,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use chrono::{Duration, Utc};
use sqlx::PgPool;
use std::env;
use serde::Deserialize;

use rand::{distributions::Alphanumeric, Rng};
use password_hash::{
    rand_core::OsRng,
    PasswordHash,
    PasswordHasher,
    PasswordVerifier,
    SaltString,
};

use crate::auth::jwt::JwtConfig;

#[derive(Deserialize)]
pub struct RegisterForm {
    email: String,
    password: String,
    confirm_password: String,
}


pub async fn register_submit(
    State(pool): State<PgPool>,
    Form(form): Form<RegisterForm>,
) -> Result<Redirect, (StatusCode, String)> {
    let email = form.email.trim().to_lowercase();

    if form.password != form.confirm_password {
        return Err((StatusCode::BAD_REQUEST, "Passwords do not match".into()));
    }

    let salt = SaltString::generate(&mut OsRng);

    let password_hash = argon2::Argon2::default()
        .hash_password(form.password.as_bytes(), &salt)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Password hashing error: {e}"),
            )
        })?
        .to_string();

    let result = sqlx::query!(
        r#"
        INSERT INTO users (email, password_hash)
        VALUES ($1, $2)
        "#,
        email,
        password_hash,
    )
    .execute(&pool)
    .await;

    match result {
        Ok(_) => Ok(Redirect::to("/login")),
        Err(e) => Err((StatusCode::BAD_REQUEST, format!("Could not create user: {e}"))),
    }
}

#[derive(Deserialize)]
pub struct LoginForm {
    email: String,
    password: String,
}

pub async fn login_submit(
    State(pool): State<PgPool>,
    jar: CookieJar,
    Form(form): Form<LoginForm>,
) -> Result<(CookieJar, Redirect), (StatusCode, String)> {
    let email = form.email.trim().to_lowercase();
    let user = sqlx::query!(
        r#"
        SELECT id, password_hash
        FROM users
        WHERE email = $1
        "#,
        email,
    )
    .fetch_optional(&pool)
    .await
    .map_err(internal_error)?;

    let user = match user {
        Some(u) => u,
        None => return Err((StatusCode::UNAUTHORIZED, "Invalid email or password".into())),
    };

    let parsed_hash = PasswordHash::new(&user.password_hash)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid stored password hash".into()))?;

    if argon2::Argon2::default()
        .verify_password(form.password.as_bytes(), &parsed_hash)
        .is_err()
    {
        return Err((StatusCode::UNAUTHORIZED, "Invalid email or password".into()));
    }

    let jwt_secret = env::var("JWT_SECRET")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "JWT_SECRET not set".into()))?;
    let jwt = JwtConfig::new(jwt_secret);

    let access_token = jwt
        .encode_access_token(user.id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("JWT encode failure: {e}")))?;

    let refresh_token: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();

    let now = Utc::now();
    let refresh_expires_at = now + Duration::hours(24);

    sqlx::query!(
        r#"
        INSERT INTO user_sessions (token, user_id, expires_at)
        VALUES ($1, $2, $3)
        "#,
        refresh_token,
        user.id,
        refresh_expires_at,
    )
    .execute(&pool)
    .await
    .map_err(internal_error)?;

    let secure = !cfg!(debug_assertions);

    let mut access_cookie = Cookie::new("access_token", access_token);
    access_cookie.set_http_only(true);
    access_cookie.set_secure(secure);
    access_cookie.set_same_site(SameSite::Lax);
    access_cookie.set_path("/");

    let mut refresh_cookie = Cookie::new("refresh_token", refresh_token);
    refresh_cookie.set_http_only(true);
    refresh_cookie.set_secure(secure);
    refresh_cookie.set_same_site(SameSite::Lax);
    refresh_cookie.set_path("/");

    let jar = jar.add(access_cookie).add(refresh_cookie);

    Ok((jar, Redirect::to("/budget")))
}

fn internal_error<E: std::fmt::Display>(e: E) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}