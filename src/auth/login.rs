use axum::{
    extract::{Form, State},
    http::StatusCode,
    response::Redirect,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use chrono::{Duration, Utc};
use serde::Deserialize;
use sqlx::PgPool;
use std::env;

use deadpool_redis::{Pool as RedisPool, redis::AsyncCommands};
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng};
use rand::{Rng, distributions::Alphanumeric};
use urlencoding::encode;

use crate::AppState;
use crate::auth::JwtConfig;

#[derive(Deserialize)]
pub struct RegisterForm {
    email: String,
    password: String,
    confirm_password: String,
}

pub async fn register_submit(
    State(state): State<AppState>,
    Form(form): Form<RegisterForm>,
) -> Result<Redirect, (StatusCode, String)> {
    let pool: &PgPool = &state.db_pool;
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

    let mut tx = pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let user = sqlx::query!(
        r#"
        INSERT INTO users (email, password_hash)
        VALUES ($1, $2)
        RETURNING id
        "#,
        email,
        password_hash,
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Could not create user: {e}"),
        )
    })?;

    let user_id = user.id;

    let family = sqlx::query!(
        r#"
        INSERT INTO families (name, created_by_user)
        VALUES ($1, $2)
        RETURNING id
        "#,
        format!("{}'s Family", email),
        user_id,
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Could not create family: {e}"),
        )
    })?;

    let family_id = family.id;

    sqlx::query!(
        r#"
        INSERT INTO family_members (family_id, user_id, role, status)
        VALUES ($1, $2, 'adult', 'active')
        "#,
        family_id,
        user_id,
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Could not add family member: {e}"),
        )
    })?;

    tx.commit().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Commit error: {e}"),
        )
    })?;

    Ok(Redirect::to("/login"))
}

pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);

    let password_hash = argon2::Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("Password hashing error: {e}"))?
        .to_string();

    Ok(password_hash)
}

fn login_attempts_key(email: &str) -> String {
    format!("login_attempts:{}", email)
}

async fn is_locked_out(redis_pool: &RedisPool, email: &str) -> Result<bool, Redirect> {
    let mut conn = redis_pool.get().await.map_err(|e| {
        eprintln!("Redis pool error in is_locked_out: {e}");
        Redirect::to("/incorrect_login_credentials?email={}")
    })?;

    let key = login_attempts_key(email);

    let attempts: i32 = conn.get(&key).await.unwrap_or(0);
    Ok(attempts >= 5)
}

async fn record_failed_attempt(redis_pool: &RedisPool, email: &str) -> Result<i32, Redirect> {
    let mut conn = redis_pool.get().await.map_err(|e| {
        eprintln!("Redis pool error in record_failed_attempt: {e}");
        Redirect::to("/incorrect_login_credentials")
    })?;

    let key = login_attempts_key(email);

    let attempts: i32 = conn.incr(&key, 1).await.map_err(|e| {
        eprintln!("Redis INCR error in record_failed_attempt: {e}");
        Redirect::to("/incorrect_login_credentials")
    })?;

    if attempts == 1 {
        let _: () = conn.expire(&key, 120).await.map_err(|e| {
            eprintln!("Redis EXPIRE error in record_failed_attempt: {e}");
            Redirect::to("/incorrect_login_credentials")
        })?;
    }

    Ok(attempts)
}

pub async fn get_lockout_ttl(redis_pool: &RedisPool, email: &str) -> i64 {
    let mut conn = match redis_pool.get().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Redis pool error in get_lockout_ttl: {e}");
            return 0;
        }
    };

    let key = login_attempts_key(email);

    let ttl: i64 = match conn.ttl(&key).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Redis TTL error in get_lockout_ttl: {e}");
            return 0;
        }
    };

    if ttl < 0 { 0 } else { ttl }
}

#[derive(Deserialize)]
pub struct LoginForm {
    email: String,
    password: String,
}

pub async fn login_submit(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<LoginForm>,
) -> Result<(CookieJar, Redirect), Redirect> {
    let pool: &PgPool = &state.db_pool;

    let email = form.email.trim().to_lowercase();

    eprintln!("login attempt for email = {:?}", email);
    if is_locked_out(&state.redis_pool, &email).await? {
        let loc = format!("/incorrect_login_credentials?email={}", encode(&email));
        return Err(Redirect::to(&loc));
    }

    let user = sqlx::query!(
        r#"
        SELECT id, password_hash
        FROM users
        WHERE email = $1
        "#,
        email,
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        eprintln!("DB error in login_submit: {e}");
        Redirect::to("/incorrect_login_credentials")
    })?;

    let user = match user {
        Some(u) => u,
        None => {
            let attempts = record_failed_attempt(&state.redis_pool, &email).await?;

            if attempts >= 5 {
                let loc = format!("/incorrect_login_credentials?email={}", encode(&email));
                return Err(Redirect::to(&loc));
            }

            return Err(Redirect::to("/login"));
        }
    };

    let parsed_hash = PasswordHash::new(&user.password_hash).map_err(|e| {
        eprintln!("Invalid stored password hash in login_submit: {e}");
        Redirect::to("/incorrect_login_credentials")
    })?;

    if argon2::Argon2::default()
        .verify_password(form.password.as_bytes(), &parsed_hash)
        .is_err()
    {
        let attempts = record_failed_attempt(&state.redis_pool, &email).await?;

        if attempts >= 5 {
            let loc = format!("/incorrect_login_credentials?email={}", encode(&email));
            return Err(Redirect::to(&loc));
        }

        return Err(Redirect::to("/login"));
    }

    let jwt_secret = env::var("JWT_SECRET").map_err(|e| {
        eprintln!("JWT_SECRET not set in login_submit: {e}");
        Redirect::to("/incorrect_login_credentials")
    })?;
    let jwt = JwtConfig::new(jwt_secret);

    let access_token = jwt.encode_access_token(user.id).map_err(|e| {
        eprintln!("JWT encode failure in login_submit: {e}");
        Redirect::to("/incorrect_login_credentials")
    })?;

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
    .execute(pool)
    .await
    .map_err(|e| {
        eprintln!("DB insert error in login_submit: {e}");
        Redirect::to("/incorrect_login_credentials")
    })?;

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
