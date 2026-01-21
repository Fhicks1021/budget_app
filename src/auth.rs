use axum::{
    extract::{Form, State},
    http::StatusCode,
    response::Redirect,
};

use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, decode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use password_hash::{
    rand_core::OsRng,
    PasswordHash,
    PasswordHasher,
    PasswordVerifier,
    SaltString,
};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::env;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: i32,
    pub exp: i64,
    pub iat: i64,
}

#[derive(Clone)]
pub struct JwtConfig {
    pub secret: String,
    pub access_token_minutes: i64,
}

impl JwtConfig {
    pub fn new(secret: String) -> Self {
        Self {
            secret,
            access_token_minutes: 20,
        }
    }

    pub fn encode_access_token(&self, user_id: i32) -> jsonwebtoken::errors::Result<String> {
        let now = Utc::now();
        let exp = now + Duration::minutes(self.access_token_minutes);

        let claims = Claims {
            sub: user_id,
            iat: now.timestamp(),
            exp: exp.timestamp(),
        };

        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(self.secret.as_bytes()),
        )
    }

    pub fn decode_access_token(&self, token: &str) -> jsonwebtoken::errors::Result<Claims> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;

        decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret.as_bytes()),
            &validation,
        )
        .map(|data| data.claims)
    }
}

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
        form.email,
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
    let user = sqlx::query!(
        r#"
        SELECT id, password_hash
        FROM users
        WHERE email = $1
        "#,
        form.email,
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

pub fn require_user(jar: &CookieJar) -> Result<i32, Redirect> {
    let cookie = match jar.get("access_token") {
        Some(c) => c,
        None => {
            // No access token → try refresh flow
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
    let new_expires_at = now + Duration::hours(24);

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