use crate::AppState;
use axum::{Form, extract::State, response::Redirect};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
pub struct ForgotPasswordForm {
    email: String,
}

pub async fn forgot_password_submit(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(input): Form<ForgotPasswordForm>,
) -> (CookieJar, Redirect) {
    let generic_redirect = Redirect::to("/login");

    let jar = jar.add(
        Cookie::build(("flash", "reset_sent"))
            .path("/")
            .http_only(true)
            .same_site(SameSite::Lax)
            .build(),
    );

    let email = input.email.trim().to_lowercase();
    if email.is_empty() {
        return (jar, generic_redirect);
    }

    let user_id: Option<i32> = match sqlx::query_scalar::<_, i32>(
        r#"
        SELECT id
        FROM users
        WHERE lower(email) = $1
        "#,
    )
    .bind(&email)
    .fetch_optional(&state.db_pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!("forgot_password: user lookup failed: {e:?}");
            return (jar, generic_redirect);
        }
    };

    let Some(user_id) = user_id else {
        eprintln!("forgot_password: no user found for {}", email);
        return (jar, generic_redirect);
    };

    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let token = URL_SAFE_NO_PAD.encode(raw);

    let token_hash = {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        format!("{:x}", hasher.finalize())
    };

    let expires_at = Utc::now() + Duration::minutes(30);

    if let Err(e) = sqlx::query(
        r#"
        INSERT INTO password_resets (user_id, token_hash, expires_at)
        VALUES ($1, $2, $3)
        "#,
    )
    .bind(user_id)
    .bind(&token_hash)
    .bind(expires_at)
    .execute(&state.db_pool)
    .await
    {
        eprintln!("forgot_password: insert token failed: {e:?}");
        return (jar, generic_redirect);
    }

    let reset_link = format!("{}/auth/reset-password?token={}", state.base_url, token);

    if let Err(e) = state.emailer.send_password_reset(&email, &reset_link) {
        eprintln!("forgot_password: email send failed: {e:?}");
    }

    (jar, generic_redirect)
}
