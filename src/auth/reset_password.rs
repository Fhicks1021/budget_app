use axum::{
    Form,
    extract::{Query, State},
    response::Html,
    response::Redirect,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;

use crate::AppState;
use crate::auth::login::hash_password;

#[derive(Deserialize)]
pub struct ResetQuery {
    pub token: String,
}

pub async fn reset_password_page(
    State(state): State<AppState>,
    Query(q): Query<ResetQuery>,
) -> Html<String> {
    let token = q.token.trim();
    if token.is_empty() {
        return Html("Invalid reset link.".to_string());
    }

    let token_hash = {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        format!("{:x}", hasher.finalize())
    };

    let valid: bool = match sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM password_resets
            WHERE token_hash = $1
              AND used_at IS NULL
              AND expires_at > now()
        )
        "#,
    )
    .bind(&token_hash)
    .fetch_one(&state.db_pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!("reset_password_page: db error: {e:?}");
            false
        }
    };

    if !valid {
        return Html("This reset link is invalid or expired.".to_string());
    }

    let template = fs::read_to_string("templates/reset_password.html")
        .unwrap_or_else(|_| "<h1>reset_password.html missing</h1>".to_string());

    let html = template
        .replace(
            "{{token}}",
            &html_escape::encode_double_quoted_attribute(token),
        )
        .replace("{{flash-banner}}", "");

    Html(html)
}

#[derive(Deserialize)]
pub struct ResetPasswordForm {
    pub token: String,
    pub password: String,
    pub password_confirm: String,
}

pub async fn reset_password_submit(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(input): Form<ResetPasswordForm>,
) -> (CookieJar, Redirect) {
    let redirect_login = Redirect::to("/login");

    let token = input.token.trim();
    if token.is_empty() {
        return (jar, redirect_login);
    }

    if input.password.trim().is_empty() || input.password_confirm.trim().is_empty() {
        return (jar, Redirect::to("/auth/reset-password?token="));
    }

    if input.password != input.password_confirm {
        let jar = jar.add(
            Cookie::build(("flash", "password_mismatch"))
                .path("/")
                .http_only(true)
                .same_site(SameSite::Lax)
                .build(),
        );

        return (
            jar,
            Redirect::to(&format!("/auth/reset-password?token={}", token)),
        );
    }

    let token_hash = {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        format!("{:x}", hasher.finalize())
    };

    let user_id: Option<i32> = match sqlx::query_scalar(
        r#"
		SELECT user_id
		FROM password_resets
		WHERE token_hash = $1
		  AND used_at IS NULL
		  AND expires_at > now()
		"#,
    )
    .bind(&token_hash)
    .fetch_optional(&state.db_pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!("reset_password_submit: token lookup failed: {e:?}");
            None
        }
    };

    let Some(user_id) = user_id else {
        let jar = jar.add(
            Cookie::build(("flash", "reset_invalid"))
                .path("/")
                .http_only(true)
                .same_site(SameSite::Lax)
                .build(),
        );

        return (jar, redirect_login);
    };

    let new_hash = match hash_password(&input.password) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("reset_password_submit: password hash failed: {e:?}");
            return (jar, redirect_login);
        }
    };

    let mut tx = match state.db_pool.begin().await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("reset_password_submit: tx begin failed: {e:?}");
            return (jar, redirect_login);
        }
    };

    if let Err(e) = sqlx::query(
        r#"
		UPDATE users
		SET password_hash = $1
		WHERE id = $2
		"#,
    )
    .bind(&new_hash)
    .bind(user_id)
    .execute(&mut *tx)
    .await
    {
        eprintln!("reset_password_submit: update users failed: {e:?}");
        return (jar, redirect_login);
    }

    if let Err(e) = sqlx::query(
        r#"
		UPDATE password_resets
		SET used_at = now()
		WHERE token_hash = $1
		"#,
    )
    .bind(&token_hash)
    .execute(&mut *tx)
    .await
    {
        eprintln!("reset_password_submit: mark token used failed: {e:?}");
        return (jar, redirect_login);
    }

    if let Err(e) = tx.commit().await {
        eprintln!("reset_password_submit: tx commit failed: {e:?}");
        return (jar, redirect_login);
    }

    let jar = jar.add(
        Cookie::build(("flash", "password_reset_success"))
            .path("/")
            .http_only(true)
            .same_site(SameSite::Lax)
            .build(),
    );

    (jar, redirect_login)
}
