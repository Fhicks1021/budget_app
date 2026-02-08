use axum::{
    Router,
    extract::Query,
    extract::State,
    response::{Html, Redirect},
    routing::{get, post},
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use serde::Deserialize;
use std::fs;
use time::Duration as TimeDuration;
use tower_http::services::ServeDir;

use crate::AppState;
use crate::auth::{
    forgot_password, login::get_lockout_ttl, login_submit, logout_submit, refresh_session,
    register_submit, require_user, reset_password::reset_password_page, reset_password_submit,
};

mod budget;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/login", get(login_page).post(login_submit))
        .route("/register", get(register_page).post(register_submit))
        .route("/access_denied", get(access_denied))
        .route(
            "/incorrect_login_credentials",
            get(incorrect_login_credentials),
        )
        .route("/budget", get(budget_page))
        .route("/handle_budget", post(budget::handle_budget))
        .route("/auth/refresh", get(refresh_session))
        .route(
            "/auth/forgot-password",
            get(forgot_password).post(forgot_password::forgot_password_submit),
        )
        .route("/auth/logout", get(logout_submit))
        .route(
            "/dev/send-test-email",
            get(send_test_email).post(send_test_email),
        )
        .route(
            "/auth/reset-password",
            get(reset_password_page).post(reset_password_submit),
        )
        .nest_service("/static", ServeDir::new("static"))
        .with_state(state)
}

async fn budget_page(jar: CookieJar) -> Result<Html<String>, Redirect> {
    let _user_id = require_user(&jar)?;

    let html = fs::read_to_string("templates/budget_index.html")
        .unwrap_or_else(|_| "<h1>index.html missing</h1>".to_string());

    Ok(Html(html))
}

#[derive(Deserialize)]
struct LockoutQuery {
    email: Option<String>,
}

async fn incorrect_login_credentials(
    State(state): State<AppState>,
    Query(params): Query<LockoutQuery>,
) -> Html<String> {
    let ttl_seconds = if let Some(email) = params.email {
        get_lockout_ttl(&state.redis_pool, &email).await
    } else {
        0
    };

    let template = std::fs::read_to_string("templates/incorrect_login_credentials.html")
        .unwrap_or_else(|_| "<h1>incorrect_login_credentials.html missing</h1>".to_string());

    let html = template.replace("{{time-remaining}}", &ttl_seconds.to_string());

    Html(html)
}

async fn login_page(jar: CookieJar) -> (CookieJar, Html<String>) {
    let mut html = std::fs::read_to_string("templates/login.html")
        .unwrap_or_else(|_| "<h1>login.html missing</h1>".to_string());

    let flash = jar.get("flash").map(|c| c.value().to_string());

    let banner_html = match flash.as_deref() {
        Some("reset_sent") => "If that email exists, we sent a reset link.",
        _ => "",
    };

    html = html.replace("{{flash-banner}}", banner_html);

    let jar = if flash.is_some() {
        jar.remove(
            Cookie::build(("flash", ""))
                .path("/")
                .max_age(TimeDuration::seconds(0))
                .build(),
        )
    } else {
        jar
    };

    (jar, Html(html))
}

async fn register_page() -> Html<String> {
    let html = std::fs::read_to_string("templates/register.html")
        .unwrap_or_else(|_| "<h1>register.html missing</h1>".to_string());
    Html(html)
}

async fn forgot_password() -> Html<String> {
    let html = std::fs::read_to_string("templates/forgot_password.html")
        .unwrap_or_else(|_| "<h1>register.html missing</h1>".to_string());
    Html(html)
}

async fn access_denied() -> Html<String> {
    let html = std::fs::read_to_string("templates/access_denied.html")
        .unwrap_or_else(|_| "<h1>register.html missing</h1>".to_string());
    Html(html)
}

async fn send_test_email(State(state): State<AppState>) -> Html<String> {
    let to = std::env::var("TEST_EMAIL_TO")
        .unwrap_or_else(|_| std::env::var("MAIL_FROM").expect("Set TEST_EMAIL_TO or MAIL_FROM"));

    let link = format!("{}/dev/test", state.base_url);

    match state.emailer.send_password_reset(&to, &link) {
        Ok(_) => Html(format!("<p>Sent test email to {}</p>", to)),
        Err(e) => {
            eprintln!("Email send failed: {e:?}");
            Html(format!("<p>Failed to send email: {:?}</p>", e))
        }
    }
}
