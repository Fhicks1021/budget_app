use axum::{
    routing::{get, post},
    response::{Html, Redirect},
    Router,
    http::StatusCode,
    response::IntoResponse,
    extract::State,
    extract::Query,
};
use axum_extra::extract::cookie::CookieJar;
use std::fs;
use sqlx::PgPool;
use tower_http::services::ServeDir;
use serde::Deserialize;
use deadpool_redis::Pool as RedisPool;

use crate::family::{get_family_context, FamilyRole};
use crate::auth::{
           Claims,
           login_submit,
           login::get_lockout_ttl,
           register_submit,
            refresh_session,
            logout_submit,
            require_user
};

mod budget;
use crate::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/login", get(login_page).post(login_submit))
        .route("/register", get(register_page).post(register_submit))
        .route("/access_denied", get(access_denied))
        .route("/incorrect_login_credentials", get(incorrect_login_credentials))
        .route("/budget", get(budget_page))
        .route("/handle_budget", post(budget::handle_budget))
        .route("/auth/refresh", get(refresh_session))
        .route("/auth/forgot-password", get(forgot_password))
        .route("/auth/logout", get(logout_submit))
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

async fn login_page() -> Html<String> {
    let html = std::fs::read_to_string("templates/login.html")
        .unwrap_or_else(|_| "<h1>login.html missing</h1>".to_string());
    Html(html)
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

async fn family_auth(
    State(pool): State<PgPool>,
    claims: Claims,
) -> Result<impl IntoResponse, StatusCode> {
    let ctx = get_family_context(&pool, claims.sub)
        .await
        .map_err(|_| StatusCode::FORBIDDEN)?;

    Ok("ok")
}