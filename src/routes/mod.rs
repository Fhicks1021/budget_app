use axum::{
    routing::{get, post},
    response::Html,
    Router,
};
use sqlx::PgPool;
use std::fs;
use tower_http::services::ServeDir;

mod budget;

pub fn router() -> Router<PgPool> {
    Router::new()
        .route("/", get(login_page))
        .route("/budget", get(index_page))
        .route("/handle_budget", post(budget::handle_budget)) 
        .nest_service("/static", ServeDir::new("static"))
}

async fn login_page() -> Html<String> {
    let html = fs::read_to_string("templates/login.html")
        .unwrap_or_else(|_| "<h1>login.html missing</h1>".to_string());
    Html(html)
}

async fn index_page() -> Html<String> {
    let html = fs::read_to_string("templates/budget_index.html")
        .unwrap_or_else(|_| "<h1>index.html missing</h1>".to_string());
    Html(html)
}