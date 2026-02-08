mod auth;
mod email;
mod family;
mod routes;

use dotenvy::dotenv;
use email::SmtpEmailer;
use sqlx::PgPool;
use std::{net::SocketAddr, sync::Arc};

use deadpool_redis::{Config as RedisConfig, Pool as RedisPool, Runtime};

#[derive(Clone)]
pub struct AppState {
    pub db_pool: PgPool,
    pub redis_pool: RedisPool,
    pub emailer: Arc<SmtpEmailer>,
    pub base_url: String,
}

fn must_env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("Missing env var: {key}"))
}

#[tokio::main]
async fn main() {
    dotenv().ok();

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL env var must be set");

    let db_pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to Postgres");

    println!("Connected to Postgres!");

    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

    let redis_cfg = RedisConfig::from_url(redis_url);

    let redis_pool: RedisPool = redis_cfg
        .create_pool(Some(Runtime::Tokio1))
        .expect("Failed to create Redis pool");

    println!("Connected to Redis!");

    let smtp_host = must_env("SMTP_HOST");
    let smtp_user = must_env("SMTP_USERNAME");
    let smtp_pass = must_env("SMTP_PASSWORD");
    let mail_from = must_env("MAIL_FROM");
    let base_url = must_env("APP_BASE_URL");

    let emailer = Arc::new(
        SmtpEmailer::new(&smtp_host, &smtp_user, &smtp_pass, &mail_from)
            .expect("Failed to init SMTP emailer"),
    );

    let state = AppState {
        db_pool: db_pool.clone(),
        redis_pool,
        emailer,
        base_url,
    };

    let app = routes::router(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("Server running at http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind to address");

    axum::serve(listener, app).await.expect("Server crashed");
}
