mod routes;

use dotenvy::dotenv;
use sqlx::PgPool;
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    dotenv().ok();
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL env var must be set");

    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to Postgres");

    println!("Connected to Postgres!");

    let app = routes::router().with_state(pool);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("Server running at http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind to address");

    axum::serve(listener, app)
        .await
        .expect("Server crashed");
}
