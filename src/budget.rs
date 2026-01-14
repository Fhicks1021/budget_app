use axum::{
    extract::State,
    routing::{get, post},
    response::Html,
    Form, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::fs;

#[derive(Deserialize)]
struct BudgetInput {
    paycheck: Option<f64>,
    mortgage: Option<f64>,
    electric: Option<f64>,
    phone: Option<f64>,
    internet: Option<f64>,
    car_insurance: Option<f64>,
}

// #[derive(Serialize)]
// struct Category {
//     name: String,
//     amount: f64,
// }

struct ComputedBudget {
    paycheck: f64,
    mortgage: f64,
    electric: f64,
    phone: f64,
    internet: f64,
    car_insurance: f64,
    remaining: f64,
}

pub fn router() -> Router<PgPool> {
    Router::new()
        .route("/", get(index_page))
        .route("/budget", post(handle_budget))
        .route("/styles.css", get(styles))
        .route("/theme.js", get(theme_js))
}

// --------- Handlers ---------

async fn index_page() -> Html<String> {
    let html = fs::read_to_string("static/budget/html/index.html")
        .unwrap_or_else(|_| "<h1>index.html missing</h1>".to_string());
    Html(html)
}

async fn styles() -> String {
    fs::read_to_string("static/budget/css/styles.css")
        .unwrap_or_else(|_| "/* styles.css missing */".to_string())
}

async fn theme_js() -> String {
    fs::read_to_string("static/budget/js/theme.js")
        .unwrap_or_else(|_| "// theme.js missing".to_string())
}

async fn handle_budget(
    State(pool): State<PgPool>,
    Form(input): Form<BudgetInput>,
) -> Html<String> {
    let paycheck = input.paycheck.unwrap_or(0.0);
    let mortgage = input.mortgage.unwrap_or(0.0);
    let electric = input.electric.unwrap_or(0.0);
    let phone = input.phone.unwrap_or(0.0);
    let internet = input.internet.unwrap_or(0.0);
    let car_insurance = input.car_insurance.unwrap_or(0.0);

    let spent = mortgage + electric + phone + internet + car_insurance;
    let remaining = paycheck - spent;

    let computed = ComputedBudget {
        paycheck,
        mortgage,
        electric,
        phone,
        internet,
        car_insurance,
        remaining,
    };

    if let Err(e) = save_budget_to_db(&pool, &computed).await {
        eprintln!("Failed to save budget to DB: {e}");
    }

    let template = fs::read_to_string("static/budget/html/result.html")
        .unwrap_or_else(|_| "<h1>result.html missing</h1>".to_string());

    let page = template
        .replace("{{paycheck}}", &format!("{:.2}", computed.paycheck))
        .replace("{{mortgage}}", &format!("{:.2}", computed.mortgage))
        .replace("{{electric}}", &format!("{:.2}", computed.electric))
        .replace("{{phone}}", &format!("{:.2}", computed.phone))
        .replace("{{internet}}", &format!("{:.2}", computed.internet))
        .replace("{{car_insurance}}", &format!("{:.2}", computed.car_insurance))
        .replace("{{remaining}}", &format!("{:.2}", computed.remaining));

    Html(page)
}

async fn save_budget_to_db(pool: &PgPool, b: &ComputedBudget) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;

    let row = sqlx::query(
        r#"
        INSERT INTO budgets (paycheck, mortgage, electric, phone, internet, car_insurance, remaining)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id
        "#,
    )
    .bind(b.paycheck)
    .bind(b.mortgage)
    .bind(b.electric)
    .bind(b.phone)
    .bind(b.internet)
    .bind(b.car_insurance)
    .bind(b.remaining)
    .fetch_one(&mut *tx)
    .await?;

    let budget_id: i32 = row.get("id");

    let categories = vec![
        ("Mortgage", b.mortgage),
        ("Electric", b.electric),
        ("Phone", b.phone),
        ("Internet", b.internet),
        ("Car Insurance", b.car_insurance),
    ];

    for (name, amount) in categories {
        if amount != 0.0 {
            sqlx::query(
                r#"
                INSERT INTO budget_categories (budget_id, name, amount)
                VALUES ($1, $2, $3)
                "#,
            )
            .bind(budget_id)
            .bind(name)
            .bind(amount)
            .execute(&mut *tx)
            .await?;
        }
    }

    tx.commit().await?;
    Ok(())
}
