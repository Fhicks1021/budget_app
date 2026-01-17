use axum::{
    extract::State,
    response::Html,
    Form,
};
use serde::Deserialize;
use sqlx::{PgPool, Row};
use std::fs;

#[derive(Deserialize)]
pub struct BudgetInput {
    pub paycheck: Option<f64>,
    pub mortgage: Option<f64>,
    pub electric: Option<f64>,
    pub phone: Option<f64>,
    pub internet: Option<f64>,
    pub car_insurance: Option<f64>,
}

struct ComputedBudget {
    paycheck: f64,
    mortgage: f64,
    electric: f64,
    phone: f64,
    internet: f64,
    car_insurance: f64,
    remaining: f64,
}

pub async fn handle_budget(
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

async fn save_budget_to_db(pool: &PgPool, computed: &ComputedBudget) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;

    let row = sqlx::query(
        r#"
        INSERT INTO budgets (paycheck, mortgage, electric, phone, internet, car_insurance, remaining)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id
        "#,
    )
    .bind(computed.paycheck)
    .bind(computed.mortgage)
    .bind(computed.electric)
    .bind(computed.phone)
    .bind(computed.internet)
    .bind(computed.car_insurance)
    .bind(computed.remaining)
    .fetch_one(&mut *tx)
    .await?;

    let budget_id: i32 = row.get("id");

    let categories = vec![
        ("Mortgage", computed.mortgage),
        ("Electric", computed.electric),
        ("Phone", computed.phone),
        ("Internet", computed.internet),
        ("Car Insurance", computed.car_insurance),
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
