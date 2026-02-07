use axum::{
    extract::State,
    response::Html,
    Form,
    response::Redirect
};
use serde::Deserialize;
use sqlx::{PgPool, Row};
use std::fs;
use axum_extra::extract::CookieJar;

use crate::AppState;
use crate::auth::require_user;
use crate::family::{get_family_context, FamilyRole};

#[derive(Deserialize)]
pub struct BudgetInput {
    #[serde(deserialize_with = "empty_string_as_none")]
    pub paycheck: Option<f64>,
    #[serde(deserialize_with = "empty_string_as_none")]
    pub mortgage: Option<f64>,
    #[serde(deserialize_with = "empty_string_as_none")]
    pub electric: Option<f64>,
    #[serde(deserialize_with = "empty_string_as_none")]
    pub phone: Option<f64>,
    #[serde(deserialize_with = "empty_string_as_none")]
    pub internet: Option<f64>,
    #[serde(deserialize_with = "empty_string_as_none")]
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

fn empty_string_as_none<'de, D>(deserializer: D) -> Result<Option<f64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: Option<String> = Option::deserialize(deserializer)?;
    Ok(match s {
        None => None,
        Some(ref v) if v.trim().is_empty() => None,
        Some(v) => v
            .parse::<f64>()
            .map(Some)
            .map_err(serde::de::Error::custom)?,
    })
}

pub async fn handle_budget(
    jar: CookieJar,
    State(state): State<AppState>,
    Form(input): Form<BudgetInput>,
) -> Result<Html<String>, Redirect> {
    let pool: &PgPool = &state.db_pool;
    let user_id = require_user(&jar)?;

    let family_ctx = match get_family_context(pool, user_id).await {
        Ok(ctx) => ctx,
        Err(_) => {
            return Err(Redirect::to("/login"));
        }
    };

    if matches!(family_ctx.role, FamilyRole::Dependent) {
        return Err(Redirect::to("/access-denied"));
    }

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

    if matches!(family_ctx.role, FamilyRole::Adult) {
        if let Err(e) = save_budget_to_db(
            pool,
            family_ctx.family_id,
            user_id,
            &computed,
        )
        .await
        {
            eprintln!("Failed to save budget to DB: {e}");
        }
    } else {
        eprintln!(
            "Dependent user {} computed a budget but did not persist",
            user_id
        );
    }

    let template = fs::read_to_string("templates/budget_result.html")
        .unwrap_or_else(|_| "<h1>result.html missing</h1>".to_string());

    let page = template
        .replace("{{paycheck}}", &format!("{:.2}", computed.paycheck))
        .replace("{{mortgage}}", &format!("{:.2}", computed.mortgage))
        .replace("{{electric}}", &format!("{:.2}", computed.electric))
        .replace("{{phone}}", &format!("{:.2}", computed.phone))
        .replace("{{internet}}", &format!("{:.2}", computed.internet))
        .replace("{{car_insurance}}", &format!("{:.2}", computed.car_insurance))
        .replace("{{remaining}}", &format!("{:.2}", computed.remaining));

    Ok(Html(page))
}


async fn save_budget_to_db(
    pool: &PgPool,
    family_id: i32,
    user_id: i32,
    computed: &ComputedBudget,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;

    let row = sqlx::query(
        r#"
        INSERT INTO budget (
            family_id,
            user_id,
            paycheck,
            mortgage,
            electric,
            phone,
            internet,
            car_insurance,
            remaining
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id
        "#,
    )
    .bind(family_id)
    .bind(user_id)
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

