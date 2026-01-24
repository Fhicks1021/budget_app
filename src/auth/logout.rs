use axum::{
    extract::State,
    response::Redirect,
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use sqlx::PgPool;


pub async fn logout_submit(
    State(pool): State<PgPool>,
    jar: CookieJar,
) -> (CookieJar, Redirect) {
    if let Some(refresh_cookie) = jar.get("refresh_token") {
        let refresh_token = refresh_cookie.value().to_string();

        let _ = sqlx::query!(
            r#"
            DELETE FROM user_sessions
            WHERE token = $1
            "#,
            refresh_token,
        )
        .execute(&pool)
        .await;
    }

    let mut access_cookie = Cookie::named("access_token");
    access_cookie.set_path("/");

    let mut refresh_cookie = Cookie::named("refresh_token");
    refresh_cookie.set_path("/");

    let jar = jar
    .remove(access_cookie)
    .remove(refresh_cookie);

    (jar, Redirect::to("/login"))
}