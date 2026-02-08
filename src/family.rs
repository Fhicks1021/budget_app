use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use sqlx::PgPool;

#[derive(Debug, FromRow, Clone)]
pub struct Family {
    pub id: i32,
    pub name: String,
    pub created_by_user: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, FromRow, Clone)]
pub struct FamilyMember {
    pub id: i32,
    pub family_id: i32,
    pub user_id: i32,
    pub role: String,
    pub status: String,
    pub joined_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FamilyRole {
    Adult,
    Dependent,
}

impl FamilyRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            FamilyRole::Adult => "adult",
            FamilyRole::Dependent => "dependent",
        }
    }

    pub fn from_str(role: &str) -> Option<Self> {
        match role {
            "adult" => Some(FamilyRole::Adult),
            "dependent" => Some(FamilyRole::Dependent),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FamilyContext {
    pub family_id: i32,
    pub role: FamilyRole,
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum FamilyError {
    NotInFamily,
    Db(sqlx::Error),
}

impl From<sqlx::Error> for FamilyError {
    fn from(err: sqlx::Error) -> Self {
        FamilyError::Db(err)
    }
}

pub async fn get_family_context(pool: &PgPool, user_id: i32) -> Result<FamilyContext, FamilyError> {
    let member: Option<FamilyMember> = sqlx::query_as::<_, FamilyMember>(
        r#"
        SELECT id, family_id, user_id, role, status, joined_at
        FROM family_members
        WHERE user_id = $1
          AND status = 'active'
        ORDER BY joined_at ASC
        LIMIT 1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    let member = member.ok_or(FamilyError::NotInFamily)?;

    let role = FamilyRole::from_str(&member.role).ok_or(FamilyError::NotInFamily)?;

    Ok(FamilyContext {
        family_id: member.family_id,
        role,
    })
}
