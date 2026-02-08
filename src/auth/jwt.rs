use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: i32,
    pub exp: i64,
    pub iat: i64,
}

#[derive(Clone)]
pub struct JwtConfig {
    pub secret: String,
    pub access_token_minutes: i64,
}

impl JwtConfig {
    pub fn new(secret: String) -> Self {
        Self {
            secret,
            access_token_minutes: 20,
        }
    }

    pub fn encode_access_token(&self, user_id: i32) -> jsonwebtoken::errors::Result<String> {
        let now = Utc::now();
        let exp = now + Duration::minutes(self.access_token_minutes);

        let claims = Claims {
            sub: user_id,
            iat: now.timestamp(),
            exp: exp.timestamp(),
        };

        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(self.secret.as_bytes()),
        )
    }

    pub fn decode_access_token(&self, token: &str) -> jsonwebtoken::errors::Result<Claims> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;

        decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret.as_bytes()),
            &validation,
        )
        .map(|data| data.claims)
    }
}
