use axum::{
    http::{self, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};

use chrono::{Utc, TimeZone};
use jsonwebtoken::{decode, encode, errors::Error, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CurrentUser {
    pub name: String,
    pub email: String,
    pub username: String,
    pub id: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub username: String,
    pub exp: i64,
}

pub struct AuthError {
    message: String,
    status_code: StatusCode,
}

#[derive(Deserialize)]
pub struct MyRequestBody {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize, Debug)]
pub struct LoginResponse {
    pub token: String,
    pub username: String,
}

pub trait UserData {
    fn get_user_by_email(&self, email: &str) -> Option<CurrentUser>;
    fn get_user_by_id(&self, _user_id: &str) -> Option<CurrentUser>;
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let body = Json(json!({
            "error": self.message,
        }));

        (self.status_code, body).into_response()
    }
}

pub async fn verify_user<B, D>(
    mut req: Request<B>,
    user_db: D,
    jwt_secret: &str,
    next: Next<B>,
) -> Result<Response, AuthError>
where
    D: UserData,
{
    let auth_header = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok());

    let auth_header = auth_header.ok_or_else(|| AuthError {
        message: "Missing authorization".to_string(),
        status_code: StatusCode::UNAUTHORIZED,
    })?;

    if let Ok(current_user) = authorize_current_user(auth_header, user_db, jwt_secret).await {
        req.extensions_mut().insert(current_user);
        Ok(next.run(req).await)
    } else {
        Err(AuthError {
            message: "Invalid token".to_string(),
            status_code: StatusCode::UNAUTHORIZED,
        })
    }
}

pub async fn auth_token_encode(
    user: CurrentUser,
    jwt_secret: &str,
    expiry_time_stamp: i64,
) -> Result<String, Error> {
    let claims = Claims {
        username: user.username,
        exp: expiry_time_stamp,
        sub: user.id,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_ref()),
    )?;
    Ok(token)
}

pub async fn auth_token_decode(
    token: String,
    jwt_secret: &str,
) -> Result<jsonwebtoken::TokenData<Claims>, String> {
    let decoding_key = DecodingKey::from_secret(jwt_secret.as_ref());
    let validation = Validation::default();

    let claims: jsonwebtoken::TokenData<Claims> =
        decode::<Claims>(&token, &decoding_key, &validation)
            .map_err(|e| format!("Error decoding token: {}", e))?;
    Ok(claims)
}

async fn authorize_current_user<D>(
    _auth_token: &str,
    user_db: D,
    jwt_secret: &str,
) -> Result<CurrentUser, String>
where
    D: UserData,
{
    let mut authorization_with_bearer = _auth_token.split_whitespace();

    if _auth_token.is_empty() {
        return Err("Authorization must be in the format: bearer {token}".to_string());
    }

    let bearer = authorization_with_bearer.next();
    let token = authorization_with_bearer.next();

    if bearer != Some("Bearer") || token.is_none() {
        return Err("Authorization must be in the format: bearer {token}".to_string());
    }

    let decode = auth_token_decode(token.unwrap().to_string(), jwt_secret).await;

    match decode {
        Ok(token_data) => {
            let user = user_db.get_user_by_id(&token_data.claims.sub);
            if let Some(user) = user {
                Ok(user)
            } else {
                Err("Invalid user ID".to_string())
            }
        }
        Err(err) => Err(err.to_string()),
    }
}

pub async fn login<D>(body: Json<MyRequestBody>, user_db: D, jwt_secret: &str) -> impl IntoResponse
where
    D: UserData,
{
    let email = &body.email;
    let password = &body.password;

    let current_timestamp = Utc::now().timestamp();
    let timestamp_in_two_days = Utc
        .timestamp_opt(current_timestamp + 2 * 24 * 60 * 60, 0)
        .unwrap(); // 2days

    if let Some(user) = user_db.get_user_by_email(email) {
        if email == &user.email && password == &user.password {
            let gentoken =
                auth_token_encode(user.clone(), jwt_secret, timestamp_in_two_days.timestamp())
                    .await;
            let response = Json(json!({
                "token": gentoken.unwrap_or_else(|_| String::from("default_token")),
                "username": user.username,
            }));
            return Ok(response);
        }
    }

    let error = AuthError {
        message: "Invalid username or password".to_string(),
        status_code: StatusCode::UNAUTHORIZED,
    };
    Err(error)
}