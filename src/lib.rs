use axum::{
    http::{self, Request, StatusCode, request},
    middleware::Next,
    response::{IntoResponse, Response},
    Json, body::{HttpBody, Body},
};

pub use jsonwebtoken::{
    decode, encode, errors::Error, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
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

#[derive(Debug, Serialize, Deserialize, Clone)]
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
pub struct RequestBody {
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
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let body = Json(json!({
            "error": self.message,
        }));

        (self.status_code, body).into_response()
    }
}

pub async fn verify_user(
    mut req: Request<Body>,
    key: &DecodingKey,
    validation: Validation,
    next: Next,
) -> Result<Response, AuthError> {
    let auth_header = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok());

    let auth_header = auth_header.ok_or_else(|| AuthError {
        message: "Missing authorization".to_string(),
        status_code: StatusCode::UNAUTHORIZED,
    })?;

    if let Ok(claims) = authorize_current_user(auth_header, key, validation).await {
        req.extensions_mut().insert(claims);
        Ok(next.run(req).await)
    } else {
        Err(AuthError {
            message: "Invalid token".to_string(),
            status_code: StatusCode::UNAUTHORIZED,
        })
    }
}

pub struct EncodingContext {
    pub key: EncodingKey,
    pub validation: Validation,
    pub header: Header,
}

pub struct DecodingContext {
    pub key: DecodingKey,
    pub validation: Validation,
    pub header: Header,
}

pub struct Queryparams {
    token: String
}

pub async fn refresh_token<B>(
    query_params: Queryparams,
    encoding_info: EncodingContext,
    decoding_info: DecodingContext,
    claims: Claims,
) -> impl IntoResponse {

    let token = query_params.token;
    if let Ok(_) = auth_token_decode(token, &decoding_info.key, decoding_info.validation).await {
        Json(json!({"token": auth_token_encode(claims, &encoding_info.header, &encoding_info.key).await.expect("Error encoding token")}))
    } else {
        Json(json!({"message": "Error decoding token"}))
    }
}

async fn authorize_current_user(
    auth_token: &str,
    key: &DecodingKey,
    validation: Validation,
) -> Result<Claims, String> {
    let mut authorization_with_bearer = auth_token.split_whitespace();

    if auth_token.is_empty() {
        return Err("Authorization must be in the format: bearer {token}".to_string());
    }

    let bearer = authorization_with_bearer.next();
    let token = authorization_with_bearer.next();

    if bearer != Some("Bearer") || token.is_none() {
        return Err("Authorization must be in the format: bearer {token}".to_string());
    }

    let decode = auth_token_decode(token.unwrap().to_string(), key, validation).await;

    match decode {
        Ok(token_data) => Ok(token_data.claims),
        Err(err) => Err(err.to_string()),
    }
}

pub async fn auth_token_encode(
    claims: Claims,
    header: &Header,
    key: &EncodingKey,
) -> Result<String, Error> {
    let token = encode(&header, &claims, key)?;
    Ok(token)
}

pub async fn auth_token_decode(
    token: String,
    key: &DecodingKey,
    validation: Validation,
) -> Result<jsonwebtoken::TokenData<Claims>, String> {
    let claims: jsonwebtoken::TokenData<Claims> = decode::<Claims>(&token, key, &validation)
        .map_err(|e| format!("Error decoding token: {}", e))?;
    Ok(claims)
}

pub async fn login<D>(
    body: Json<RequestBody>,
    user_data: D,
    jwt_secret: &str,
    expiry_timestamp: i64,
) -> impl IntoResponse
where
    D: UserData,
{
    let email = &body.email;
    let password = &body.password;

    if let Some(user) = user_data.get_user_by_email(email) {
        if email == &user.email && password == &user.password {
            let header = &Header::default();
            let key = EncodingKey::from_secret(jwt_secret.as_ref());

            let claims = Claims {
                sub: user.id,
                username: user.username.clone(),
                exp: expiry_timestamp,
            };
            let gentoken = auth_token_encode(claims, header, &key).await;
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
