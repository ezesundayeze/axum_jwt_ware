use axum::{
    body::Body,
    http::{self, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};

pub use jsonwebtoken::{
    decode, encode, errors::Error, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
pub use serde::{Deserialize, Serialize};
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
    fn get_user_by_email(
        &self,
        email: &str,
    ) -> impl std::future::Future<Output = Option<CurrentUser>> + Send;
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

#[derive(Deserialize)]
pub struct RefreshBody {
    token: String,
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

    let (bearer, token) = (
        authorization_with_bearer.next(),
        authorization_with_bearer.next(),
    );

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
    jwt_secret: String,
    refresh_jwt_secret: String,
    expiry_timestamp: i64,
) -> impl IntoResponse
where
    D: UserData,
{
    let email = &body.email;
    let password = &body.password;

    if let Some(user) = user_data.get_user_by_email(email).await {
        if email == &user.email && password == &user.password {
            let header = &Header::default();
            let key = EncodingKey::from_secret(jwt_secret.as_ref());
            let refresh_key = EncodingKey::from_secret(refresh_jwt_secret.as_ref());
            let refresh_header = &Header::default();

            let claims = Claims {
                sub: user.id,
                username: user.username.clone(),
                exp: expiry_timestamp,
            };

            let access_token = auth_token_encode(claims.clone(), header, &key).await;
            let refresh_token = auth_token_encode(claims, refresh_header, &refresh_key).await;
            let response = Json(json!({
                "access_token": access_token.expect("Invalid token"),
                "username": user.username,
                "refresh_token": refresh_token.expect("invalid refresh token")
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

pub async fn refresh_token(
    body: Json<RefreshBody>,
    encoding_context: EncodingContext,
    decoding_context: DecodingContext,
    new_claims: Option<Claims>,
) -> impl IntoResponse {
    let token = &body.token;

    match auth_token_decode(
        token.to_string(),
        &decoding_context.key,
        decoding_context.validation,
    )
    .await
    {
        Ok(mut claims) => {
            match new_claims {
                Some(new) => claims.claims = new,
                None => {}
            }
            match auth_token_encode(
                claims.claims,
                &encoding_context.header,
                &encoding_context.key,
            )
            .await
            {
                Ok(new_token) => Ok(Json(json!({"access_token": new_token}))),
                Err(_) => Err(AuthError {
                    message: "Invalid refresh token".to_string(),
                    status_code: StatusCode::UNAUTHORIZED,
                }),
            }
        }

        Err(_) => Err(AuthError {
            message: "Invalid refresh token".to_string(),
            status_code: StatusCode::UNAUTHORIZED,
        }),
    }
}
