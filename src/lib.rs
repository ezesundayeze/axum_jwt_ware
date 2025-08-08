//! # Axum JWT Ware
//!
//! Simple Axum + JWT authentication middleware with implemented Login and refresh token.
//!
//! ## Goal
//!
//! I aim to simplify the process for developers/indie hackers to focus on writing their core business logic
//! when starting a new project, rather than spending time rewriting authentication.

use axum::{
    http::{self, Request, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
pub use jsonwebtoken::{
    decode, encode, errors::Error, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
pub use serde::{Deserialize, Serialize};
use serde_json::json;

/// The user object that will be returned from the `UserData` trait.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CurrentUser {
    pub name: String,
    pub email: String,
    pub username: String,
    pub id: String,
}

#[cfg(test)]
mod tests;

/// The claims that will be encoded into the JWT.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub username: String,
    pub exp: i64,
}

/// The error type for the auth module.
#[derive(Debug)]
pub enum AuthError {
    InvalidToken,
    MissingAuthorization,
    InvalidUsernameOrPassword,
    TokenCreation,
    Internal,
}

/// The request body for the login handler.
#[derive(Deserialize)]
pub struct RequestBody {
    pub email: String,
    pub password: String,
}

/// The response body for the login handler.
#[derive(Deserialize, Debug)]
pub struct LoginResponse {
    pub token: String,
    pub username: String,
}

/// The trait that must be implemented by the user to provide user data.
use async_trait::async_trait;

#[async_trait]
pub trait UserData: Send + Sync {
    /// Get a user by email.
    async fn get_user_by_email(&self, email: &str) -> Option<CurrentUser>;
    /// Verify a user's password.
    async fn verify_password(&self, user_id: &str, password: &str) -> bool;
}

#[derive(Clone)]
pub struct Authenticator<D: UserData> {
    user_data: D,
    jwt_key: EncodingKey,
    refresh_key: EncodingKey,
    jwt_decoding_key: DecodingKey,
    refresh_decoding_key: DecodingKey,
    validation: Validation,
}

impl<D: UserData> Authenticator<D> {
    pub fn new(
        user_data: D,
        jwt_key: EncodingKey,
        refresh_key: EncodingKey,
        jwt_decoding_key: DecodingKey,
        refresh_decoding_key: DecodingKey,
        validation: Validation,
    ) -> Self {
        Self {
            user_data,
            jwt_key,
            refresh_key,
            jwt_decoding_key,
            refresh_decoding_key,
            validation,
        }
    }

    pub fn layer(&self) -> AuthLayer {
        AuthLayer::new(self.jwt_decoding_key.clone(), self.validation.clone())
    }

    pub async fn login(
        &self,
        body: Json<RequestBody>,
    ) -> Result<Json<serde_json::Value>, AuthError> {
        let expiry_timestamp = (chrono::Utc::now() + chrono::Duration::hours(48)).timestamp();
        login(
            body,
            &self.user_data,
            &self.jwt_key,
            &self.refresh_key,
            expiry_timestamp,
        )
        .await
    }

    pub async fn refresh(
        &self,
        body: Json<RefreshBody>,
        new_claims: Option<Claims>,
    ) -> Result<Json<serde_json::Value>, AuthError> {
        refresh_token(
            body,
            &self.refresh_key,
            &self.refresh_decoding_key,
            &self.validation,
            &Header::default(),
            new_claims,
        )
        .await
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token"),
            AuthError::MissingAuthorization => (StatusCode::UNAUTHORIZED, "Missing authorization"),
            AuthError::InvalidUsernameOrPassword => {
                (StatusCode::UNAUTHORIZED, "Invalid username or password")
            }
            AuthError::TokenCreation => (StatusCode::INTERNAL_SERVER_ERROR, "Token creation error"),
            AuthError::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error"),
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}

/// The auth layer that can be used to protect routes.
#[derive(Clone)]
pub struct AuthLayer {
    key: DecodingKey,
    validation: Validation,
}

impl AuthLayer {
    /// Create a new `AuthLayer`.
    pub fn new(key: DecodingKey, validation: Validation) -> Self {
        Self { key, validation }
    }
}

impl<S> tower::Layer<S> for AuthLayer {
    type Service = AuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthService {
            inner,
            key: self.key.clone(),
            validation: self.validation.clone(),
        }
    }
}

/// The auth service that will be used by the `AuthLayer`.
#[derive(Clone)]
pub struct AuthService<S> {
    inner: S,
    key: DecodingKey,
    validation: Validation,
}

impl<S, ReqBody> tower::Service<Request<ReqBody>> for AuthService<S>
where
    S: tower::Service<Request<ReqBody>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let key = self.key.clone();
        let validation = self.validation.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            if let Some(auth_header) = req
                .headers()
                .get(http::header::AUTHORIZATION)
                .and_then(|header| header.to_str().ok())
            {
                match authorize_current_user(auth_header, &key, validation).await {
                    Ok(claims) => {
                        req.extensions_mut().insert(claims);
                        inner.call(req).await
                    }
                    Err(_) => Ok(AuthError::InvalidToken.into_response()),
                }
            } else {
                Ok(AuthError::MissingAuthorization.into_response())
            }
        })
    }
}

/// The request body for the refresh token handler.
#[derive(Deserialize)]
pub struct RefreshBody {
    token: String,
}

/// Authorize a user from an auth token.
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

/// Encode a new token.
pub async fn auth_token_encode(
    claims: Claims,
    header: &Header,
    key: &EncodingKey,
) -> Result<String, Error> {
    let token = encode(&header, &claims, key)?;
    Ok(token)
}

/// Decode a token.
pub async fn auth_token_decode(
    token: String,
    key: &DecodingKey,
    validation: Validation,
) -> Result<jsonwebtoken::TokenData<Claims>, String> {
    let claims: jsonwebtoken::TokenData<Claims> = decode::<Claims>(&token, key, &validation)
        .map_err(|e| format!("Error decoding token: {}", e))?;
    Ok(claims)
}

/// The login handler.
pub async fn login(
    body: Json<RequestBody>,
    user_data: &dyn UserData,
    jwt_key: &EncodingKey,
    refresh_key: &EncodingKey,
    expiry_timestamp: i64,
) -> Result<Json<serde_json::Value>, AuthError> {
    let email = &body.email;
    let password = &body.password;

    if let Some(user) = user_data.get_user_by_email(email).await {
        if user_data.verify_password(&user.id, password).await {
            let header = &Header::default();
            let refresh_header = &Header::default();

            let claims = Claims {
                sub: user.id,
                username: user.username.clone(),
                exp: expiry_timestamp,
            };

            let access_token = auth_token_encode(claims.clone(), header, jwt_key)
                .await
                .map_err(|_| AuthError::TokenCreation)?;
            let refresh_token = auth_token_encode(claims, refresh_header, refresh_key)
                .await
                .map_err(|_| AuthError::TokenCreation)?;
            let response = Json(json!({
                "access_token": access_token,
                "username": user.username,
                "refresh_token": refresh_token
            }));
            return Ok(response);
        }
    }

    Err(AuthError::InvalidUsernameOrPassword)
}

/// The refresh token handler.
pub async fn refresh_token(
    body: Json<RefreshBody>,
    key: &EncodingKey,
    decoding_key: &DecodingKey,
    validation: &Validation,
    header: &Header,
    new_claims: Option<Claims>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let token = &body.token;

    match auth_token_decode(token.to_string(), decoding_key, validation.clone()).await {
        Ok(mut claims) => {
            if let Some(new) = new_claims {
                claims.claims = new;
            }
            match auth_token_encode(claims.claims, header, key).await {
                Ok(new_token) => Ok(Json(json!({ "access_token": new_token }))),
                Err(_) => Err(AuthError::TokenCreation),
            }
        }
        Err(_) => Err(AuthError::InvalidToken),
    }
}
