use crate::service::{hello, MyUserData};
use axum::{
    middleware,
    routing::{get, post},
    Json, Router,
};
use axum_jwt_ware::{self, refresh_token, Claims, DecodingContext, EncodingContext, RefreshBody};
use chrono::{Duration, Utc};

pub fn create_router() -> Router {
    let user_data = MyUserData;
    let jwt_secret = "secret";
    let refresh_secret = "refresh_secret";

    let app = Router::new()
        .route(
            "/hello",
            get(hello).layer(middleware::from_fn(move |req, next| {
                let key = axum_jwt_ware::DecodingKey::from_secret(jwt_secret.as_ref());
                let validation = axum_jwt_ware::Validation::default();
                async move { axum_jwt_ware::verify_user(req, &key, validation, next).await }
            })),
        )
        .route(
            "/login",
            post(move |body: Json<axum_jwt_ware::RequestBody>| {
                let expiry_timestamp = (Utc::now() + Duration::hours(48)).timestamp();

                axum_jwt_ware::login(
                    body,
                    user_data.clone(),
                    jwt_secret.to_string(),
                    refresh_secret.to_string(),
                    expiry_timestamp,
                )
            }),
        )
        .route(
            "/refresh",
            post(move |body: Json<RefreshBody>| {
                let encoding_context = EncodingContext {
                    header: axum_jwt_ware::Header::default(),
                    validation: axum_jwt_ware::Validation::default(),
                    key: axum_jwt_ware::EncodingKey::from_secret("refresh_secret".as_ref()),
                };
                let decoding_context = DecodingContext {
                    header: axum_jwt_ware::Header::default(),
                    validation: axum_jwt_ware::Validation::default(),
                    key: axum_jwt_ware::DecodingKey::from_secret("refresh_secret".as_ref()),
                };
                let claims = Claims {
                    sub: "jkfajfafghjjfn".to_string(),
                    username: "ezesunday".to_string(),
                    exp: (Utc::now() + Duration::hours(48)).timestamp(),
                };
                refresh_token(body, encoding_context, decoding_context, Some(claims))
            }),
        );
    app
}
