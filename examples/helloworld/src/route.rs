use crate::service::{hello, MyUserData};
use axum::{
    routing::{get, post},
    Json, Router,
};
use axum_jwt_ware::{
    self, refresh_token, AuthLayer, Claims, DecodingKey, EncodingKey, Header, RefreshBody,
    RequestBody, Validation,
};
use chrono::{Duration, Utc};

pub fn create_router() -> Router {
    let user_data = MyUserData;
    let jwt_secret = EncodingKey::from_secret("secret".as_ref());
    let refresh_secret = EncodingKey::from_secret("refresh_secret".as_ref());
    let decoding_key = DecodingKey::from_secret("secret".as_ref());
    let refresh_decoding_key = DecodingKey::from_secret("refresh_secret".as_ref());
    let validation = Validation::default();

    let auth_layer = AuthLayer::new(decoding_key, validation.clone());

    let app = Router::new()
        .route("/hello", get(hello))
        .layer(auth_layer)
        .route(
            "/login",
            post(move |body: Json<RequestBody>| {
                let expiry_timestamp = (Utc::now() + Duration::hours(48)).timestamp();

                axum_jwt_ware::login(
                    body,
                    &user_data,
                    &jwt_secret,
                    &refresh_secret,
                    expiry_timestamp,
                )
            }),
        )
        .route(
            "/refresh",
            post(move |body: Json<RefreshBody>| {
                let claims = Claims {
                    sub: "jkfajfafghjjfn".to_string(),
                    username: "ezesunday".to_string(),
                    exp: (Utc::now() + Duration::hours(48)).timestamp(),
                };
                refresh_token(
                    body,
                    &refresh_secret,
                    &refresh_decoding_key,
                    &validation,
                    &Header::default(),
                    Some(claims),
                )
            }),
        );
    app
}
