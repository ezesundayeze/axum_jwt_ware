use crate::service::{hello, MyUserData};
use axum::{
    routing::{get, post},
    Json, Router,
};
use axum_jwt_ware::{
    Authenticator, Claims, DecodingKey, EncodingKey, RefreshBody, RequestBody, Validation,
};
use chrono::{Duration, Utc};

pub fn create_router() -> Router {
    let user_data = MyUserData;
    let jwt_key = EncodingKey::from_secret("secret".as_ref());
    let refresh_key = EncodingKey::from_secret("refresh_secret".as_ref());
    let jwt_decoding_key = DecodingKey::from_secret("secret".as_ref());
    let refresh_decoding_key = DecodingKey::from_secret("refresh_secret".as_ref());
    let validation = Validation::default();

    let auth = Authenticator::new(
        user_data,
        jwt_key,
        refresh_key,
        jwt_decoding_key,
        refresh_decoding_key,
        validation,
    );

    let app = Router::new()
        .route("/hello", get(hello))
        .layer(auth.layer())
        .route(
            "/login",
            post(move |body: Json<RequestBody>| async move { auth.login(body).await }),
        )
        .route(
            "/refresh",
            post(move |body: Json<RefreshBody>| async move {
                let new_claims = Claims {
                    sub: "jkfajfafghjjfn".to_string(),
                    username: "ezesunday".to_string(),
                    exp: (Utc::now() + Duration::hours(48)).timestamp(),
                };
                auth.refresh(body, Some(new_claims)).await
            }),
        );
    app
}
