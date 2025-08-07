# axum_jwt_ware Integration Guide

Simple Axum + JWT authentication middleware with implemented Login and refresh token.

## Goal

I aim to simplify the process for developers/indie hackers to focus on writing their core business logic when starting a new project, rather than spending time rewriting authentication.

## Installation

```sh
cargo add axum_jwt_ware
```

## Usage

### 1. Implement the `UserData` trait

You need to create a struct and implement the `UserData` trait for it. This trait has two methods: `get_user_by_email` and `verify_password`. These methods are responsible for fetching a user from your database and verifying their password.

```rust
use axum_jwt_ware::{CurrentUser, UserData};
use async_trait::async_trait;

#[derive(Clone, Copy)]
pub struct MyUserData;

#[async_trait]
impl UserData for MyUserData {
    async fn get_user_by_email(&self, email: &str) -> Option<CurrentUser> {
        // Implement the logic to fetch a user by email from your database
        // This is just a placeholder; replace it with the actual implementation
        if email == "test@test.com" {
            Some(CurrentUser {
                id: "1".to_string(),
                name: "test".to_string(),
                email: "test@test.com".to_string(),
                username: "test".to_string(),
            })
        } else {
            None
        }
    }

    async fn verify_password(&self, user_id: &str, password: &str) -> bool {
        // Implement the logic to verify a user's password
        // This is just a placeholder; replace it with the actual implementation
        user_id == "1" && password == "password"
    }
}
```

### 2. Create the `AuthLayer`

The `AuthLayer` is a middleware that you can use to protect your routes. You need to provide a `DecodingKey` and a `Validation` struct to create it.

```rust
use axum_jwt_ware::{AuthLayer, DecodingKey, Validation};

let key = DecodingKey::from_secret("secret".as_ref());
let validation = Validation::default();
let auth_layer = AuthLayer::new(key, validation);
```

### 3. Protect your routes

You can use the `AuthLayer` to protect your routes by adding it as a layer to your router.

```rust
use axum::{routing::get, Router};

async fn protected_route() -> &'static str {
    "This is a protected route"
}

let app = Router::new()
    .route("/protected", get(protected_route))
    .layer(auth_layer);
```

Any route under the `auth_layer` will have access to the `Claims` from the JWT in the request extensions. You can extract it like this:

```rust
use axum::{Extension, Json};
use axum_jwt_ware::Claims;

async fn protected_route(Extension(claims): Extension<Claims>) -> Json<Claims> {
    Json(claims)
}
```

### 4. Implement the login handler

The library provides a `login` function that you can use to implement your login handler. You need to provide the necessary keys, user data, and other parameters to this function.

```rust
use axum::{routing::post, Json, Router};
use axum_jwt_ware::{login, EncodingKey, RequestBody};
use chrono::{Duration, Utc};

let user_data = MyUserData;
let jwt_secret = EncodingKey::from_secret("secret".as_ref());
let refresh_secret = EncodingKey::from_secret("refresh_secret".as_ref());

let app = Router::new().route(
    "/login",
    post(move |body: Json<RequestBody>| {
        let expiry_timestamp = (Utc::now() + Duration::hours(48)).timestamp();

        login(
            body,
            &user_data,
            &jwt_secret,
            &refresh_secret,
            expiry_timestamp,
        )
    }),
);
```

### 5. Implement the refresh token handler

The library provides a `refresh_token` function that you can use to implement your refresh token handler.

```rust
use axum::{routing::post, Json, Router};
use axum_jwt_ware::{
    refresh_token, Claims, DecodingKey, EncodingKey, Header, RefreshBody, Validation,
};
use chrono::{Duration, Utc};

let refresh_secret = EncodingKey::from_secret("refresh_secret".as_ref());
let refresh_decoding_key = DecodingKey::from_secret("refresh_secret".as_ref());
let validation = Validation::default();

let app = Router::new().route(
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
```

## Example

You can find a working example in the `examples/helloworld` directory in the [GitHub Repo](https://github.com/ezesundayeze/axum_jwt_ware/tree/main/examples/helloworld).

## Features

- [x] Refresh Token
- [x] Login
- [x] Authentication Middleware
- [x] Tests

Want to contribute?

- Create an issue
- Fork the repo
- Create a PR that fixes the issue
