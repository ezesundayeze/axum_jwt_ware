# axum_jwt_ware Integration Guide

Simple Axum + JWT authentication middleware with implemented Login and refresh token.

## Goal

I aim to simplify the process for developers/indie hackers to focus on writing their core business logic when starting a new project, rather than spending time rewriting authentication.

## Installation

```sh
cargo add axum_jwt_ware
```

## Usage example

There is one standard middleware for verifying a user via JWT -- the `verify_user` middleware. Its signature looks like this:

```rust
pub async fn verify_user<B>(
    mut req: Request<B>,
    key: &DecodingKey,
    validation: Validation,
    next: Next<B>,
) -> Result<Response, AuthError>
```

You can pass it to the route layer as shown below:

```rust
use axum_jwt_ware;

let app = Router::new()
        .route(
            "/hello",
            get(hello)
            .layer(middleware::from_fn(move |req, next| {
                let key = axum_jwt_ware::DecodingKey::from_secret(jwt_secret.as_ref());
                let validation = axum_jwt_ware::Validation::default();
                async move { axum_jwt_ware::verify_user(req, &key, validation, next).await }
        })),
    )
```

## Login

It's possible for you to either implement your own custom Login or use the login provided by the library. The provided login uses the default Algorithm and just requires you to provide your "secret."

Here is an example of how to use the provided login:

```rust
use axum_jwt_ware::{CurrentUser, UserData};

#[derive(Clone, Copy)]
pub struct MyUserData;

impl UserData for MyUserData {
    fn get_user_by_email(&self, _email: &str) -> Option<CurrentUser> {
        // Implement the logic to fetch a user by email from your database
    }
}

let app = Router::new()
        .route(
            "/login",
            post(move |body: Json<axum_jwt_ware::RequestBody>| {
                let expiry_timestamp = Utc::now() + Duration::hours(48);
                let user_data = MyUserData;
                let jwt_secret = "secret";
                let refresh_secret = "refresh_secret";

                axum_jwt_ware::login(
                    body,
                    user_data.clone(),
                    jwt_secret,
                    refresh_secret,
                    expiry_timestamp.timestamp(),
                )
            }),
        )
```

If you are going to implement a custom login, make sure to use the `axum_auth_ware::auth_token_encode` method to generate your token. Here is an example of a login with RSA encryption:

```rust
use axum_jwt_ware::{CurrentUser, UserData, Algorithm, auth_token_encode};
let key = EncodingKey::from_rsa_pem(include_bytes!("../jwt_rsa.key")).unwrap();
let mut header = Header::new(Algorithm::RS256);
let expiry_timestamp = Utc::now() + Duration::hours(48);

let claims = Claims {
    sub: user.id,
    username: user.username.clone(),
    exp: expiry_timestamp,
};
let token = auth_token_encode(claims, header, &key).await;
```

## Refresh token

A refresh token allows a user to login (get a new access token) without requiring them to enter their username and password (full login).

You can create your own using the `auth_token_encode` and `auth_token_decode` functions, or you can use the refresh token handler, which should look like this:

```rust
use axum_jwt_ware;

let app = Router::new()
        .route(
            "/refresh",
            post(move |body: Json<axum_jwt_ware::RefreshBody>| {

                let encoding_context = axum_jwt_ware::EncodingContext {
                    header: axum_jwt_ware::Header::default(),
                    validation: axum_jwt_ware::Validation::default(),
                    key: axum_jwt_ware::EncodingKey::from_secret("refresh_secret".as_ref()),
                };
                let decoding_context = axum_jwt_ware::DecodingContext {
                    header: axum_jwt_ware::Header::default(),
                    validation: axum_jwt_ware::Validation::default(),
                    key: axum_jwt_ware::DecodingKey::from_secret("refresh_secret".as_ref()),
                };
                let claims = axum_jwt_ware::Claims {
                    sub: "jkfajfafghjjfn".to_string(),
                    username: "ezesunday".to_string(),
                    exp: (Utc::now() + Duration::hours(48)).timestamp(),
                };

                axum_jwt_ware::refresh_token(body, encoding_context, decoding_context, claims)
            }),
        )
```

A more holistic example:

```rust
use crate::{
    auth,
    service::{hello, MyUserData},
};
use axum::{
    middleware,
    routing::{get, post},
    Json, Router,
};

use chrono::{Duration, Utc};

pub fn create_router() -> Router {
    let user_data = MyUserData;
    let jwt_secret = "secret";

    let app = Router::new()
        .route(
            "/hello",
            get(hello)
                .layer(middleware::from_fn(move |req, next| {
                    let key = auth::DecodingKey::from_secret(jwt_secret.as_ref());
                    let validation  = auth::Validation::default();
                    async move { auth::verify_user(req, &key, validation, next).await }
                })),
        )
        .route(
            "/login",
            post(move |body: Json<auth::RequestBody>| {
                let expiry_timestamp = Utc::now() + Duration::hours(48);

                auth::login(
                    body,
                    user_data.clone(),
                    jwt_secret,
                    expiry_timestamp.timestamp(),
                )
            }),
        );
    app
}

```
## Example
You can find a working example in the example directory in the [GitHub Repo](https://github.com/ezesundayeze/axum_jwt_ware/examples)

You're all set!

## Features

- [x] Refresh Token
- [x] Login
  - You can implement your own login
  - Use the provided login
- [x] Authentication Middleware
- [ ] Test

Want to contribute?

- Create an issue
- Fork the repo
- Create a PR that fixes the issue
