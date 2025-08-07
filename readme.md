# axum_jwt_ware Integration Guide

Simple Axum + JWT authentication middleware with implemented Login and refresh token.

## Goal

I aim to simplify the process for developers/indie hackers to focus on writing their core business logic when starting a new project, rather than spending time rewriting authentication.

## Installation

```sh
cargo add axum_jwt_ware
```

## Usage example

There is one standard middleware for verifying a user via JWT -- the `AuthLayer` middleware. Its signature looks like this:

```rust
pub fn new(key: DecodingKey, validation: Validation) -> Self
```

You can pass it to the route layer as shown below:

```rust
use axum_jwt_ware::{AuthLayer, DecodingKey, Validation};

let key = DecodingKey::from_secret("secret".as_ref());
let validation = Validation::default();
let auth_layer = AuthLayer::new(key, validation);

let app = Router::new()
        .route(
            "/hello",
            get(hello)
    )
    .layer(auth_layer);
```

## Login

It's possible for you to either implement your own custom Login or use the login provided by the library. The provided login uses the default Algorithm and just requires you to provide your "secret."

Here is an example of how to use the provided login:

```rust
use axum_jwt_ware::{login, CurrentUser, RequestBody, UserData};
use axum::Json;
use chrono::{Duration, Utc};

#[derive(Clone, Copy)]
pub struct MyUserData;

#[async_trait::async_trait]
impl UserData for MyUserData {
    async fn get_user_by_email(&self, _email: &str) -> Option<CurrentUser> {
        // Implement the logic to fetch a user by email from your database
    }
    async fn verify_password(&self, user_id: &str, password: &str) -> bool {
        // Implement the logic to verify a user's password
    }
}

let app = Router::new()
        .route(
            "/login",
            post(move |body: Json<RequestBody>| {
                let expiry_timestamp = (Utc::now() + Duration::hours(48)).timestamp();
                let user_data = MyUserData;
                let jwt_key = EncodingKey::from_secret("secret".as_ref());
                let refresh_key = EncodingKey::from_secret("refresh_secret".as_ref());

                login(
                    body,
                    user_data.clone(),
                    &jwt_key,
                    &refresh_key,
                    expiry_timestamp,
                )
            }),
        )
```

If you are going to implement a custom login, make sure to use the `axum_auth_ware::auth_token_encode` method to generate your token. Here is an example of a login with RSA encryption:

```rust
use axum_jwt_ware::{auth_token_encode, Claims, Algorithm, Header, EncodingKey};
use chrono::{Duration, Utc};

let key = EncodingKey::from_rsa_pem(include_bytes!("../jwt_rsa.key")).unwrap();
let mut header = Header::new(Algorithm::RS256);
let expiry_timestamp = (Utc::now() + Duration::hours(48)).timestamp();

let claims = Claims {
    sub: user.id,
    username: user.username.clone(),
    exp: expiry_timestamp,
};
let token = auth_token_encode(claims, &header, &key).await;
```

## Refresh token

A refresh token allows a user to login (get a new access token) without requiring them to enter their username and password (full login).

You can create your own using the `auth_token_encode` and `auth_token_decode` functions, or you can use the refresh token handler, which should look like this:

```rust
use axum_jwt_ware::{refresh_token, Claims, DecodingKey, EncodingKey, Header, RefreshBody, Validation};
use axum::Json;
use chrono::{Duration, Utc};

let app = Router::new()
        .route(
            "/refresh",
            post(move |body: Json<RefreshBody>| {
                let key = EncodingKey::from_secret("refresh_secret".as_ref());
                let decoding_key = DecodingKey::from_secret("refresh_secret".as_ref());
                let validation = Validation::default();
                let header = Header::default();
                let claims = Claims {
                    sub: "jkfajfafghjjfn".to_string(),
                    username: "ezesunday".to_string(),
                    exp: (Utc::now() + Duration::hours(48)).timestamp(),
                };

                refresh_token(body, &key, &decoding_key, &validation, &header, Some(claims))
            }),
        )
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
