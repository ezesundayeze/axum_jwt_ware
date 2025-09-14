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

### 2. Create the `Authenticator`

The `Authenticator` struct holds all the necessary configuration, such as the keys, validation, and user data implementation.

```rust
use axum_jwt_ware::{Authenticator, DecodingKey, EncodingKey, Validation};

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
```

### 3. Protect your routes

You can use the `Authenticator` to protect your routes by calling the `layer()` method.

```rust
use axum::{routing::get, Router};

async fn protected_route() -> &'static str {
    "This is a protected route"
}

let app = Router::new()
    .route("/protected", get(protected_route))
    .layer(auth.layer());
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

The `Authenticator` provides a `login` method that you can use to implement your login handler.

```rust
use axum::{routing::post, Json, Router};
use axum_jwt_ware::RequestBody;

let app = Router::new().route(
    "/login",
    post(move |body: Json<RequestBody>| async move { auth.login(body).await }),
);
```

### 5. Implement the refresh token handler

The `Authenticator` provides a `refresh` method that you can use to implement your refresh token handler.

```rust
use axum::{routing::post, Json, Router};
use axum_jwt_ware::{Claims, RefreshBody};
use chrono::{Duration, Utc};

let app = Router::new().route(
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
```

## Error Handling

The middleware and its associated functions return errors that are automatically converted into HTTP responses. Here are the possible error scenarios:

| Error                        | Status Code | Response Body                               | Description                                                                                                                              |
| ---------------------------- | ----------- | ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `InvalidToken`               | 401         | `{"error": "Invalid token"}`                | Occurs when the provided JWT is invalid, malformed, or expired. This is returned by the authentication middleware.                     |
| `MissingAuthorization`       | 401         | `{"error": "Missing authorization"}`        | Occurs when the `Authorization` header is not present in a request to a protected route. This is returned by the authentication middleware. |
| `InvalidUsernameOrPassword`  | 401         | `{"error": "Invalid username or password"}` | Occurs during login when the provided email does not exist or the password does not match. This is returned by the `login` handler.      |
| `TokenCreation`              | 500         | `{"error": "Token creation error"}`         | Occurs if there is an internal error during the creation of a JWT. This is returned by the `login` and `refresh` handlers.          |
| `Internal`                   | 500         | `{"error": "Internal server error"}`        | A generic error for any other unexpected server-side issues.                                                                             |

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
