
## axum_jwt_ware Integration Guide
Simple Axum + JWT authentication middleware with Login implemented.

## Goal
<p>I want to make it a lot easier for developers/indie hackers to focus on writing their core business logic when starting a new project instead of spending time re-writing authentication</p>

## Installation

```sh
cargo add axum_jwt_ware
```

## Usage example

There is one standard middleware for verifying a user via JWT -- the verify_user middleware. Its signature looks like this:

```rs
pub async fn verify_user<B>(
    mut req: Request<B>,
    key: &DecodingKey,
    validation: Validation,
    next: Next<B>,
) -> Result<Response, AuthError>
```
So, you can pass it to the route layer as shown below:

```rs
use crate::{
    verify_user,
    Claims, CurrentUser, UserData, DecodingKey, EncodingKey, Validation, Header
};
let app = Router::new()
    .route(
        "/hello",
        get(hello_handler)
        .layer(middleware::from_fn(move |req, next| {
            let key = DecodingKey::from_secret("secret_from_your_env".as_ref());
            let validation = Validation::default();
            async move {
                verify_user(req, &key, validation, next).await
            }
        })),
    )
```
## Login

<p>This library allows you to either implement your own custom Login or use the login provided by the library. The login provided by the library uses the default Algorithm and just requires you to provide your "secret". Note that what ever pattern you use in the login should also be replicated in the verify_user middleware.</p>

<p>Here is an example of how to use the provided login</p>

```rs
use axum_jwt_ware::{CurrentUser, UserData};

#[derive(Clone, Copy)]
pub struct MyUserData;

impl UserData for MyUserData {
    fn get_user_by_email(&self, _email: &str) -> Option<CurrentUser> {
        // Implement the logic to fetch user by email from your database
    }   
}

let app = Router::new()
.route("/login", post(move | body: Json<axum_jwt_ware::RequestBody>| {
    let user_data = MyUserData;
    let jwt_secret = "secret_from_env";
    login(body, user_data.clone(), jwt_secret) // login returns {username, token}
}));
```

<p>If you are going to implement a custom login make sure to use the `axum_auth_ware::auth_encode` method to generate your token</p>

```rs
use axum_jwt_ware::{CurrentUser, UserData, auth_token_encode};
let header = &Header::default();
let key = EncodingKey::from_secret(jwt_secret.as_ref());

let claims = Claims {
    sub: user.id,
    username: user.username.clone(),
    exp: expiry_timestamp,
};
let token = auth_token_encode(claims, header, &key).await;
```

<p>That's all.</p>

## Features
- [] Refresh Token
- [x] Login
  - You can imlement your own test

- [x] Authentication Middleware
- [] Test 

