
## axum_jwt_ware Integration Guide
Simple Axum + JWT authentication middleware with Login implemented. 

Warning: This library is still under development and should be considered expirimental until version a stable release at version 1.0.0

## Installation

```sh
cargo add axum_jwt_ware
```

## Usage example

```rs
// main.rs file
use axum_jwt_ware::{login, CurrentUser, UserData, verify_user};
use axum::{middleware, routing::{get, post}, Extension, Json, Router};
use std::net::SocketAddr;

#[derive(Clone, Copy)]
pub struct MyUserData;

#[tokio::main]
async fn main() {

let jwt_secret = "secret";  //secret from env
let user_data = MyUserData;

let app = Router::new()
    .route(
        "/hello",
        get(hello)
        .layer(middleware::from_fn(move |req: axum::http::Request<axum::body::Body>, next: middleware::Next<axum::body::Body>| {
            let user_db = user_data.clone();
            async move {
                verify_user(req, user_db, &jwt_secret, next).await
            }
        })),
    )
    .route("/login", post(move | body: Json<lib::MyRequestBody>| {
        login(body, user_data.clone(), jwt_secret) // login returns {username, token}
    }));

}


impl UserData for MyUserData {
    fn get_user_by_email(&self, _email: &str) -> Option<CurrentUser> {
        // Replace with your actual implementation to fetch user by email
    }

    fn get_user_by_id(&self, _user_id: &str) -> Option<CurrentUser> {
        // Replace with your actual implementation to fetch user by ID
    }
}

async fn hello(
    Extension(current_user): Extension<CurrentUser>,
) -> Json<CurrentUser> {
    Json(current_user)
}
```

The `CurrentUser` Struct looks like this: 
```rs
pub struct CurrentUser {
    pub name: String,
    pub email: String,
    pub username: String,
    pub id: String,
    pub password: String,
}
```


If you don't want to implement your own login: you can use the `axum_jwt_ware::auth_token_encode` method to generate your token. 

