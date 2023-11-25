
## auth_tools Integration Guide

Auth Tools is a Rust crate designed to simplify authentication and authorization in your Axum-based web applications. This guide provides step-by-step instructions on integrating Auth Tools into your project.

## Installation

```sh
cargo add auth_tools
```

## Usage example

```rs
// main.rs file
use auth_tools::{login, CurrentUser, UserData, verify_user};
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
        login(body, user_data.clone(), jwt_secret)
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

