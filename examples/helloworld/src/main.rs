mod route;
use route::create_router;
mod service;
pub use axum_jwt_ware;


#[tokio::main]
async fn main() {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, create_router().into_make_service())
        .await
        .unwrap();
}