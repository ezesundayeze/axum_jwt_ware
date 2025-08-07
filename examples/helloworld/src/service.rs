use axum::{Extension, Json};
use axum_jwt_ware::{Claims, CurrentUser, UserData};
use async_trait::async_trait;

#[derive(Clone, Copy)]
pub struct MyUserData;

#[async_trait]
impl UserData for MyUserData {
    async fn get_user_by_email(&self, email: &str) -> Option<CurrentUser> {
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
        user_id == "1" && password == "password"
    }
}

pub async fn hello(Extension(claims): Extension<Claims>) -> Json<Claims> {
    Json(claims)
}
