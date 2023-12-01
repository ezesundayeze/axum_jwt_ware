use axum::{Extension, Json};
use crate::axum_jwt_ware::{UserData, CurrentUser, Claims};

#[derive(Clone, Copy)]
pub struct MyUserData;

impl UserData for MyUserData {
    fn get_user_by_email(&self, _email: &str) -> Option<CurrentUser> {
        // Implement the logic to fetch user by email from your database
        // This is just a placeholder; replace it with the actual implementation
        Some(CurrentUser {
            password: "password".to_string(),
            name: "Eze Sunday".to_string(),
            email: "mailstoeze@gmail.com".to_string(),
            username: "ezesunday".to_string(),
            id: "jkfajfafghjjfn".to_string(),
        })
    }
}

pub async fn hello(
    Extension(claims): Extension<Claims>,
) -> Json<Claims> {
    Json(claims)
}
