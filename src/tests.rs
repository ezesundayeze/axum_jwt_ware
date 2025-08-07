use super::*;
use axum::{
    body::Body,
    http::{self, Request, StatusCode},
    routing::get,
    Router,
};
use tower::ServiceExt;

#[derive(Clone)]
struct MockUserData;

#[async_trait::async_trait]
impl UserData for MockUserData {
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

async fn protected() -> &'static str {
    "protected"
}

fn app() -> Router {
    let key = DecodingKey::from_secret("secret".as_ref());
    let validation = Validation::default();
    let auth_layer = AuthLayer::new(key, validation);

    Router::new()
        .route("/protected", get(protected))
        .layer(auth_layer)
}

#[tokio::test]
async fn test_auth_layer_no_token() {
    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_auth_layer_with_token() {
    let app = app();

    let key = EncodingKey::from_secret("secret".as_ref());
    let claims = Claims {
        sub: "1".to_string(),
        username: "test".to_string(),
        exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
    };
    let token = encode(&Header::default(), &claims, &key).unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(http::header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_login() {
    let user_data = MockUserData;
    let jwt_key = EncodingKey::from_secret("secret".as_ref());
    let refresh_key = EncodingKey::from_secret("refresh_secret".as_ref());
    let expiry_timestamp = (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp();

    let body = Json(RequestBody {
        email: "test@test.com".to_string(),
        password: "password".to_string(),
    });

    let response = login(body, &user_data, &jwt_key, &refresh_key, expiry_timestamp).await;

    assert_eq!(response.unwrap().into_response().status(), StatusCode::OK);
}

#[tokio::test]
async fn test_login_invalid_credentials() {
    let user_data = MockUserData;
    let jwt_key = EncodingKey::from_secret("secret".as_ref());
    let refresh_key = EncodingKey::from_secret("refresh_secret".as_ref());
    let expiry_timestamp = (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp();

    let body = Json(RequestBody {
        email: "test@test.com".to_string(),
        password: "wrong_password".to_string(),
    });

    let response = login(body, &user_data, &jwt_key, &refresh_key, expiry_timestamp).await;

    assert_eq!(
        response.unwrap_err().into_response().status(),
        StatusCode::UNAUTHORIZED
    );
}
