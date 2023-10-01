use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};
use chrono::prelude::*;

//User structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub name: String,
    pub email: String,
    pub password: String,
}

//Todo structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Todos {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    #[serde(rename = "_uid", skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    pub description: String,
    #[serde(rename = "_createdAt", skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
}

//Todo list structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TodoList {
    pub list: Vec<Todos>
}

//User login schema
#[derive(Debug, Deserialize)]
pub struct LoginSchema {
    pub email: String,
    pub password: String,
}
//Token claims structure
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub iat: String,
    pub exp: usize,
}

//Error response structure
#[derive(Serialize, Deserialize, Debug)]
pub struct ErrorResponse {
    pub message: String,
    pub status: bool
}

//Success response structure
#[derive(Serialize, Deserialize, Debug)]
pub struct SuccessResponse {
    pub message: String,
    pub status: bool
}