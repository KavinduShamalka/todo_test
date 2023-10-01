use actix_web::{get, Responder, HttpResponse, web::{self, Data, Json}, post, HttpRequest, put, delete};
use serde_json::json;

use crate::{repository::repository::MongoRepo, models::models::{User, LoginSchema, Todos}};

#[get("/test")]
pub async fn test() -> impl Responder {
    const MESSAGE: &str = "JWT Authentication in Rust using Actix-web and MongoDB";
    HttpResponse::Ok().json(serde_json::json!({"status": "success", "message": MESSAGE}))
}

#[post("/register")]
pub async fn user_register(db: Data<MongoRepo>, new_user: Json<User>) -> HttpResponse {
    
    let data = User {
        id: None,
        name: new_user.name.to_owned(),
        email: new_user.email.to_owned(),
        password: new_user.password.to_owned(),
    };

    match db.register_user(data).await {
        Ok(_) => HttpResponse::Ok().json(json!({"status" : "success", "message" : "Registration Successfull"})),
        Err(error) =>  HttpResponse::ExpectationFailed().json(json!({"status" : "failed", "message" : error})),
    }
}

//User login
#[post("/login")]
pub async fn user_login(data: Json<LoginSchema>, db: Data<MongoRepo>) -> HttpResponse {
        
        let login = db.login(data.into_inner()).await;

        login

}

//create todo
#[post("/auth/create-todo")]
pub async fn create_todo(data: Json<Todos>, db: Data<MongoRepo>, req: HttpRequest) -> HttpResponse {

    let auth = req.headers().get("Authorization");
    let split: Vec<&str> = auth.unwrap().to_str().unwrap().split("Bearer").collect();
    let token = split[1].trim();

    let todos = Todos {
        id: None,
        uid: None,
        description: data.description.to_owned(),
        created_at: None
    };

    match db.create_todo_list(token, todos).await {
        Ok(result) => HttpResponse::Ok().json(json!({"status" : "success", "result" : result})),
        Err(error) =>  HttpResponse::ExpectationFailed().json(json!({"status" : "failed", "message" : error})),
    }
}

//Find todo by ID
#[get("/all")]
pub async fn get_all_todos(req: HttpRequest, db: Data<MongoRepo>) -> HttpResponse {

    let auth = req.headers().get("Authorization");
    let split: Vec<&str> = auth.unwrap().to_str().unwrap().split("Bearer").collect();
    let token = split[1].trim();

    match db.getall_todos(token).await {
        Ok(result) => HttpResponse::Ok().json(json!({"status" : "success", "result" : result})),
        Err(error) =>  HttpResponse::ExpectationFailed().json(json!({"status" : "failed", "message" : error})), 
    }
}

//Update todo
#[put("/update/{id}")]
pub async fn update_todo(data: Json<Todos>, id: web::Path<String>, db: Data<MongoRepo>, req: HttpRequest) -> HttpResponse {

    let todo_id = id.into_inner();

    let auth = req.headers().get("Authorization");
    let split: Vec<&str> = auth.unwrap().to_str().unwrap().split("Bearer").collect();    
    let token = split[1].trim();

    let todos = Todos {
        id: None,
        uid: None,
        description: data.description.clone(),
        created_at: None
    };

    match db.update_todo(token, todos, todo_id).await {
        Ok(result) => HttpResponse::Ok().json(json!({"result": result})),
        Err(err) => HttpResponse::Ok().json(err),
     }
}

//Delete todo
#[delete("/delete/{id}")]
pub async fn delete_todo(db: Data<MongoRepo>, req: HttpRequest, id: web::Path<String>) -> HttpResponse {

    let delete_id = id.into_inner();
    let auth = req.headers().get("Authorization");
    let split: Vec<&str> = auth.unwrap().to_str().unwrap().split("Bearer").collect();    
    let token = split[1].trim();

    match db.delete_todo(token, delete_id).await {
        Ok(result) => HttpResponse::Ok().json(json!({"result": result})),
        Err(err) => HttpResponse::Ok().json(err),
    }
}


pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(test)
        .service(user_register)
        .service(user_login)
        .service(create_todo)
        .service(update_todo)
        .service(delete_todo)
        .service(get_all_todos);
}