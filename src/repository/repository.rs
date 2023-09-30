use std::{env, collections::HashMap};
extern crate dotenv;
use actix_web::{
    HttpResponse, cookie::Cookie,
    cookie::time::Duration as ActixWebDuration,
};
use chrono::{Utc, Duration};
use dotenv::dotenv;

use jsonwebtoken::{encode, Header, EncodingKey, decode, DecodingKey, Validation, Algorithm};
use mongodb::{Collection, Client, results::InsertOneResult, bson::doc};
use serde_json::json;

use crate::models::models::{User, Todos, ErrorResponse, LoginSchema, TokenClaims, TodoList};



#[derive(Debug, Clone)]
pub struct MongoRepo {
    user: Collection<User>,
    todo: Collection<TodoList>
}

impl MongoRepo {

    pub async fn init() -> Self {

        dotenv().ok();
        let url = match env::var("MONGOURI"){
            Ok(url) => url.to_string(),
            Err(_) => format!("Error loading env variable")
        };

        let client = Client::with_uri_str(url).await.unwrap();
        let db = client.database("todo_api");
        let user = db.collection("user");
        let todo =db.collection("todos");

        MongoRepo {
            user,
            todo
        }
    }

    //found by email
    pub async fn found_by_email(&self, email: String) -> String {

        let filter_email = doc! { "email" : email};

        let check_email = self
            .user
            .find_one(filter_email, None)
            .await.ok()
            .expect("Error finding email");
            

        match check_email {
            Some(user) => user.email,
            None => "No user found".to_string()
        }

    }

    //Register user
    pub async fn register_user(&self, new_user: User) -> Result<InsertOneResult, ErrorResponse> {

            let email = self.found_by_email(new_user.email.clone()).await;

            let new_email = new_user.email.clone();

            if email == new_email {
                Err(
                    ErrorResponse{
                        status: false,
                        message: "Email already exists".to_owned()
                    }
                )
            } else {

                let doc = User {
                    id: None,
                    name: new_user.name,
                    email: new_user.email,
                    password: new_user.password,
                    todo_list: None
                };

                let user = self
                    .user
                    .insert_one(doc, None)
                    .await.ok()
                    .expect("Error creating user");

                Ok(user)
            }
    }

    //User Login
    pub async fn login(&self, login: LoginSchema) -> HttpResponse {

        let user = self
            .user
            .find_one( doc! {
                "email" : login.email,
                "password": login.password 
            }, None)
            .await.ok()
            .expect("Error finding user");
            

            match user {

                Some(user) => {
                    let jwt_secret = "secret".to_owned();

                    let id = user.id.unwrap();

                    let now = Utc::now();
                    let iat = now.timestamp() as usize;
                            
                    let exp = (now + Duration::minutes(60)).timestamp() as usize;
                    let claims: TokenClaims = TokenClaims {
                        sub: id.to_string(),
                        exp,
                        iat: iat.to_string(),
                    };

                    let token = encode(&Header::default(),&claims,&EncodingKey::from_secret(jwt_secret.as_ref()),).unwrap();

                    let cookie = Cookie::build("token", token.to_owned())
                        .path("/")
                        .max_age(ActixWebDuration::new(60 * 60, 0))
                        .http_only(true)
                        .finish();

                    HttpResponse::Ok()
                        .cookie(cookie)
                        .json(json!({"status" :  "success", "token": token}))

                },
                None => {
                    return HttpResponse::BadRequest().json(ErrorResponse{
                        status: false,
                        message: "Invalid username or password".to_owned()
                    })
                }
                
            }
        }


        //Create todo
        pub async fn create_todo_list(&self, token:&str, new_todo: Todos) -> Result<InsertOneResult, ErrorResponse> {

            let secret_key = "secret".to_owned();

            let var = secret_key;
            let key = var.as_bytes();
            let decode = decode::<TokenClaims> (
                token,
                &DecodingKey::from_secret(key),
                &Validation::new(Algorithm::HS256),
            ); 

            match decode {

                Ok(decoded) => {

                    println!("User id{:?}", decoded.claims.sub.to_owned());

                    let id = decoded.claims.sub;

                    // let bson_id = ObjectId::parse_str(id).unwrap();

                    let todos = Todos {
                        id: None,
                        description: new_todo.description,
                        created_at: None
                    };

                    // Create a HashMap and insert the new_todo into it
                    let mut list = HashMap::new();
                    list.insert(id, todos);

                    let doc = TodoList {
                        list,
                    };

                    let todo = self
                        .todo
                        .insert_one( doc, None)
                        .await.ok()
                        .expect("Error finding");

                    println!("{:?}", todo);
            
                    Ok(todo)

                }
                Err(_) => Err(ErrorResponse {
                    status: false,
                    message: "Invalid Token".to_string(),
                }),
            }
        }


        // //Get all todos
        // pub async fn getall_todos(&self, token : &str, todo_id: String) -> HttpResponse {



        // }



}

    