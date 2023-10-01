use std::env;
extern crate dotenv;
use actix_web::{
    HttpResponse, cookie::Cookie,
    cookie::time::Duration as ActixWebDuration,
};
use chrono::{Utc, Duration};
use dotenv::dotenv;

use futures::StreamExt;
use jsonwebtoken::{encode, Header, EncodingKey, decode, DecodingKey, Validation, Algorithm};
use mongodb::{Collection, Client, results::{InsertOneResult, UpdateResult, DeleteResult}, bson::{doc, oid::ObjectId, extjson::de::Error}};
use serde_json::json;

use crate::models::models::{User, Todos, ErrorResponse, LoginSchema, TokenClaims};


#[derive(Debug, Clone)]
pub struct MongoRepo {
    user: Collection<User>,
    todo: Collection<Todos>
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

                    let todos = Todos {
                        id: None,
                        uid: Some(id),
                        description: new_todo.description,
                        created_at: Some(Utc::now())
                    };

                    // // Create a HashMap and insert the new_todo into it
                    // let mut list = HashMap::new();
                    // list.insert(id, todos);

                    // let doc = TodoList {
                    //     list,
                    // };

                    let todo = self
                        .todo
                        .insert_one( todos, None)
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


        //Get all todos
        pub async fn getall_todos(&self, token: &str) -> Result<Vec<Todos>, ErrorResponse> {

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

                    let id = decoded.claims.sub.to_owned();

                    let doc = doc! {
                        "_uid": id
                    };

                    let mut todo = self
                        .todo
                        .find(doc, None)
                        .await
                        .ok()
                        .expect("Error finding todos");

                    let mut todo_vec = Vec::new();

                    while let Some(doc) = todo.next().await {

                        println!("Hiiii {:?}", doc);

                        match doc {
                            Ok(todo) => {
                                todo_vec.push(todo)
                            },
                            Err(err) => {
                                eprintln!("Error finding todo: {:?}", err)
                            },
                        }
                    }

                    println!("{:?}", todo_vec);

                    Ok(todo_vec)
                    
                }
                Err(_) =>  Err(ErrorResponse {
                    status: false,
                    message: "Invalid Token".to_string(),
                }),
            }

        }


        //Update todo
        pub async fn update_todo(&self, token: &str, todo_list: Todos, todo_id: String ) -> Result<UpdateResult, ErrorResponse> {

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

                    println!("object_id{:?}", decoded.claims.sub.to_owned());

                    let id = decoded.claims.sub;

                    let bson_id = ObjectId::parse_str(todo_id).unwrap();

                    match self.finding_todo(&id, &bson_id).await.unwrap() {

                        Some(_) => {

                            let filter = doc! {"_id": bson_id};
        
                            let new_doc = doc! {
                                "$set":
                                    {
                                        "description": todo_list.description
                                    },
                            };
                            let updated_doc = self
                                .todo
                                .update_one(filter, new_doc, None)
                                .await
                                .ok()
                                .expect("Error updating todo");
                    
                            Ok(updated_doc)
                        },
                        None => {
                            return Err(ErrorResponse {
                                    message: "Todo Not found".to_owned(),
                                    status: false
                            })
                        }
                    }
                }
                Err(_) => Err(ErrorResponse {
                    status: false,
                    message: "Invalid Token".to_string(),
                }),
            }

        }

        //Delete todo
        pub async fn delete_todo(&self, token: &str, todo_id: String ) -> Result<DeleteResult, ErrorResponse> {

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

                    println!("object_id{:?}", decoded.claims.sub.to_owned());

                    let id = decoded.claims.sub;

                    let bson_id = ObjectId::parse_str(&todo_id).unwrap();

                    match self.finding_todo(&id, &bson_id).await.unwrap() {

                        Some(_) => {

                            let filter = doc! {"_id": bson_id};

                            let delete = self
                                .todo
                                .delete_one(filter, None)
                                .await
                                .ok()
                                .expect("Error deleting todos");
                            
                            Ok(delete)
                        },
                        None => {
                            return Err(ErrorResponse {
                                    message: "Todo Not found".to_owned(),
                                    status: false
                            })
                        }
                    }

                },
                Err(_) => Err(ErrorResponse {
                    status: false,
                    message: "Invalid Token".to_string(),
                }),
            }
        }

        //finding todo
        pub async fn finding_todo(&self, user_id: &String, todo_id: &ObjectId) -> Result<Option<Todos>, Error> {

            let todo = self
                .todo
                .find_one(doc! {
                    "_id" : todo_id,
                    "_uid" : user_id
                }, None)
                .await.ok()
                .expect("Error finding todo");

            Ok(todo)
        }


}

    