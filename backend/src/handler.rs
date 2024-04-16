use std::sync::Arc;

use argon2::{password_hash::SaltString, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::{
    extract::State,
    http::{header, Response, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use jsonwebtoken::{encode, EncodingKey, Header};
use rand_core::OsRng;
use serde_json::json;

use crate::{
    model::{LoginUserSchema, RegisterUserSchema, TokenClaims, User},
    response::FilteredUser,
    AppState,
};

// Funcion para no mostrar la contraseña en ningun momento
fn filter_user_record(user: &User) -> FilteredUser {
    FilteredUser {
        id: user.id.to_string(),
        email: user.email.to_owned(),
        name: user.name.to_owned(),
        role: user.role.to_owned(),
        verified: user.verified,
        createdAt: user.created_at.unwrap(),
        updatedAt: user.updated_at.unwrap(),
    }
}

// Funcion solo para comprobar que el servidor sirve
pub async fn health_checker_handler() -> impl IntoResponse {
    const MESSAGE: &str = "The API works perfectly";

    let json_response = serde_json::json!({
        "status": "success",
        "message": MESSAGE
    });

    Json(json_response)
}

// Funcion para el registro de usuarios
pub async fn register_user_handler(
    State(data): State<Arc<AppState>>, // Necesitamos el estado global
    Json(body): Json<RegisterUserSchema>, // El body formareado de la request
                                       // Devolvemos un resultado con el codigo de estado y un json
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    // Vemos si el usuario existe buscandolo en la base de datos
    let user_exists: Option<bool> =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
            .bind(body.email.to_owned().to_ascii_lowercase())
            .fetch_one(&data.db)
            .await
            .map_err(|e| {
                // En caso de fallar la conexion devolvemos un json de fallo
                let response_error = serde_json::json!({
                    "status": "fail",
                    "message": format!("Database error: {}", e),
                });
                (StatusCode::INTERNAL_SERVER_ERROR, Json(response_error))
            })?;

    // En caso de no exisir devolvemos un json de fallo
    if let Some(exists) = user_exists {
        if exists {
            let error_response = serde_json::json!({
                "status": "fail",
                "message": "User with that email already exists",
            });
            return Err((StatusCode::CONFLICT, Json(error_response)));
        }
    }
    // Creamos una semilla para el hash
    let salt = SaltString::generate(&mut OsRng);
    // Encriptamos la contraseña
    let hashed_password = Argon2::default()
        .hash_password(body.password.as_bytes(), &salt)
        .map_err(|e| {
            // Manejamos el posible error al hashear
            let error_response = serde_json::json!({
                "status": "fail",
                "message": format!("Error while hashing password: {}", e),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
        })
        .map(|hash| hash.to_string())?;

    // Creamos el usuario en la base de datos
    let user = sqlx::query_as!(
        User,
        "INSERT INTO users (name,email,password) VALUES ($1, $2, $3) RETURNING *",
        body.name.to_string(),
        body.email.to_string().to_ascii_lowercase(),
        hashed_password
    )
    .fetch_one(&data.db)
    .await
    .map_err(|e| {
        // Manejamos el posible fallo con la base de datos
        let error_response = serde_json::json!({
            "status": "fail",
            "message": format!("Database error: {}", e),
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?;

    // Si todo va correcto mandamos como respuesta un json con el usuario filtrado
    let user_response = serde_json::json!({"status": "success","data": serde_json::json!({
        "user": filter_user_record(&user)
    })});

    Ok(Json(user_response))
}

// Funcion para el login de usuarios
pub async fn login_user_handler(
    State(data): State<Arc<AppState>>, // Necesitamos el estado global
    Json(body): Json<LoginUserSchema>, // El body formareado de la request
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    // Buscamos un usuario con email del body
    let user = sqlx::query_as!(
        User,
        "SELECT * FROM users WHERE email = $1",
        body.email.to_ascii_lowercase()
    )
    .fetch_optional(&data.db)
    .await
    // Manejamos el posible error en la base de datos
    .map_err(|e| {
        let error_response = serde_json::json!({
            "status": "error",
            "message": format!("Database error: {}",e),
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response))
    })?
    // Manejamos el posible fallo al no encontrar un usuario con ese email
    .ok_or_else(|| {
        let error_response = serde_json::json!({
            "status": "error",
            "message": "Invalid email or password",
        });
        (StatusCode::BAD_REQUEST, Json(error_response))
    })?;

    // Validamos que la contraseña mandada sea igual a la de la base de datos
    let is_valid = match PasswordHash::new(&user.password) {
        Ok(parsed_hash) => Argon2::default()
            .verify_password(body.password.as_bytes(), &parsed_hash)
            .map_or(false, |_| true),
        Err(_) => false,
    };

    // Si la validadacion no es correcta; devolvemos el fallo de que la contraseña es invalida
    if !is_valid {
        let error_response = serde_json::json!({
            "status": "fail",
            "message": "Invalid email or password"
        });
        return Err((StatusCode::BAD_REQUEST, Json(error_response)));
    }

    // Usamos la fecha actual para el token
    let now = chrono::Utc::now();
    let iat = now.timestamp() as usize;
    // El token sera valido por 60 min
    let exp = (now + chrono::Duration::minutes(60)).timestamp() as usize;
    let claims: TokenClaims = TokenClaims {
        sub: user.id.to_string(), // Guardamos el usuario tambien en el token
        exp,
        iat,
    };

    // Creamos el token con los datos anteriores y la secret
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(data.env.jwt_secret.as_ref()),
    )
    .unwrap();

    // Crearemos una cookie con el token que durara una hora
    let cookie = Cookie::build(("token", token.to_owned()))
        .path("/")
        .max_age(time::Duration::hours(1))
        .same_site(SameSite::None)
        .secure(true)
        .http_only(true);

    // Devolvemos exito si no fallo y devolvemos el token
    let mut response = Response::new(json!({"status": "success", "token": token}).to_string());
    response
        .headers_mut()
        // Insertamos la cookie en el cliente
        .insert(header::SET_COOKIE, cookie.to_string().parse().unwrap());
    Ok(response)
}

// Crearemos una funcion para el logout que no tiene parametros y devolvera un resultado con el codigo y json
pub async fn logout_handler() -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    // Para cerrar sesion mandamos un cookie para que sobreescriba al token pero vacio y con duracion negativa
    let cookie = Cookie::build(("token", ""))
        .path("/")
        .max_age(time::Duration::hours(-1))
        .same_site(SameSite::Lax)
        .http_only(true);

    // Devolvemos e insertamos al cliente la cookie vacia
    let mut response = Response::new(json!({"status": "success"}).to_string());
    response
        .headers_mut()
        .insert(header::SET_COOKIE, cookie.to_string().parse().unwrap());
    Ok(response)
}

// Esta funcion es para mostrar una vista de perfil protegida
pub async fn get_me_handler(
    Extension(user): Extension<User>, // En la extension se encuentra el usuario gracias al middleware de autentificacion
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    // Simplemente devolvemos al usuario con los datos filtrados
    let json_response = serde_json::json!({
        "status":  "success",
        "data": serde_json::json!({
            "user": filter_user_record(&user)
        })
    });

    Ok(Json(json_response))
}
