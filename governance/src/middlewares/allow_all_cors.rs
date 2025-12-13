use actix_cors::Cors;

pub fn allow_all() -> Cors {
    Cors::default()
        .allow_any_origin()
        .allow_any_method()
        .allow_any_header()
        .supports_credentials()
        .max_age(3600)
}
