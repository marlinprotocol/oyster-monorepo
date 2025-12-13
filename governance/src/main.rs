use std::time::Duration;

use actix_web::{App, HttpServer, web::Data};
use anyhow::Result;
use governance::{
    apidoc::get_swagger,
    handler::get_scope,
    kms,
    middlewares::{self, allow_all_cors::allow_all},
    vote_registry::VoteRegistry,
};

#[cfg(feature = "dirty_kms")]
type ActiveKms = kms::kms::DirtyKMS;

#[cfg(not(feature = "dirty_kms"))]
type ActiveKms = kms::oyster_kms::OysterKms;

#[actix_web::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    log::info!("Governance Enclave Started!");

    HttpServer::new(move || {
        let vote_registry = VoteRegistry::new();
        let kms = ActiveKms::default();

        let server = App::new()
            .wrap(middlewares::ratelimiter::get_rate_limiter(
                Duration::from_secs(1),
                15,
            ))
            .wrap(allow_all());
        server
            .app_data(Data::new(vote_registry))
            .app_data(Data::new(kms))
            .service(get_swagger())
            .service(get_scope::<ActiveKms>())
    })
    .bind(("0.0.0.0", 3001))? // listen on all interfaces, port 3001
    .run()
    .await?; // await server, bubble up error if any

    Ok(())
}
