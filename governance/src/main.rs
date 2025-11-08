use std::time::Duration;

use actix_web::{App, HttpServer, web::Data};
use anyhow::Result;
use governance::{
    apidoc::get_swagger, handler::get_scope, kms::DirtyKMS, middlewares,
    vote_registry::VoteRegistry,
};

#[actix_web::main]
async fn main() -> Result<()> {
    println!("Governance Enclave Started!");

    HttpServer::new(move || {
        let vote_registry = VoteRegistry::new();
        let kms = DirtyKMS::default();
        let server = App::new().wrap(middlewares::ratelimiter::get_rate_limiter(
            Duration::from_secs(1),
            15,
        ));
        server
            .app_data(Data::new(vote_registry))
            .app_data(Data::new(kms))
            .service(get_swagger())
            .service(get_scope::<DirtyKMS>())
    })
    .bind(("0.0.0.0", 3001))? // listen on all interfaces, port 3001
    .run()
    .await?; // await server, bubble up error if any

    Ok(())
}
