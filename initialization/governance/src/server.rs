use std::sync::Arc;
use warp::Filter;

use crate::types::VoteResult;

pub async fn serve_result_api(result: VoteResult) {
    let result = Arc::new(result);

    let route = warp::path("result").and(warp::get()).map({
        let result = result.clone();
        move || warp::reply::json(&*result)
    });

    println!("[server] Starting API server on port 8080...");
    warp::serve(route).run(([0, 0, 0, 0], 8080)).await;
}
