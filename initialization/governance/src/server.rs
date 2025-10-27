use std::sync::Arc;
use tokio::sync::RwLock;
use warp::Filter;

use crate::types::ApiResponse;

pub async fn serve_result_api(state: Arc<RwLock<ApiResponse>>) {
    let route = warp::path("result").and(warp::get()).and_then({
        let state = state.clone();
        move || {
            let state = state.clone();
            async move {
                let resp = state.read().await.clone();
                Ok::<_, warp::Rejection>(warp::reply::json(&resp))
            }
        }
    });

    println!("[server] Starting API server on port 8080...");
    warp::serve(route).run(([0, 0, 0, 0], 8080)).await;
}
