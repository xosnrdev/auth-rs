use dotenvy::dotenv;

use auth_rs::{
    bootstrap::run_application,
    utils::{AppResult, CONFIG},
};

#[tokio::main]
async fn main() -> AppResult<()> {
    dotenv().ok();
    run_application(CONFIG.to_owned()).await
}
