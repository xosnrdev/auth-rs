use auth::{
    bootstrap::run_application,
    utils::{AppResult, CONFIG},
};
use dotenvy::dotenv;

#[tokio::main]
async fn main() -> AppResult<()> {
    dotenv().ok();
    run_application(CONFIG.to_owned()).await
}
