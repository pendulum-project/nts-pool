use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct Servers {
    pub servers: Vec<String>,
}
