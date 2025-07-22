use uuid::Uuid;

pub struct Server {
    id: Uuid,
    owner: Uuid,
    hostname: String,
    port: Option<u16>,
    countries: Vec<String>,
}

pub struct NewServer {}
