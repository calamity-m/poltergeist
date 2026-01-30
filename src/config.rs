use serde::Deserialize;

#[derive(Clone, Deserialize)]
pub struct Settings {
    pub issuer: String,
    pub grant_types_supported: Vec<String>,
    pub port: u16,
}

pub fn load_config() -> Settings {
    config::Config::builder()
        .add_source(config::File::with_name("config"))
        .build()
        .unwrap()
        .try_deserialize::<Settings>()
        .unwrap()
}
