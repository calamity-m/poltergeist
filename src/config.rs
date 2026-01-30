use serde::Deserialize;

#[derive(Clone, Deserialize)]
pub struct Settings {
    pub issuer: String,
    pub grant_types_supported: Vec<String>,
    pub port: u16,
    pub upstream_oidc_url: String,
    pub upstream_jwks_url: String,
    pub validate_upstream_token: bool,
    pub private_key_path: String,
}

pub fn load_config() -> Settings {
    config::Config::builder()
        .add_source(config::File::with_name("config"))
        .build()
        .unwrap()
        .try_deserialize::<Settings>()
        .unwrap()
}
