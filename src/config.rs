use config;

#[derive(serde::Deserialize)]
pub struct AppConfig {
    pub host: String,
    pub port: u16,
}

pub fn read_config() -> Result<AppConfig, config::ConfigError> {
    let base_path = std::env::current_dir().expect("Failed to determine current directory path");
    let config_dir = base_path.join("config");

    let environment: Environment = std::env::var("APP_ENV")
        .unwrap_or_else(|_| "dev".into())
        .try_into()
        .expect("Failed to parse APP_ENV");

    let env_file = format!("{}.json", environment.as_str());

    let settings = config::Config::builder()
        .add_source(config::File::from(config_dir.join("base.json")))
        .add_source(config::File::from(config_dir.join(env_file)))
        .build()
        .unwrap_or_else(|err| panic!("Cannot read app config with error {:?}", err));

    settings.try_deserialize::<AppConfig>()
}

pub enum Environment {
    Dev,
    Production,
}

impl Environment {
    pub fn as_str(&self) -> &'static str {
        match self {
            Environment::Dev => "dev",
            Environment::Production => "production",
        }
    }
}

impl TryFrom<String> for Environment {
    type Error = String;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "dev" => Ok(Environment::Dev),
            "production" => Ok(Environment::Production),
            other => Err(format!(
                "{} is not a supported environment. Use either `local` or `production`.",
                other
            )),
        }
    }
}
