use glob::Pattern;
use tracing::{subscriber::set_global_default, Subscriber};
use tracing_bunyan_formatter::BunyanFormattingLayer;
use tracing_log::LogTracer;
use tracing_subscriber::{
    layer::{Filter, SubscriberExt},
    EnvFilter, Layer, Registry,
};

pub fn setup_subscriber() -> impl Subscriber + Sync + Send {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let file_filter = FileFilter::new("**/dev/**".to_string());
    let format_layer = BunyanFormattingLayer::new("taskfi-tlsn".to_string(), std::io::stdout);

    Registry::default()
        .with(env_filter)
        .with(format_layer.with_filter(file_filter))
}

/// Register a subscriber as global default to process span data.
///
/// It should only be called once!
pub fn init_subscriber(subscriber: impl Subscriber + Sync + Send) {
    LogTracer::init().expect("Failed to set logger");
    set_global_default(subscriber).expect("Failed to set subscriber");
}

pub struct FileFilter {
    pattern: Pattern,
}

impl FileFilter {
    pub fn new(filter: String) -> Self {
        let pattern = Pattern::new(&filter).expect("Filter should be a valid glob");
        Self { pattern }
    }
}

impl<S: Subscriber> Filter<S> for FileFilter {
    fn enabled(
        &self,
        meta: &tracing::Metadata<'_>,
        _: &tracing_subscriber::layer::Context<'_, S>,
    ) -> bool {
        let source = match meta.file() {
            Some(source) => source,
            None => return true,
        };

        !self.pattern.matches(source)
    }
}
