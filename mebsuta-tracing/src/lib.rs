//! Tracing bridge for mebsuta.
//!
//! `MebsutaLayer` implements `tracing::Layer` and forwards events
//! to a mebsuta `Handler`.

use std::sync::Arc;

use mebsuta::{Handler, Level, RecordBuilder};

/// Tracing layer that bridges tracing events to mebsuta handlers.
pub struct MebsutaLayer<H> {
    handler: H,
}

impl<H: Handler + Clone + 'static> MebsutaLayer<H> {
    pub fn new(handler: H) -> Self {
        MebsutaLayer { handler }
    }
}

impl<H, S> tracing_subscriber::Layer<S> for MebsutaLayer<H>
where
    H: Handler + Clone + 'static,
    S: tracing_core::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn on_event(
        &self,
        event: &tracing_core::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let level = match *event.metadata().level() {
            l if l == tracing_core::Level::ERROR => Level::Error,
            l if l == tracing_core::Level::WARN => Level::Warn,
            l if l == tracing_core::Level::INFO => Level::Info,
            l if l == tracing_core::Level::DEBUG => Level::Debug,
            _ => Level::Trace,
        };

        let mut visitor = MebsutaVisitor::new();
        event.record(&mut visitor);

        let mut builder = RecordBuilder::new(level, visitor.message)
            .module_path(event.metadata().module_path().unwrap_or(""))
            .file(event.metadata().file().unwrap_or(""))
            .line(event.metadata().line().unwrap_or(0));

        for (k, v) in visitor.attrs {
            builder = builder.attr(k, v);
        }

        let _ = self.handler.handle(&Arc::new(builder.build()));
    }
}

struct MebsutaVisitor {
    message: String,
    attrs: Vec<(mebsuta::Key, mebsuta::Value)>,
}

impl MebsutaVisitor {
    fn new() -> Self {
        MebsutaVisitor {
            message: String::new(),
            attrs: Vec::new(),
        }
    }
}

impl tracing_core::field::Visit for MebsutaVisitor {
    fn record_str(&mut self, field: &tracing_core::Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_owned();
        } else {
            self.attrs
                .push((field.name().into(), value.to_owned().into()));
        }
    }

    fn record_debug(&mut self, field: &tracing_core::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        } else {
            self.attrs
                .push((field.name().into(), format!("{value:?}").into()));
        }
    }

    fn record_i64(&mut self, field: &tracing_core::Field, value: i64) {
        self.attrs.push((field.name().into(), value.into()));
    }

    fn record_u64(&mut self, field: &tracing_core::Field, value: u64) {
        self.attrs.push((field.name().into(), value.into()));
    }

    fn record_bool(&mut self, field: &tracing_core::Field, value: bool) {
        self.attrs.push((field.name().into(), value.into()));
    }

    fn record_f64(&mut self, field: &tracing_core::Field, value: f64) {
        self.attrs.push((field.name().into(), value.into()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layer_constructs_with_stdout() {
        let handler = mebsuta::StdoutHandler::new(mebsuta::Level::Info, mebsuta::Format::Json);
        let _layer = MebsutaLayer::new(handler);
    }

    #[test]
    fn layer_constructs_with_text_format() {
        let handler = mebsuta::StdoutHandler::new(mebsuta::Level::Debug, mebsuta::Format::Text);
        let _layer = MebsutaLayer::new(handler);
    }
}
