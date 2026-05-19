use mebsuta::{Format, Handler, Level, MultiHandler, StdoutHandler, arc_record};

fn main() {
    let h = MultiHandler::new(vec![
        Box::new(StdoutHandler::new(Level::Info, Format::Json)),
        Box::new(StdoutHandler::new(Level::Debug, Format::Text)),
    ]);

    h.handle(&arc_record(Level::Info, "fan-out to both"))
        .unwrap();
    h.handle(&arc_record(Level::Warn, "warning message"))
        .unwrap();
    h.flush();
}
