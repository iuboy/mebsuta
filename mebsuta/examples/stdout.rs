use mebsuta::{Format, Handler, Level, StdoutHandler, arc_record};

fn main() {
    let h = StdoutHandler::new(Level::Info, Format::Json);
    let r = arc_record(Level::Info, "hello world");
    h.handle(&r).unwrap();
    h.flush();
}
