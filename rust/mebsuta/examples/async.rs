use mebsuta::{Async, Format, Handler, Level, StdoutHandler, arc_record};

fn main() {
    let inner = StdoutHandler::new(Level::Info, Format::Json);
    let mut async_h = Async::new(inner);

    for i in 0..10 {
        let r = arc_record(Level::Info, format!("async msg {i}"));
        async_h.handle(&r).unwrap();
    }

    async_h.close_if_needed();
    println!("dropped: {}", async_h.dropped());
}
