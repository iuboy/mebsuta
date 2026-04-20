use mebsuta::{Format, Handler, Level, Sampling, StdoutHandler, arc_record};

fn main() {
    let stdout = StdoutHandler::new(Level::Info, Format::Json);
    let sampling: Sampling<StdoutHandler> = Sampling::new(stdout, 5, 3, 100);

    for i in 0..20 {
        let r = arc_record(Level::Info, format!("message {i}"));
        sampling.handle(&r).unwrap();
    }

    sampling.flush();
}
