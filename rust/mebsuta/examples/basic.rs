use mebsuta::{Format, Handler, Level, Sampling, StdoutHandler, arc_record};

fn main() {
    let stdout = StdoutHandler::new(Level::Info, Format::Json);
    let sampling: Sampling<StdoutHandler> = Sampling::new(stdout, 5, 10, 100);

    for i in 0..30 {
        let record = arc_record(Level::Info, format!("message {i}"));
        let _ = sampling.handle(&record);
    }

    sampling.flush();
}
