#![feature(async_await, futures_api)]
use std::sync::{atomic::AtomicUsize, Arc};

use tide::{App, IntoResponse, Seeded, Response};
use tide_session::{GetOrCreate, Store, Session, SessionToken};

struct Counter(Arc<AtomicUsize>);

async fn introspect(token: SessionToken) -> String {
    format!("{:?}", token)
}

async fn incremental(session: Session<Counter>) -> String {
    unimplemented!()
}

fn main() {
    let mut app = tide::App::new(());
    let store = Arc::new(Store::<Counter>::new());
    app.at("/self").get(introspect);
    // app.at("/").get(Seeded(incremental, GetOrCreate(store)));

    app.serve();
}
