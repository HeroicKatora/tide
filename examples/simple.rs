#![feature(async_await, futures_api)]
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tide::{App, IntoResponse, Seeded, Response};
use tide_session::{GetOrCreate, Store, Session, SessionToken};

#[derive(Clone, Default)]
struct Counter(Arc<AtomicUsize>);

async fn introspect(token: SessionToken) -> String {
    format!("{:?}", token)
}

async fn incremental(session: Session<Counter>) -> Response {
    let previous = session.data().0.fetch_add(1, Ordering::AcqRel);
    let body = format!("You have been here {} previous times", previous);
    let mut response = body.into_response();
    session.attach(&mut response);
    response
}

fn main() {
    let mut app = App::new(());
    let store = {
        let mut store = Store::new();
        store.disable_secure_for_impossible_https();
        Arc::new(store)
    };
    app.at("/self").get(introspect);
    app.at("/").get(Seeded(incremental, GetOrCreate(store)));

    app.serve();
}
