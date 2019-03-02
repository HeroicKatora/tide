# A session addon for Tide

Provided that the [seeded extractors PR](https://github.com/rustasync/tide/pull/126)
is accepted, this could serve as a starting point for session management in Tide.
The main part is a new type `Session<T>` which can extract a session from a
token provided in the cookies or push such a cookie to the client. This is
built with third-party crates in mind, and consequently this also is not
integrated into Tide but rather added outside.

## Example

My dynamically configuring an endpoint with seeds for an extractor, this avoid
having to type everything with the specific `AppData` instance to be used.
Instead, the type only relates to the session data (which should be `Default +
Clone` for the set of extractors provided here, but that is not an inherent
restriction).

```
#[derive(Clone, Default)]
struct Counter(Arc<AtomicUsize>);

async fn incremental(session: Session<Counter>) -> Response {
    let previous = session.data().0.fetch_add(1, Ordering::AcqRel);
    let body = format!("You have been here {} previous times", previous);
    let mut response = body.into_response();
    session.attach(&mut response);
    response
}

fn main() {
    let store = Default::default();
    app.at("/").get(Seeded(incremental, GetOrCreate(store)));
    app.serve();
}
```

> $ cargo run --example simple

[Full example here](./examples/simple.rs)

