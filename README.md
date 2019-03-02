# An authentication addon for Tide

Provided that the [seeded extractors PR](https://github.com/rustasync/tide/pull/126)
is accepted, this could serve as a starting point for authentication in Tide.
Provides a basic set for storing user/password and for protecting an endpoint
by requiring a specific type in the method parameters. This is built with
third-party crates in mind, and consequently this also is not integrated into
Tide but rather added outside. Specifically, the `Credentials` and `User` types
may be reused for other authentication than `Basic` as provided here.

## Example

Dynamically configuring an endpoint with seeds for an extractor provides a
pretty neat way to protect some endpoint against all but a specific user:

```
async fn admin(User(_): User) -> &'static str {
    "Highly secure admin page"
}

fn main() {
    let accounts = credentials.freeze(realm);
    …
    app.at("/admin").get(Seeded(admin, accounts.single_user("admin")));
    app.server();
}
```

> $ cargo run --example simple

[Full example here](./examples/simple.rs)

