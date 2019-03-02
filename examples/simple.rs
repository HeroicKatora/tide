#![feature(async_await, futures_api)]
use tide::{App, Seeded};
use tide_authorize::{Credentials, Realm, Unauthorized, User};

/// Does not enforce any authentication but accepts it.
async fn introspect(user: Result<User, Unauthorized>) -> String {
    match user {
        Ok(User(user)) => format!("Hello {}", user),
        Err(_) => "No user logged authentication".into(),
    }
}

async fn member(User(user): User) -> String {
    format!("Only accessible to users. Like you, handsome {}", user)
}

async fn admin(User(_): User) -> &'static str {
    "Highly secure admin page"
}

fn main() {
    let mut app = App::new(());
    let realm = Realm::new("WorldOfPureImagination").unwrap();
    let credentials: Credentials = vec![
        ("irc".into(), "hunter2".into()),
        ("admin".into(), "admin".into()),
    ].into_iter().collect();
    let accounts = credentials.freeze(realm);

    app.at("/self").get(Seeded(introspect, accounts.clone()));
    app.at("/").get(Seeded(member, accounts.clone()));
    app.at("/admin").get(Seeded(admin, accounts.single_user("admin")));

    app.serve();
}
