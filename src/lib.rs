use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::RwLock;

use rand::{rngs::StdRng, FromEntropy, Rng};
use tide::{ExtractSeed, Cookies};

/// A random generated token identifying the session.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Token {
    rnd: [u8; 16],
}

/// Stores sesssions behind opaque tokens and recovers them.
pub struct Store<T> {
    inner: RwLock<StoreInner<T>>,
}

struct StoreInner<T> {
    rand: StdRng,
    active: HashMap<Token, T>,
}

/// Generic session data.
#[derive(Clone)]
pub struct Session<T>(pub T);

/// Marker struct to denote a missing or invalid session token.
pub struct Unauthorized;

impl<T> Store<T> {
    pub fn new() -> Self {
        Store {
            inner: RwLock::new(StoreInner::new()),
        }
    }

    /// Create a new session with provided data.
    ///
    /// Returns a token that can be used later to retrieve the session. The token itself is opaque
    /// data that does not leak any information to the client, so it may be returned to web clients
    /// in a cookie for example.
    pub fn create(&self, data: T) -> Token {
        self.inner.write().unwrap().create(data)
    }

    pub fn create_default(&self) -> Token where T: Default {
        self.create(T::default())
    }

    /// Retrieve the session associated with some token.
    pub fn get(&self, id: Token) -> Result<T, Unauthorized> where T: Clone {
        self.inner.read().unwrap().active.get(&id).cloned().ok_or(Unauthorized)
    }

    pub fn invalidate(&self, token: Token) -> Option<T> {
        self.inner.write().unwrap().active.remove(&token)
    }
}

impl<T> StoreInner<T> {
    fn new() -> Self {
        StoreInner {
            rand: FromEntropy::from_entropy(),
            active: HashMap::new(),
        }
    }

    fn create(&mut self, data: T) -> Token {
        let mut token = [0; 16];
        loop {
            self.rand.fill(&mut token);
            let real_token = Token { rnd: token };
            match self.active.entry(real_token) {
                Entry::Occupied(_) => (),
                Entry::Vacant(vacant) => {
                    vacant.insert(data);
                    return real_token;
                },
            }
        }
    }
}
