#![feature(await_macro, futures_api)]
use std::pin::Pin;

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::RwLock;

use base64::{decode_config_slice, encode_config, URL_SAFE};
use cookie::Cookie;
use futures::future::{self, Future, TryFutureExt as _};
use http::{header, header::HeaderValue};
use rand::{rngs::StdRng, FromEntropy, Rng};
use tide::{configuration::Store as ConfigStore, Cookies, Extract, ExtractSeed, Request, Response, RouteMatch};

/// A random generated token identifying the session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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

/// Marker struct to denote a missing or invalid session token.
pub struct Unauthorized;

/// Newtype wrapper to implement `Extract` the client side token.
///
/// The contained value is `None` when `session_id` cookie has an invalid format or is not set,
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SessionToken(Option<Token>);

/// Generic session data.
#[derive(Clone)]
pub struct Session<T> {
    token: Token,
    new: bool,
    data: T,
}

/// Seeded extractor that attaches session data or uses an existing one.
pub struct GetOrCreate<P>(pub P);

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

    async fn get_or_create<P, F>(ptr: P, f: F) -> Result<Session<T>, Response>
    where
        P: AsRef<Self>,
        F: Future<Output=Result<SessionToken, Response>>,
        T: Default + Clone,
    {
        match r#await!(f)?.0 {
            Some(token) => match ptr.as_ref().get(token) {
                Ok(data) => return Ok(Session {
                    token,
                    new: false,
                    data,
                }),
                Err(_) => (),
            },
            None => (),
        }

        let token = ptr.as_ref().create_default();
        // Shouldn't fail because we just created this data.
        let data = ptr.as_ref().get(token).unwrap_or_else(|_|
            panic!("The session data just inserted is no longer there"));
        Ok(Session {
            token,
            new: true,
            data,
        })
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

impl Token {
    const COOKIE_KEY: &'static str = "session_id";

    fn from_cookies(cookies: Cookies) -> Option<Self> {
        let session = cookies.get(Self::COOKIE_KEY)
            .map(|session| session.value())
            .unwrap_or("");

        let mut token = [0; 16];
        let len = decode_config_slice(session, URL_SAFE, &mut token)
            .unwrap_or(0);

        if len == token.len() {
            Some(Token { rnd: token })
        } else {
            None
        }
    }

    fn into_cookie(self) -> Cookie<'static> {
        let session_id = encode_config(&self.rnd[..], URL_SAFE);
        Cookie::build("session_id", session_id)
            .secure(true)
            .http_only(true)
            .finish()
    }
}

impl SessionToken {
    fn from_cookies(cookies: Cookies) -> Self {
        SessionToken(Token::from_cookies(cookies))
    }
}

impl<T> Session<T> {
    /// Ensure that the client has the token.
    pub fn attach(&self, response: &mut Response) {
        if self.new {
            let cookie = format!("{}", self.token.into_cookie());
            let value = HeaderValue::from_shared(cookie.into())
                // This should never fail as cookie gives well formatted header values.
                .unwrap();
            response.headers_mut()
                .append(header::SET_COOKIE, value);
        }
    }

    pub fn data(&self) -> &T {
        &self.data
    }

    pub fn data_mut(&mut self) -> &mut T {
        &mut self.data
    }
}

impl<Data> Extract<Data> for SessionToken
    where Data: 'static
{
    type Fut = future::MapOk<<Cookies as Extract<Data>>::Fut, fn(Cookies) -> Self>;

    fn extract(
        data: &mut Data,
        req: &mut Request,
        params: &Option<RouteMatch<'_>>,
        store: &ConfigStore,
    ) -> Self::Fut {
        // The future is `future::Ready`, so we can convert.
        Cookies::extract(data, req, params, store)
            .map_ok(Self::from_cookies)
    }
}

impl<T, P, Data> ExtractSeed<Session<T>, Data> for GetOrCreate<P> 
where
    P: AsRef<Store<T>> + Clone + Send + Sync + 'static,
    T: Clone + Default + Send + Sync + 'static,
    Data: 'static,
{
    type Fut = Pin<Box<Future<Output=Result<Session<T>, Response>> + Send>>;

    fn extract(&self,
        data: &mut Data,
        req: &mut Request,
        params: &Option<RouteMatch<'_>>,
        store: &ConfigStore,
    ) -> Self::Fut {
        Box::pin(Store::get_or_create(self.0.clone(), SessionToken::extract(data, req, params, store)))
    }
}
