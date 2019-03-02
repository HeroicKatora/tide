#![feature(await_macro, futures_api)]
use std::iter::FromIterator;
use std::str::from_utf8;

use std::collections::HashMap;
use std::sync::Arc;

use base64::{decode_config, URL_SAFE};
use futures::future;
use http::{header, header::HeaderValue, StatusCode};
use pwhash::bcrypt;
use tide::{configuration::Store as ConfigStore, IntoResponse, Extract, ExtractSeed, Request, Response, RouteMatch};

/// Pre-hashed password data.
///
/// This is provided for convenience and should be used when loading/storing credentials from/to
/// disk.
pub struct Hashed {
    data: String,
}

/// A simple mapping of name to password data.
///
/// Passwords are of course not stored in plaintext, even in memory, but instead always hashed.
pub struct Credentials {
    inner: HashMap<String, Hashed>,
}

/// A frozen set of account data.
///
/// You can cheaply `Copy` this while referring to the same set of credentials.
///
/// This is a very simple way to implement a seeded extractor for an authorized `User`, based on a
/// shared frozen map of the credentials. Other libraries or implementations may provide more
/// elaborate ways to manage account data.
#[derive(Clone)]
pub struct AccountSet {
    credentials: Arc<Credentials>,
    realm: Realm,
}

/// A `realm` identifies some space to which a user/password combination is applicable.
#[derive(Clone)]
pub struct Realm(Arc<HeaderValue>);

#[derive(Debug)]
pub enum RealmError {
    /// The character can not be used in a realm.
    UnhandledCharacter,
}

/// Marker struct to denote a missing or invalid session token.
#[derive(Debug)]
pub struct Unauthorized;

/// An authorized user.
#[derive(Debug)]
pub struct User(pub String);

/// Seeded extractor that requires a specific user to log-in.
pub struct Protected {
    set: AccountSet,
    user: String
}

/// Data from the `Authorization` HTTP header.
pub enum Authorization {
    /// A valid request with basic authorization.
    Basic(String, String),

    /// Unknown or illformed header.
    Unknown,
}

impl Hashed {
    pub fn new<T: Into<String>>(data: T) -> Self {
        Hashed { data: data.into() }
    }

    pub fn hash(password: &str) -> Result<Self, pwhash::error::Error> {
        Ok(Hashed {
            data: bcrypt::hash(password)?,
        })
    }

    pub fn hashed(&self) -> &str {
        &self.data
    }
}

impl Credentials {
    pub fn new() -> Self {
        Credentials {
            inner: HashMap::new(),
        }
    }

    pub fn insert(&mut self, user: String, password: &str) -> bool {
        match Hashed::hash(password) {
            Ok(hashed) => self.prehashed(user, hashed),
            Err(_) => false,
        }
    }

    pub fn prehashed(&mut self, user: String, hashed: Hashed) -> bool {
        if let Some(_) = self.inner.get(&user) {
            return false;
        }

        assert!(self.inner.insert(user, hashed).is_none());
        true
    }

    pub fn check(&self, user: &str, password: &str) -> Result<(), Unauthorized> {
        match self.inner.get(user) {
            Some(hashed) if bcrypt::verify(password, hashed.hashed()) => Ok(()),
            // FIXME: this is horrible! and must NEVER get deployed. This probably offers an
            // incredibly cheap way for an attacker to probe the system for existing user names
            // through response timings.
            _ => Err(Unauthorized),
        }
    }

    /// Freeze the current credential set into a set of accounts.
    ///
    /// See `AccountSet` for more information.
    pub fn freeze(self, realm: Realm) -> AccountSet {
        AccountSet {
            realm,
            credentials: Arc::new(self),
        }
    }
}

impl Authorization {
    const BASIC: &'static [u8] = b"Basic ";

    pub fn from_header(request: &Request) -> Self {
        let mut auths = request.headers().get_all(header::AUTHORIZATION).iter();
        let first = auths.next();

        // Never accept two authorization headers at the same time
        if auths.next().is_some() {
            return Authorization::Unknown
        }

        let header = match first {
            None => return Authorization::Unknown,
            Some(header) => header.as_ref(),
        };

        let payload = match header.get(..Self::BASIC.len()) {
            Some(id) if id.eq_ignore_ascii_case(Self::BASIC) => &header[Self::BASIC.len()..],
            _ => return Authorization::Unknown,
        };

        // FIXME: relies on the outer framework to avoid resource exhaustion here.
        let payload = match decode_config(payload, URL_SAFE) {
            Ok(payload) => payload,
            Err(_) => return Authorization::Unknown,
        };

        let pw_pos = payload.iter().cloned()
            .position(|ch| ch == b':')
            .unwrap_or_else(|| payload.len());

        // always safe to access
        let user = &payload[..pw_pos];
        // this is not
        let password = payload.get(pw_pos + 1..)
            .unwrap_or(b"");

        let user = match from_utf8(user) {
            Ok(user) => user,
            Err(_) => return Authorization::Unknown,
        };

        let password = match from_utf8(password) {
            Ok(password) => password,
            Err(_) => return Authorization::Unknown,
        };

        Authorization::Basic(user.to_owned(), password.to_owned())
    }
}

impl AccountSet {
    pub fn credentials(&self) -> &Credentials {
        &self.credentials
    }

    pub fn realm(&self) -> &Realm {
        &self.realm
    }

    pub fn check(&self, authorization: Authorization) -> Option<User> {
        match authorization {
            Authorization::Basic(user, pass) => match self.credentials.check(&user, &pass) {
                Ok(()) => return Some(User(user)),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn single_user<U: Into<String>>(self, user: U) -> Protected {
        Protected {
            set: self,
            user: user.into(),
        }
    }

    pub fn authenticate(&self) -> Response {
        let mut response = ().with_status(StatusCode::UNAUTHORIZED).into_response();
        response.headers_mut()
            .insert(header::WWW_AUTHENTICATE, self.realm.www_authenticate().clone());
        response
    }
}

impl Realm {
    /// Construct a realm from its name.
    ///
    /// The name must already be escaped according to quoted-string escaping as defined in
    /// <https://tools.ietf.org/html/rfc7230#section-3.2.6>.
    ///
    /// FIXME: this should probably do the escaping itself.
    pub fn new<T: Into<String>>(name: T) -> Result<Self, RealmError> {
        let formatted = format!("Basic realm=\"{}\"", name.into());
        let value = HeaderValue::from_shared(formatted.into())
            .map_err(|_| RealmError::UnhandledCharacter)?;
            Ok(Realm(Arc::new(value)))
    }

    /// The value for a `WWW-Authenticate` header.
    pub fn www_authenticate(&self) -> &HeaderValue {
        &self.0
    }
}

impl FromIterator<(String, String)> for Credentials {
    fn from_iter<I>(iter: I) -> Self where I: IntoIterator<Item=(String, String)> {
        let mut empty = Self::new();
        iter.into_iter().for_each(|(user, pass)| { empty.insert(user, &pass); });
        empty
    }
}

impl<Data> Extract<Data> for Authorization 
    where Data: 'static
{
    type Fut = future::Ready<Result<Authorization, Response>>;

    fn extract(
        _: &mut Data,
        req: &mut Request,
        _: &Option<RouteMatch<'_>>,
        _: &ConfigStore,
    ) -> Self::Fut {
        future::ready(Ok(Authorization::from_header(req)))
    }
}

impl<Data> ExtractSeed<User, Data> for AccountSet {
    type Fut = future::Ready<Result<User, Response>>;

    fn extract(&self,
        _: &mut Data,
        req: &mut Request,
        _: &Option<RouteMatch<'_>>,
        _: &ConfigStore,
    ) -> Self::Fut {
        future::ready(match self.check(Authorization::from_header(req)) {
            Some(user) => Ok(user),
            None => Err(self.authenticate()),
        })
    }
}

impl<Data> ExtractSeed<Result<User, Unauthorized>, Data> for AccountSet {
    type Fut = future::Ready<Result<Result<User, Unauthorized>, Response>>;

    fn extract(&self,
        _: &mut Data,
        req: &mut Request,
        _: &Option<RouteMatch<'_>>,
        _: &ConfigStore,
    ) -> Self::Fut {
        let user = self.check(Authorization::from_header(req)).ok_or(Unauthorized);
        future::ready(Ok(user))
    }
}

impl<Data> ExtractSeed<User, Data> for Protected {
    type Fut = future::Ready<Result<User, Response>>;

    fn extract(&self,
        _: &mut Data,
        req: &mut Request,
        _: &Option<RouteMatch<'_>>,
        _: &ConfigStore,
    ) -> Self::Fut {
        let User(checked) = match self.set.check(Authorization::from_header(req)) {
            Some(user) => user,
            None => return future::ready(Err(self.set.authenticate())),
        };

        if checked != self.user {
           return future::ready(Err(self.set.authenticate()))
        }

        return future::ready(Ok(User(checked)))
    }
}
