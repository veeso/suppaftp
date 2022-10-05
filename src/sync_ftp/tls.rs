//! # Tls
//!
//! Tls wrappers

#[cfg(feature = "native-tls")]
mod native_tls;
#[cfg(feature = "native-tls")]
pub use self::native_tls::{TlsConnector, TlsStream};

#[cfg(feature = "rustls")]
mod rustls;
#[cfg(feature = "rustls")]
pub use self::rustls::{TlsConnector, TlsStream};
