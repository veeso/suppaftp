//! # Tls
//!
//! Tls wrappers

#[cfg(feature = "async-native-tls")]
mod native_tls;
#[cfg(feature = "async-native-tls")]
pub use self::native_tls::TlsConnector;

#[cfg(feature = "async-rustls")]
mod rustls;
#[cfg(feature = "async-rustls")]
pub use self::rustls::TlsConnector;
