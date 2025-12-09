pub mod gossip;

use std::{
    fmt::{self, Display, Formatter},
    net::SocketAddr,
    str::FromStr,
};

use sillad::{
    Pipe,
    dialer::{Dialer, DialerExt},
    listener::{DynListener, ListenerExt},
    tcp::{TcpDialer, TcpListener},
};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum NetAddr {
    Tcp(SocketAddr),
}

#[derive(Debug)]
pub enum NetAddrParseError {
    UnknownScheme,
    InvalidSocketAddr(std::net::AddrParseError),
}

impl Display for NetAddrParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            NetAddrParseError::UnknownScheme => write!(f, "unknown network scheme"),
            NetAddrParseError::InvalidSocketAddr(err) => {
                write!(f, "invalid socket address: {err}")
            }
        }
    }
}

impl std::error::Error for NetAddrParseError {}

impl FromStr for NetAddr {
    type Err = NetAddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        const TCP_PREFIX: &str = "tcp://";
        let addr = s
            .strip_prefix(TCP_PREFIX)
            .ok_or(NetAddrParseError::UnknownScheme)?;
        let socket_addr = addr
            .parse::<SocketAddr>()
            .map_err(NetAddrParseError::InvalidSocketAddr)?;
        Ok(NetAddr::Tcp(socket_addr))
    }
}

impl Display for NetAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            NetAddr::Tcp(addr) => write!(f, "tcp://{addr}"),
        }
    }
}

impl NetAddr {
    /// Connect to this address, returning a type-erased sillad pipe.
    pub async fn connect(&self) -> std::io::Result<Box<dyn Pipe>> {
        match self {
            NetAddr::Tcp(addr) => TcpDialer { dest_addr: *addr }.dynamic().dial().await,
        }
    }

    /// Bind a listener at this address, returning a type-erased sillad listener.
    pub async fn bind(&self) -> std::io::Result<DynListener> {
        match self {
            NetAddr::Tcp(addr) => {
                let listener = TcpListener::bind(*addr).await?;
                Ok(listener.dynamic())
            }
        }
    }
}
