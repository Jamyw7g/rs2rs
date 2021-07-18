use std::{
    fmt::{self, Debug},
    io::{self, ErrorKind},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    str::FromStr,
};

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub use self::consts::{
    SOCKS5_AUTH_METHOD_GSSAPI, SOCKS5_AUTH_METHOD_NONE, SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE,
    SOCKS5_AUTH_METHOD_PASSWORD,
};

mod consts {
    pub const SOCKS5_VERSION: u8 = 0x05;

    pub const SOCKS5_AUTH_METHOD_NONE: u8 = 0x00;
    pub const SOCKS5_AUTH_METHOD_GSSAPI: u8 = 0x01;
    pub const SOCKS5_AUTH_METHOD_PASSWORD: u8 = 0x02;
    pub const SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE: u8 = 0xff;

    pub const SOCKS5_CMD_TCP_CONNECT: u8 = 0x01;
    pub const SOCKS5_CMD_TCP_BIND: u8 = 0x02;
    pub const SOCKS5_CMD_UDP_ASSOCIATE: u8 = 0x03;

    pub const SOCKS5_ADDR_TYPE_IPV4: u8 = 0x01;
    pub const SOCKS5_ADDR_TYPE_DOMAIN_NAME: u8 = 0x03;
    pub const SOCKS5_ADDR_TYPE_IPV6: u8 = 0x04;

    pub const SOCKS5_REPLY_SUCCEEDED: u8 = 0x00;
    pub const SOCKS5_REPLY_GENERAL_FAILURE: u8 = 0x01;
    pub const SOCKS5_REPLY_CONNECTION_NOT_ALLOWED: u8 = 0x02;
    pub const SOCKS5_REPLY_NETWORK_UNREACHABLE: u8 = 0x03;
    pub const SOCKS5_REPLY_HOST_UNREACHABLE: u8 = 0x04;
    pub const SOCKS5_REPLY_CONNECTION_REFUSE: u8 = 0x05;
    pub const SOCKS5_REPLY_TTL_EXPIRED: u8 = 0x06;
    pub const SOCKS5_REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;
    pub const SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

#[derive(Debug, Clone, Copy)]
pub enum Command {
    TcpConnect,
    TcpBind,
    UdpAssociate,
}

impl Command {
    #[inline]
    pub fn as_u8(self) -> u8 {
        match self {
            Self::TcpConnect => consts::SOCKS5_CMD_TCP_CONNECT,
            Self::TcpBind => consts::SOCKS5_CMD_TCP_BIND,
            Self::UdpAssociate => consts::SOCKS5_CMD_UDP_ASSOCIATE,
        }
    }

    #[inline]
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            consts::SOCKS5_CMD_TCP_CONNECT => Some(Self::TcpConnect),
            consts::SOCKS5_CMD_TCP_BIND => Some(Self::TcpBind),
            consts::SOCKS5_CMD_UDP_ASSOCIATE => Some(Self::UdpAssociate),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Reply {
    Succeeded,
    GeneralFailure,
    ConnecionNotAllowed,
    NetWorkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSupported,

    OtherReply(u8),
}

impl Reply {
    #[inline]
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Succeeded => consts::SOCKS5_REPLY_SUCCEEDED,
            Self::GeneralFailure => consts::SOCKS5_REPLY_GENERAL_FAILURE,
            Self::ConnecionNotAllowed => consts::SOCKS5_REPLY_CONNECTION_NOT_ALLOWED,
            Self::NetWorkUnreachable => consts::SOCKS5_REPLY_NETWORK_UNREACHABLE,
            Self::HostUnreachable => consts::SOCKS5_REPLY_HOST_UNREACHABLE,
            Self::ConnectionRefused => consts::SOCKS5_REPLY_CONNECTION_REFUSE,
            Self::TtlExpired => consts::SOCKS5_REPLY_TTL_EXPIRED,
            Self::CommandNotSupported => consts::SOCKS5_REPLY_COMMAND_NOT_SUPPORTED,
            Self::AddressTypeNotSupported => consts::SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
            Self::OtherReply(c) => c,
        }
    }

    #[inline]
    pub fn from_u8(code: u8) -> Self {
        match code {
            consts::SOCKS5_REPLY_GENERAL_FAILURE => Self::GeneralFailure,
            consts::SOCKS5_REPLY_CONNECTION_NOT_ALLOWED => Self::ConnecionNotAllowed,
            consts::SOCKS5_REPLY_NETWORK_UNREACHABLE => Self::NetWorkUnreachable,
            consts::SOCKS5_REPLY_HOST_UNREACHABLE => Self::HostUnreachable,
            consts::SOCKS5_REPLY_CONNECTION_REFUSE => Self::ConnectionRefused,
            consts::SOCKS5_REPLY_TTL_EXPIRED => Self::TtlExpired,
            consts::SOCKS5_REPLY_COMMAND_NOT_SUPPORTED => Self::CommandNotSupported,
            consts::SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED => Self::AddressTypeNotSupported,
            _ => Self::OtherReply(code),
        }
    }
}

impl fmt::Display for Reply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Succeeded => write!(f, "Succeeded"),
            Self::GeneralFailure => write!(f, "General failure"),
            Self::ConnecionNotAllowed => write!(f, "Connecion not allowed"),
            Self::NetWorkUnreachable => write!(f, "NetWork unreachable"),
            Self::HostUnreachable => write!(f, "Host unreachable"),
            Self::ConnectionRefused => write!(f, "Connection refused"),
            Self::TtlExpired => write!(f, "Ttl expired"),
            Self::CommandNotSupported => write!(f, "Command not supported"),
            Self::AddressTypeNotSupported => write!(f, "Address type not supported"),
            Self::OtherReply(c) => write!(f, "Other reply ({})", c),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    IoError(#[from] io::Error),
    #[error("address type {0:#x} not supported")]
    AddressTypeNotSupported(u8),
    #[error("address domain name must be UTF-8 encoding")]
    AddressDomainInvalidEncoding,
    #[error("unspported socks version {0:#x}")]
    UnsupportedSocksVersion(u8),
    #[error("unspported command {0:#x}")]
    UnsupportedCommand(u8),
    #[error("{0}")]
    Reply(Reply),
}

impl From<Error> for io::Error {
    fn from(err: Error) -> Self {
        match err {
            Error::IoError(e) => e,
            e => io::Error::new(ErrorKind::Other, e),
        }
    }
}

impl Error {
    pub fn as_reply(&self) -> Reply {
        match self {
            Error::IoError(e) => match e.kind() {
                ErrorKind::ConnectionRefused => Reply::ConnectionRefused,
                _ => Reply::GeneralFailure,
            },
            Error::AddressTypeNotSupported(_) => Reply::AddressTypeNotSupported,
            Error::AddressDomainInvalidEncoding => Reply::GeneralFailure,
            Error::UnsupportedSocksVersion(_) => Reply::GeneralFailure,
            Error::UnsupportedCommand(_) => Reply::CommandNotSupported,
            Error::Reply(r) => *r,
        }
    }
}

#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum Address {
    SocketAddress(SocketAddr),
    DomainNameAddress(String, u16),
}

impl Address {
    pub const MAX_SERIALIED_LEN: usize = 1 + 1 + 255 + 2;

    pub async fn read_from<R>(stream: &mut R) -> Result<Address, Error>
    where
        R: AsyncRead + Unpin,
    {
        let atyp = stream.read_u8().await?;
        match atyp {
            consts::SOCKS5_ADDR_TYPE_IPV4 => {
                let ip = Ipv4Addr::from(stream.read_u32().await?);
                let port = stream.read_u16().await?;
                Ok(Address::SocketAddress(SocketAddr::V4(SocketAddrV4::new(
                    ip, port,
                ))))
            }
            consts::SOCKS5_ADDR_TYPE_IPV6 => {
                let ip = Ipv6Addr::from(stream.read_u128().await?);
                let port = stream.read_u16().await?;
                Ok(Address::SocketAddress(SocketAddr::V6(SocketAddrV6::new(
                    ip, port, 0, 0,
                ))))
            }
            consts::SOCKS5_ADDR_TYPE_DOMAIN_NAME => {
                let len = stream.read_u8().await? as usize;
                let mut domain_buf = vec![0; len];

                stream.read_exact(&mut domain_buf).await?;
                let domain = match String::from_utf8(domain_buf) {
                    Ok(s) => s,
                    Err(_) => return Err(Error::AddressDomainInvalidEncoding),
                };
                let port = stream.read_u16().await?;
                Ok(Address::DomainNameAddress(domain, port))
            }
            _ => Err(Error::AddressTypeNotSupported(atyp)),
        }
    }

    #[inline]
    pub async fn write_to<W>(&self, writer: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        writer.write_all(&buf).await
    }

    #[inline]
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        write_address(self, buf);
    }

    #[inline]
    pub fn serialized_len(&self) -> usize {
        get_addr_len(self)
    }

    pub fn port(&self) -> u16 {
        match self {
            Self::SocketAddress(addr) => addr.port(),
            Self::DomainNameAddress(_, port) => *port,
        }
    }

    pub fn host(&self) -> String {
        match self {
            Self::SocketAddress(addr) => addr.ip().to_string(),
            Self::DomainNameAddress(name, _) => name.clone(),
        }
    }
}

impl Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::SocketAddress(addr) => write!(f, "{}", addr),
            Address::DomainNameAddress(domain, port) => write!(f, "{}:{}", domain, port),
        }
    }
}
impl From<SocketAddr> for Address {
    fn from(addr: SocketAddr) -> Self {
        Self::SocketAddress(addr)
    }
}

impl From<(String, u16)> for Address {
    fn from((name, port): (String, u16)) -> Self {
        Self::DomainNameAddress(name, port)
    }
}

impl From<&Address> for Address {
    fn from(addr: &Address) -> Self {
        addr.clone()
    }
}

#[derive(Debug)]
pub struct AddressError;

impl FromStr for Address {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.parse::<SocketAddr>() {
            Ok(addr) => Ok(Address::SocketAddress(addr)),
            Err(_) => {
                if let Some((name, port)) = s.split_once(':') {
                    match port.parse::<u16>() {
                        Ok(port) => Ok(Address::DomainNameAddress(name.to_owned(), port)),
                        Err(_) => Err(AddressError),
                    }
                } else {
                    Err(AddressError)
                }
            }
        }
    }
}

fn write_ipv4_addr<B: BufMut>(addr: &SocketAddrV4, buf: &mut B) {
    buf.put_u8(consts::SOCKS5_ADDR_TYPE_IPV4);
    buf.put_slice(&addr.ip().octets());
    buf.put_u16(addr.port());
}

fn write_ipv6_addr<B: BufMut>(addr: &SocketAddrV6, buf: &mut B) {
    buf.put_u8(consts::SOCKS5_ADDR_TYPE_IPV6);
    buf.put_slice(&addr.ip().octets());
    buf.put_u16(addr.port());
}

fn write_domain_addr<B: BufMut>(domain: &str, port: u16, buf: &mut B) {
    assert!(
        domain.len() <= 255,
        "domain name length must be smaller than 256"
    );
    let len = domain.len() as u8;

    buf.put_u8(consts::SOCKS5_ADDR_TYPE_DOMAIN_NAME);
    buf.put_u8(len);
    buf.put_slice(domain.as_bytes());
    buf.put_u16(port);
}

fn write_socket_addr<B: BufMut>(addr: &SocketAddr, buf: &mut B) {
    match addr {
        SocketAddr::V4(addr) => write_ipv4_addr(addr, buf),
        SocketAddr::V6(addr) => write_ipv6_addr(addr, buf),
    }
}

fn write_address<B: BufMut>(addr: &Address, buf: &mut B) {
    match addr {
        Address::SocketAddress(addr) => write_socket_addr(addr, buf),
        Address::DomainNameAddress(domain, port) => write_domain_addr(domain, *port, buf),
    }
}

#[inline]
fn get_addr_len(atyp: &Address) -> usize {
    match atyp {
        Address::SocketAddress(SocketAddr::V4(_)) => 1 + 4 + 2,
        Address::SocketAddress(SocketAddr::V6(_)) => 1 + 16 + 2,
        Address::DomainNameAddress(domain, _) => 1 + 1 + domain.len() + 2,
    }
}

#[derive(Debug, Clone)]
pub struct TcpRequestHeader {
    pub command: Command,
    pub address: Address,
}

impl TcpRequestHeader {
    pub fn new(command: Command, address: Address) -> Self {
        Self { command, address }
    }

    pub async fn read_from<R>(r: &mut R) -> Result<Self, Error>
    where
        R: AsyncRead + Unpin,
    {
        let mut buf = [0; 3];
        r.read_exact(&mut buf).await?;

        let ver = buf[0];
        if ver != consts::SOCKS5_VERSION {
            return Err(Error::UnsupportedSocksVersion(ver));
        }

        let cmd = buf[1];
        let command = match Command::from_u8(cmd) {
            Some(cmd) => cmd,
            None => return Err(Error::UnsupportedCommand(cmd)),
        };

        let address = Address::read_from(r).await?;
        Ok(Self { command, address })
    }

    pub async fn write_to<W>(&self, w: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        w.write_all(&buf).await
    }

    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        let Self { command, address } = self;
        buf.put_slice(&[consts::SOCKS5_VERSION, command.as_u8(), 0x00]);
        address.write_to_buf(buf);
    }

    #[inline]
    pub fn serialized_len(&self) -> usize {
        self.address.serialized_len() + 3
    }
}

#[derive(Debug, Clone)]
pub struct TcpResponseHeader {
    pub reply: Reply,
    pub address: Address,
}

impl TcpResponseHeader {
    pub fn new(reply: Reply, address: Address) -> Self {
        Self { reply, address }
    }

    pub async fn read_from<R>(r: &mut R) -> Result<Self, Error>
    where
        R: AsyncRead + Unpin,
    {
        let mut buf = [0; 3];
        r.read_exact(&mut buf).await?;

        let ver = buf[0];
        if ver != consts::SOCKS5_VERSION {
            return Err(Error::UnsupportedSocksVersion(ver));
        }
        let reply_code = buf[1];
        let address = Address::read_from(r).await?;

        Ok(Self {
            reply: Reply::from_u8(reply_code),
            address,
        })
    }

    pub async fn write_to<W>(&self, w: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        w.write_all(&buf).await
    }

    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        let Self { reply, address } = self;
        buf.put_slice(&[consts::SOCKS5_VERSION, reply.as_u8(), 0x00]);
        address.write_to_buf(buf);
    }

    #[inline]
    pub fn serialized_len(&self) -> usize {
        self.address.serialized_len() + 3
    }
}

#[derive(Debug, Clone)]
pub struct HandshakeRequest {
    pub methods: Vec<u8>,
}

impl HandshakeRequest {
    pub fn new(methods: Vec<u8>) -> Self {
        Self { methods }
    }

    pub async fn read_from<R>(r: &mut R) -> Result<Self, Error>
    where
        R: AsyncRead + Unpin,
    {
        let mut buf = [0; 2];
        r.read_exact(&mut buf).await?;

        let ver = buf[0];
        if ver != consts::SOCKS5_VERSION {
            return Err(Error::UnsupportedSocksVersion(ver));
        }
        let nmet = buf[1] as usize;
        let mut methods = vec![0; nmet];
        r.read_exact(&mut methods).await?;
        Ok(Self { methods })
    }

    pub async fn write_to<W>(&self, w: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        w.write_all(&buf).await
    }

    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        let nmet = self.methods.len() as u8;
        buf.put_slice(&[consts::SOCKS5_VERSION, nmet]);
        buf.put_slice(&self.methods);
    }

    pub fn serialized_len(&self) -> usize {
        self.methods.len() + 2
    }
}

#[derive(Debug, Clone, Copy)]
pub struct HandshakeResponse {
    pub chosen_method: u8,
}

impl HandshakeResponse {
    pub fn new(chosen_method: u8) -> Self {
        Self { chosen_method }
    }

    pub async fn read_from<R>(r: &mut R) -> Result<Self, Error>
    where
        R: AsyncRead + Unpin,
    {
        let mut buf = [0; 2];
        r.read_exact(&mut buf).await?;

        let ver = buf[0];
        if ver != consts::SOCKS5_VERSION {
            return Err(Error::UnsupportedSocksVersion(ver));
        }

        Ok(Self {
            chosen_method: buf[1],
        })
    }

    pub async fn write_to<W>(&self, w: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        w.write_all(&buf).await
    }

    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(consts::SOCKS5_VERSION);
        buf.put_u8(self.chosen_method);
    }

    #[inline]
    pub fn serialized_len(&self) -> usize {
        2
    }
}

#[derive(Debug, Clone)]
pub struct UdpAssociateHeader {
    pub frag: u8,
    pub address: Address,
}

impl UdpAssociateHeader {
    pub fn new(frag: u8, address: Address) -> Self {
        Self { frag, address }
    }

    pub async fn read_from<R>(r: &mut R) -> Result<Self, Error>
    where
        R: AsyncRead + Unpin,
    {
        let mut buf = [0; 3];
        r.read_exact(&mut buf).await?;

        let frag = buf[2];
        let address = Address::read_from(r).await?;

        Ok(Self { frag, address })
    }

    pub async fn write_to<W>(&self, w: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        w.write_all(&buf).await
    }

    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        let Self { frag, address } = self;
        buf.put_slice(&[0x00, 0x00, *frag]);
        address.write_to_buf(buf);
    }

    #[inline]
    pub fn serialized_len(&self) -> usize {
        self.address.serialized_len() + 3
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Cursor, mem::discriminant};

    #[tokio::test]
    async fn test_ipv6() {
        let ipv6 = Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8);
        let mut buffer = vec![consts::SOCKS5_ADDR_TYPE_IPV6];
        buffer.extend(ipv6.octets());
        let port = 8080u16;
        buffer.extend(port.to_be_bytes());

        let mut cursor = Cursor::new(buffer);
        let address = Address::read_from(&mut cursor).await.unwrap();
        let socketv6 = SocketAddr::V6(SocketAddrV6::new(ipv6, port, 0, 0));

        assert_eq!(
            discriminant(&address),
            discriminant(&Address::SocketAddress(socketv6))
        );
    }
}
