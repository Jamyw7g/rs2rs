use std::{
    convert::Infallible,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, ToSocketAddrs},
    str::FromStr,
    time::Duration,
};

use hyper::{
    http::uri::{Authority, Scheme},
    server::conn::AddrStream,
    server::Server,
    service::{make_service_fn, service_fn},
    upgrade, Body, Method, Request, Response, StatusCode, Uri,
};
use tokio::net::TcpStream;

use crate::copy_bidirectional;
use crate::socks5;

#[derive(Debug)]
pub struct Http;

impl Http {
    pub async fn run<I: ToSocketAddrs>(addr: I) -> io::Result<()> {
        let make_service = make_service_fn(|socket: &AddrStream| {
            let client_addr = socket.remote_addr();

            async move {
                Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                    HttpDispatcher::new(req, client_addr).dispatch()
                }))
            }
        });
        let listener = TcpListener::bind(addr)?;
        let server = match Server::from_tcp(listener) {
            Ok(builder) => builder
                .http1_only(true)
                .http1_preserve_header_case(true)
                .http1_title_case_headers(true)
                .tcp_sleep_on_accept_errors(true)
                .tcp_keepalive(Some(Duration::from_secs(30)))
                .tcp_nodelay(true)
                .serve(make_service),
            Err(e) => {
                eprintln!("Hyper server error: {}", e.to_string());
                return Err(io::Error::new(io::ErrorKind::InvalidInput, e));
            }
        };

        if let Err(e) = server.await {
            eprintln!("hyper exited with error: {}", e.to_string());

            return Err(io::Error::new(io::ErrorKind::Other, e));
        }

        Ok(())
    }
}
#[derive(Debug)]
pub struct HttpDispatcher {
    req: Request<Body>,
    client_addr: SocketAddr,
}

impl HttpDispatcher {
    pub fn new(req: Request<Body>, client_addr: SocketAddr) -> Self {
        Self { req, client_addr }
    }
    pub async fn dispatch(mut self) -> io::Result<Response<Body>> {
        eprintln!(
            "client address: {}, uri: {:?}",
            self.client_addr,
            self.req.uri()
        );

        let host = match host_addr(self.req.uri()) {
            Some(h) => h,
            None => {
                if self.req.uri().authority().is_some() {
                    return make_bad_response();
                }
                match get_addr_from_header(&mut self.req) {
                    Ok(h) => h,
                    Err(_) => return make_bad_response(),
                }
            }
        };

        if Method::CONNECT == self.req.method() {
            let mut stream = match host {
                socks5::Address::SocketAddress(addr) => TcpStream::connect(addr).await?,
                socks5::Address::DomainNameAddress(domain, port) => {
                    TcpStream::connect((domain, port)).await?
                }
            };
            let req = self.req;
            let client_addr = self.client_addr;

            tokio::spawn(async move {
                match upgrade::on(req).await {
                    Ok(mut upgraded) => {
                        if let Ok((r, w)) =
                            copy_bidirectional::copy_bidirectional(&mut stream, &mut upgraded).await
                        {
                            eprintln!("forward: {}bytes, back: {}bytes", r, w);
                        }
                    }
                    Err(e) => {
                        eprintln!("upgrade break: {}", e.to_string());
                    }
                }
            });

            Ok(Response::new(Body::empty()))
        } else {
            make_bad_response()
        }
    }
}

fn make_bad_response() -> io::Result<Response<Body>> {
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::BAD_REQUEST;
    Ok(resp)
}

fn host_addr(uri: &Uri) -> Option<socks5::Address> {
    match uri.authority() {
        Some(authority) => authority_addr(uri.scheme_str(), authority),
        None => None,
    }
}

fn authority_addr(scheme_str: Option<&str>, authority: &Authority) -> Option<socks5::Address> {
    let port = match authority.port_u16() {
        Some(port) => port,
        None => match scheme_str {
            Some("http") => 80,
            Some("https") => 443,
            None => 80,
            _ => return None,
        },
    };

    let host_str = authority.host();

    if host_str.starts_with('[') && host_str.ends_with(']') {
        let addr = &host_str[1..host_str.len() - 1];
        match addr.parse::<Ipv6Addr>() {
            Ok(a) => Some(socks5::Address::from(SocketAddr::new(IpAddr::V6(a), port))),
            Err(_) => None,
        }
    } else {
        match host_str.parse::<Ipv4Addr>() {
            Ok(a) => Some(socks5::Address::from(SocketAddr::new(IpAddr::V4(a), port))),
            Err(_) => Some(socks5::Address::DomainNameAddress(
                host_str.to_owned(),
                port,
            )),
        }
    }
}

fn get_addr_from_header(req: &mut Request<Body>) -> Result<socks5::Address, ()> {
    match req.headers().get("Host") {
        Some(hhost) => match hhost.to_str() {
            Ok(shost) => match Authority::from_str(shost) {
                Ok(authority) => match authority_addr(req.uri().scheme_str(), &authority) {
                    Some(host) => {
                        let mut parts = req.uri().clone().into_parts();
                        if parts.scheme.is_none() {
                            parts.scheme = Some(Scheme::HTTP);
                        }
                        parts.authority = Some(authority);
                        *req.uri_mut() = Uri::from_parts(parts).expect("Reassemble URI failed");
                        Ok(host)
                    }
                    _ => Err(()),
                },
                Err(_) => Err(()),
            },
            Err(_) => Err(()),
        },
        None => Err(()),
    }
}
