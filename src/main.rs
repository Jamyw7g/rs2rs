use std::{convert::Infallible, io};
use tokio::net::{TcpListener, TcpStream};

mod copy_bidirectional;
mod http;
mod socks5;

#[tokio::main]
async fn main() -> io::Result<()> {
    return http::Http::run("127.0.0.1:8080").await;

    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(stream).await {
                        eprintln!(
                            "Connection {} disconnected: {}",
                            addr.to_string(),
                            e.to_string()
                        )
                    }
                });
            }
            Err(e) => eprintln!("Failed to establish connection: {}", e.to_string()),
        }
    }
}

async fn handle_conn(mut stream: TcpStream) -> Result<(), socks5::Error> {
    let hheader = socks5::HandshakeRequest::read_from(&mut stream).await?;
    if hheader
        .methods
        .iter()
        .any(|&v| v == socks5::SOCKS5_AUTH_METHOD_NONE)
    {
        return Err(socks5::Error::UnsupportedCommand(0));
    }
    let resp = socks5::HandshakeResponse::new(socks5::SOCKS5_AUTH_METHOD_NONE);
    resp.write_to(&mut stream).await?;

    let re_header = socks5::TcpRequestHeader::read_from(&mut stream).await?;
    let re_response =
        socks5::TcpResponseHeader::new(socks5::Reply::Succeeded, re_header.address.clone());
    re_response.write_to(&mut stream).await?;

    let mut dst = match re_header.address {
        socks5::Address::SocketAddress(addr) => TcpStream::connect(addr).await?,
        socks5::Address::DomainNameAddress(domain, port) => {
            TcpStream::connect((domain, port)).await?
        }
    };

    tokio::spawn(async move {
        match copy_bidirectional::copy_bidirectional(&mut stream, &mut dst).await {
            Ok((r, w)) => eprintln!("forward {}bytes, back: {}bytes", r, w),
            Err(e) => eprintln!("Connection disconnected: {}", e.to_string()),
        }
    });

    Ok(())
}
