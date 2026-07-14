//! TERMIX-03 — inline SOCKS5 relay state machine (RFC 1928).
//!
//! Two pure-`tokio` primitives that the `ssh-tunnel` feature wires to an SSH
//! channel in [`super::ssh_jump`] / the relay loop:
//!
//! * the **server handshake** ([`negotiate_no_auth`] → [`read_connect_request`]
//!   → [`write_reply`]) — accept a local SOCKS5 client, negotiate NO-AUTH, parse
//!   its `CONNECT` request into a [`Socks5Addr`]. The caller then opens an SSH
//!   `direct-tcpip` channel to that target and pipes bytes both ways.
//! * the **client dialer** ([`socks5_connect`]) — egress THROUGH an existing
//!   SOCKS5 proxy (the "SOCKS5 hop-0" case of TERMIX-02), returning a connected
//!   [`TcpStream`].
//!
//! Pure byte-protocol over any `AsyncRead + AsyncWrite`, so it compiles +
//! unit-tests on the default build (no `russh`); the only `ssh-tunnel`-gated
//! piece is the loop that bridges a handshake to an SSH channel.

use std::net::SocketAddr;

use anyhow::{Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

const VER: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// SOCKS5 reply codes (RFC 1928 §6).
pub mod reply {
    pub const SUCCEEDED: u8 = 0x00;
    pub const GENERAL_FAILURE: u8 = 0x01;
    pub const HOST_UNREACHABLE: u8 = 0x04;
    pub const COMMAND_NOT_SUPPORTED: u8 = 0x07;
    pub const ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

/// A parsed SOCKS5 `CONNECT` target. `host` is a domain (ATYP=DOMAIN) or the
/// textual form of an IP — exactly what an SSH `direct-tcpip` channel wants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5Addr {
    pub host: String,
    pub port: u16,
}

/// Read the client greeting and select NO-AUTH. Writes the method-selection
/// reply. Errors (after writing `0xFF`) if the client offers no NO-AUTH method.
pub async fn negotiate_no_auth<S>(stream: &mut S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != VER {
        bail!("socks5: bad greeting version {:#x}", head[0]);
    }
    let nmethods = head[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;
    if methods.contains(&METHOD_NO_AUTH) {
        stream.write_all(&[VER, METHOD_NO_AUTH]).await?;
        Ok(())
    } else {
        stream.write_all(&[VER, METHOD_NONE_ACCEPTABLE]).await?;
        bail!("socks5: client offered no NO-AUTH method");
    }
}

/// Read + parse the client `CONNECT` request into a [`Socks5Addr`]. Only the
/// `CONNECT` command is supported (BIND / UDP-ASSOCIATE are rejected by the
/// caller via [`write_reply`]). On an unsupported command / address type this
/// returns an error AFTER the caller has read the bytes, so the caller replies
/// with the appropriate code.
pub async fn read_connect_request<S>(stream: &mut S) -> Result<Socks5Addr>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != VER {
        bail!("socks5: bad request version {:#x}", head[0]);
    }
    if head[1] != CMD_CONNECT {
        bail!("socks5: unsupported command {:#x}", head[1]);
    }
    // head[2] = RSV (ignored), head[3] = ATYP
    let host = match head[3] {
        ATYP_IPV4 => {
            let mut a = [0u8; 4];
            stream.read_exact(&mut a).await?;
            std::net::Ipv4Addr::from(a).to_string()
        }
        ATYP_IPV6 => {
            let mut a = [0u8; 16];
            stream.read_exact(&mut a).await?;
            std::net::Ipv6Addr::from(a).to_string()
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            stream.read_exact(&mut name).await?;
            String::from_utf8(name).map_err(|_| anyhow::anyhow!("socks5: non-utf8 domain"))?
        }
        other => bail!("socks5: unsupported address type {:#x}", other),
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    Ok(Socks5Addr {
        host,
        port: u16::from_be_bytes(port),
    })
}

/// Write a SOCKS5 reply with `code` and a zeroed `0.0.0.0:0` bound address (the
/// bound address is irrelevant for a relayed `CONNECT`).
pub async fn write_reply<S>(stream: &mut S, code: u8) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    // VER, REP, RSV, ATYP=IPv4, BND.ADDR=0.0.0.0, BND.PORT=0
    stream
        .write_all(&[VER, code, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

/// Egress through an existing SOCKS5 proxy: connect to `proxy`, do the NO-AUTH
/// greeting + a `CONNECT` to `target_host:target_port`, and return the live
/// stream on success. Used for the "SOCKS5 hop-0" path of TERMIX-02.
pub async fn socks5_connect(
    proxy: SocketAddr,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream> {
    if target_host.len() > 255 {
        bail!("socks5: domain too long ({} > 255)", target_host.len());
    }
    let mut s = TcpStream::connect(proxy).await?;
    // Greeting: VER, NMETHODS=1, NO_AUTH.
    s.write_all(&[VER, 0x01, METHOD_NO_AUTH]).await?;
    let mut sel = [0u8; 2];
    s.read_exact(&mut sel).await?;
    if sel[0] != VER || sel[1] != METHOD_NO_AUTH {
        bail!(
            "socks5: proxy refused NO-AUTH (got {:#x},{:#x})",
            sel[0],
            sel[1]
        );
    }
    // CONNECT request with a DOMAIN address (the proxy resolves it).
    let mut req = vec![VER, CMD_CONNECT, 0x00, ATYP_DOMAIN, target_host.len() as u8];
    req.extend_from_slice(target_host.as_bytes());
    req.extend_from_slice(&target_port.to_be_bytes());
    s.write_all(&req).await?;
    // Reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT — consume per ATYP.
    let mut rhead = [0u8; 4];
    s.read_exact(&mut rhead).await?;
    if rhead[0] != VER {
        bail!("socks5: bad reply version {:#x}", rhead[0]);
    }
    if rhead[1] != reply::SUCCEEDED {
        bail!("socks5: proxy CONNECT failed (reply {:#x})", rhead[1]);
    }
    let skip = match rhead[3] {
        ATYP_IPV4 => 4,
        ATYP_IPV6 => 16,
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await?;
            len[0] as usize
        }
        other => bail!("socks5: bad reply address type {:#x}", other),
    };
    let mut rest = vec![0u8; skip + 2]; // bound addr + 2-byte port
    s.read_exact(&mut rest).await?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Drive the server handshake against an in-memory client (no network).
    #[tokio::test]
    async fn server_handshake_parses_domain_connect() {
        let (mut client, mut server) = tokio::io::duplex(256);
        let client_task = tokio::spawn(async move {
            // greeting: VER, NMETHODS=1, NO_AUTH
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut sel = [0u8; 2];
            client.read_exact(&mut sel).await.unwrap();
            assert_eq!(sel, [0x05, 0x00]);
            // CONNECT example.com:443 (domain)
            let mut req = vec![0x05, 0x01, 0x00, 0x03, 11];
            req.extend_from_slice(b"example.com");
            req.extend_from_slice(&443u16.to_be_bytes());
            client.write_all(&req).await.unwrap();
            let mut reply = [0u8; 10];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[1], reply::SUCCEEDED);
        });
        negotiate_no_auth(&mut server).await.unwrap();
        let addr = read_connect_request(&mut server).await.unwrap();
        assert_eq!(
            addr,
            Socks5Addr {
                host: "example.com".into(),
                port: 443
            }
        );
        write_reply(&mut server, reply::SUCCEEDED).await.unwrap();
        client_task.await.unwrap();
    }

    #[tokio::test]
    async fn server_handshake_parses_ipv4_connect() {
        let (mut client, mut server) = tokio::io::duplex(256);
        let t = tokio::spawn(async move {
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut sel = [0u8; 2];
            client.read_exact(&mut sel).await.unwrap();
            // CONNECT 10.0.0.5:22
            let mut req = vec![0x05, 0x01, 0x00, 0x01, 10, 0, 0, 5];
            req.extend_from_slice(&22u16.to_be_bytes());
            client.write_all(&req).await.unwrap();
        });
        negotiate_no_auth(&mut server).await.unwrap();
        let addr = read_connect_request(&mut server).await.unwrap();
        assert_eq!(
            addr,
            Socks5Addr {
                host: "10.0.0.5".into(),
                port: 22
            }
        );
        t.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_client_without_no_auth() {
        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            // offers only GSSAPI (0x01), no NO-AUTH
            client.write_all(&[0x05, 0x01, 0x01]).await.unwrap();
            let mut sel = [0u8; 2];
            let _ = client.read_exact(&mut sel).await;
            assert_eq!(sel, [0x05, 0xFF]);
        });
        assert!(negotiate_no_auth(&mut server).await.is_err());
    }

    #[tokio::test]
    async fn unsupported_command_errors() {
        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            // BIND (0x02) instead of CONNECT
            let mut req = vec![0x05, 0x02, 0x00, 0x01, 1, 1, 1, 1];
            req.extend_from_slice(&80u16.to_be_bytes());
            client.write_all(&req).await.unwrap();
        });
        assert!(read_connect_request(&mut server).await.is_err());
    }

    // Full client dialer against a minimal in-process SOCKS5 server that bridges
    // to a loopback echo — exercises socks5_connect end-to-end, no real proxy.
    #[tokio::test]
    async fn dialer_round_trips_through_loopback_proxy() {
        use tokio::net::TcpListener;
        // Upstream echo server the proxy will connect us to.
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(&buf).await.unwrap();
        });
        // Minimal SOCKS5 proxy: handshake, then connect to the echo + splice.
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut client, _) = proxy.accept().await.unwrap();
            negotiate_no_auth(&mut client).await.unwrap();
            let _target = read_connect_request(&mut client).await.unwrap();
            let mut up = TcpStream::connect(echo_addr).await.unwrap();
            write_reply(&mut client, reply::SUCCEEDED).await.unwrap();
            tokio::io::copy_bidirectional(&mut client, &mut up)
                .await
                .ok();
        });
        let mut s = socks5_connect(proxy_addr, "127.0.0.1", echo_addr.port())
            .await
            .unwrap();
        s.write_all(b"hello").await.unwrap();
        let mut got = [0u8; 5];
        s.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello");
    }
}
