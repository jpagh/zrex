use std::env;
use std::ffi::OsString;
use std::fmt::Display;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::FileTypeExt;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use futures_util::StreamExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UnixStream};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::client::Request;
use tokio_tungstenite::tungstenite::http::{HeaderValue, Uri};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, client_async_tls};

pub mod control;
pub mod data;
pub mod proto;
pub mod stream;

trait Transport: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Transport for T {}

type Socket = WebSocketStream<MaybeTlsStream<Box<dyn Transport>>>;

/// A network can drop packets without telling either end, so every handshake
/// step has a timeout.
pub const CONNECT_TIME: Duration = Duration::from_secs(10);

const OPEN_TRIES: u32 = 3;

#[derive(Debug, PartialEq, Eq)]
pub enum ServerAddress {
    Network(String),
    Unix(PathBuf),
}

impl FromStr for ServerAddress {
    type Err = anyhow::Error;

    fn from_str(address: &str) -> Result<Self> {
        let (scheme, rest) = match address.split_once("://") {
            Some((scheme, rest)) => (scheme.to_lowercase(), rest),
            None => ("http".to_owned(), address),
        };
        let scheme = match scheme.as_str() {
            "https" | "wss" => "wss",
            "http" | "ws" => "ws",
            "unix" => {
                if rest.is_empty() {
                    bail!("no server address");
                }
                return Ok(Self::Unix(OsString::from_vec(decode_percent(rest)?).into()));
            }
            other => bail!("unknown server scheme {other}"),
        };
        let rest = rest.trim_end_matches('/');
        if rest.is_empty() {
            bail!("no server address");
        }
        Ok(Self::Network(format!("{scheme}://{rest}")))
    }
}

impl ServerAddress {
    pub fn local_or_loopback() -> Self {
        discover_local_socket()
            .map(Self::Unix)
            .unwrap_or_else(|| Self::Network("ws://127.0.0.1:7297".to_owned()))
    }

    fn websocket_url(&self, route: &str) -> String {
        let base = match self {
            Self::Network(base) => base,
            // The host is only used in the WebSocket handshake over Unix.
            Self::Unix(_) => "ws://localhost",
        };
        format!("{base}{route}")
    }

    /// Retry initial socket opens because mobile links often drop the first
    /// SYN or TLS packet.
    async fn open(&self, route: &str, protocol: &'static str) -> Result<Socket> {
        let url = self.websocket_url(route);
        let mut last = None;
        for try_number in 1..=OPEN_TRIES {
            if try_number > 1 {
                tokio::time::sleep(Duration::from_millis(200 * u64::from(try_number))).await;
            }
            match self.try_open(&url, protocol).await {
                Ok(socket) => return Ok(socket),
                Err(error) => last = Some(error),
            }
        }
        Err(last.unwrap_or_else(|| anyhow!("could not reach {url}")))
    }

    async fn try_open(&self, url: &str, protocol: &'static str) -> Result<Socket> {
        let mut request = url.into_client_request()?;
        request
            .headers_mut()
            .insert("Sec-WebSocket-Protocol", HeaderValue::from_static(protocol));

        match self {
            Self::Network(_) => {
                with_connect_timeout(url, async {
                    let stream = connect_tcp(request.uri()).await?;
                    websocket(request, stream).await
                })
                .await
            }
            Self::Unix(path) => {
                let stream =
                    with_connect_timeout(path.display(), UnixStream::connect(path)).await?;
                with_connect_timeout(url, websocket(request, stream)).await
            }
        }
    }
}

/// Finds the local server's socket even outside a terminal started by Rex.
fn discover_local_socket() -> Option<PathBuf> {
    local_socket_candidates_from(env::var_os("HOME"), env::var_os("XDG_RUNTIME_DIR"))
        .into_iter()
        .find(|path| {
            path.metadata()
                .is_ok_and(|metadata| metadata.file_type().is_socket())
        })
}

fn local_socket_candidates_from(
    home: Option<OsString>,
    xdg_runtime_dir: Option<OsString>,
) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    #[cfg(target_os = "macos")]
    if let Some(home) = home.map(PathBuf::from).filter(|path| path.is_absolute()) {
        candidates.push(home.join("Library/Application Support/rex/server.sock"));
    }
    #[cfg(not(target_os = "macos"))]
    let _ = home;
    if let Some(runtime) = xdg_runtime_dir
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
    {
        candidates.push(runtime.join("rex/server.sock"));
    }
    #[cfg(not(target_os = "macos"))]
    {
        candidates.push(PathBuf::from("/run/rex/server.sock"));
        candidates.push(PathBuf::from("/var/run/rex/server.sock"));
    }
    candidates
}

fn decode_percent(text: &str) -> Result<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = bytes
                .get(index + 1..index + 3)
                .ok_or_else(|| anyhow!("incomplete percent escape in the server address"))?;
            let hex = std::str::from_utf8(hex)
                .map_err(|_| anyhow!("invalid percent escape in the server address"))?;
            let byte = u8::from_str_radix(hex, 16)
                .map_err(|_| anyhow!("invalid percent escape %{hex} in the server address"))?;
            decoded.push(byte);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    Ok(decoded)
}

async fn connect_tcp(uri: &Uri) -> Result<TcpStream> {
    let host = uri
        .host()
        .ok_or_else(|| anyhow!("the server URL has no host"))?
        .trim_matches(['[', ']']);
    let default_port = if uri.scheme_str() == Some("wss") {
        443
    } else {
        80
    };
    let stream = TcpStream::connect((host, uri.port_u16().unwrap_or(default_port))).await?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

async fn websocket(request: Request, stream: impl Transport + 'static) -> Result<Socket> {
    let stream: Box<dyn Transport> = Box::new(stream);
    let (socket, _) = client_async_tls(request, stream).await?;
    Ok(socket)
}

async fn with_connect_timeout<T, E: Into<anyhow::Error>>(
    target: impl Display,
    operation: impl Future<Output = std::result::Result<T, E>>,
) -> Result<T> {
    tokio::time::timeout(CONNECT_TIME, operation)
        .await
        .map_err(|_| anyhow!("{target} did not answer within {}s", CONNECT_TIME.as_secs()))?
        .map_err(Into::into)
}

async fn frame(socket: &mut Socket, what: &str) -> Result<Option<Message>> {
    match tokio::time::timeout(CONNECT_TIME, socket.next()).await {
        Ok(Some(frame)) => Ok(Some(frame?)),
        Ok(None) => Ok(None),
        Err(_) => bail!(
            "the server sent no {what} within {}s",
            CONNECT_TIME.as_secs()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::SinkExt;
    use tokio::net::UnixListener;
    use tokio_tungstenite::accept_hdr_async;
    use tokio_tungstenite::tungstenite::handshake::server::Response;

    #[test]
    fn builds_websocket_urls_from_network_addresses() {
        for (address, base) in [
            ("http://127.0.0.1:7297/", "ws://127.0.0.1:7297"),
            ("https://example.com/", "wss://example.com"),
            ("127.0.0.1:7297", "ws://127.0.0.1:7297"),
            ("wss://example.com", "wss://example.com"),
        ] {
            let address: ServerAddress = address.parse().unwrap();
            assert_eq!(
                address.websocket_url("/api/control"),
                format!("{base}/api/control")
            );
            assert_eq!(
                address.websocket_url("/api/data"),
                format!("{base}/api/data")
            );
        }
        assert!("".parse::<ServerAddress>().is_err());
        assert!("http:///".parse::<ServerAddress>().is_err());
        assert!("https:///".parse::<ServerAddress>().is_err());
        assert!("ws:///".parse::<ServerAddress>().is_err());
        assert!("ftp://example.com".parse::<ServerAddress>().is_err());
    }

    #[test]
    fn ignores_empty_or_relative_socket_env_dirs() {
        let empty = local_socket_candidates_from(Some(OsString::new()), Some(OsString::new()));
        assert!(empty.iter().all(|path| path.is_absolute()));

        let relative = local_socket_candidates_from(
            Some(OsString::from("relative/home")),
            Some(OsString::from("relative/run")),
        );
        assert!(relative.iter().all(|path| path.is_absolute()));

        let absolute = local_socket_candidates_from(
            Some(OsString::from("/Users/test")),
            Some(OsString::from("/run/user/1000")),
        );
        assert!(absolute.contains(&PathBuf::from("/run/user/1000/rex/server.sock")));
    }

    #[test]
    fn decodes_unix_socket_paths() {
        let address: ServerAddress = "unix:///tmp/100%25%20rex.sock".parse().unwrap();
        assert_eq!(
            address,
            ServerAddress::Unix(PathBuf::from("/tmp/100% rex.sock"))
        );
        assert_eq!(
            address.websocket_url("/api/control"),
            "ws://localhost/api/control"
        );
        assert_eq!(
            address.websocket_url("/api/data"),
            "ws://localhost/api/data"
        );
        assert!("unix://".parse::<ServerAddress>().is_err());
        assert!("unix:///tmp/bad%2.sock".parse::<ServerAddress>().is_err());
    }

    #[tokio::test]
    async fn exchanges_websocket_frames_over_a_unix_socket() {
        let socket_path = env::temp_dir().join(format!("zrex-{} %.sock", std::process::id()));
        let listener = UnixListener::bind(&socket_path).unwrap();
        let peer = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            #[allow(
                clippy::result_large_err,
                reason = "tungstenite fixes the callback error type"
            )]
            let mut socket = accept_hdr_async(stream, |req: &Request, mut res: Response| {
                assert_eq!(req.uri().path(), "/api/control");
                assert_eq!(
                    req.headers()["Sec-WebSocket-Protocol"],
                    control::SUBPROTOCOL
                );
                res.headers_mut().insert(
                    "Sec-WebSocket-Protocol",
                    HeaderValue::from_static(control::SUBPROTOCOL),
                );
                Ok(res)
            })
            .await
            .unwrap();
            assert_eq!(
                socket.next().await.unwrap().unwrap(),
                Message::text("hello")
            );
            socket.send(Message::text("welcome")).await.unwrap();
        });

        let address = ServerAddress::Unix(socket_path.clone());
        let result = address.open("/api/control", control::SUBPROTOCOL).await;
        std::fs::remove_file(socket_path).unwrap();
        let mut socket = result.unwrap();
        socket.send(Message::text("hello")).await.unwrap();
        assert_eq!(
            frame(&mut socket, "welcome").await.unwrap(),
            Some(Message::text("welcome"))
        );
        peer.await.unwrap();
    }
}
