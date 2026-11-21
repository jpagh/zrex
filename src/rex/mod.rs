use std::env;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use futures_util::StreamExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UnixStream};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
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
const DEFAULT_LOOPBACK_ADDR: &str = "127.0.0.1:7297";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerConfig {
    Explicit(String),
    Env(String),
    Default,
}

impl ServerConfig {
    pub fn from_sources(flag: Option<String>, env: Option<String>) -> Self {
        if let Some(address) = flag {
            Self::Explicit(address)
        } else if let Some(address) = env.filter(|address| !address.is_empty()) {
            Self::Env(address)
        } else {
            Self::Default
        }
    }

    pub async fn resolve(&self) -> Result<ServerAddress> {
        match self {
            Self::Explicit(address) | Self::Env(address) => address.parse(),
            Self::Default => Ok(ServerAddress::local_or_loopback().await),
        }
    }
}

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
    pub async fn local_or_loopback() -> Self {
        Self::first_reachable_local(local_socket_candidates())
            .await
            .unwrap_or_else(|| Self::Network(format!("ws://{DEFAULT_LOOPBACK_ADDR}")))
    }

    /// Returns the local Rex server's Unix socket or default loopback TCP
    /// address only when a local server is actually accepting connections.
    pub async fn local_if_running() -> Option<Self> {
        Self::detect_local(local_socket_candidates(), DEFAULT_LOOPBACK_ADDR).await
    }

    async fn first_reachable_local(candidates: impl IntoIterator<Item = PathBuf>) -> Option<Self> {
        for path in candidates {
            if path.metadata().is_ok_and(|m| m.file_type().is_socket())
                && with_connect_timeout(UnixStream::connect(&path))
                    .await
                    .is_ok()
            {
                return Some(Self::Unix(path));
            }
        }
        None
    }

    async fn detect_local(
        candidates: impl IntoIterator<Item = PathBuf>,
        loopback: &str,
    ) -> Option<Self> {
        if let Some(unix) = Self::first_reachable_local(candidates).await {
            return Some(unix);
        }
        if with_connect_timeout(TcpStream::connect(loopback))
            .await
            .is_ok()
        {
            return Some(Self::Network(format!("ws://{loopback}")));
        }
        None
    }

    async fn open(&self, route: &str, protocol: &'static str) -> Result<Socket> {
        self.endpoint(route).open(protocol).await
    }

    fn endpoint(&self, route: &str) -> Endpoint<'_> {
        let (base, unix_path) = match self {
            Self::Network(base) => (base.as_str(), None),
            // The host is only used in the WebSocket handshake over Unix.
            Self::Unix(path) => ("ws://localhost", Some(path.as_path())),
        };
        Endpoint {
            url: format!("{base}{route}"),
            unix_path,
        }
    }
}

struct Endpoint<'a> {
    url: String,
    unix_path: Option<&'a Path>,
}

impl Endpoint<'_> {
    /// Retry initial socket opens because mobile links often drop the first
    /// SYN or TLS packet.
    async fn open(&self, protocol: &'static str) -> Result<Socket> {
        let mut last = None;
        for try_number in 1..=OPEN_TRIES {
            if try_number > 1 {
                tokio::time::sleep(Duration::from_millis(200 * u64::from(try_number))).await;
            }
            match self.try_open(protocol).await {
                Ok(socket) => return Ok(socket),
                Err(error) => last = Some(error),
            }
        }
        let target = self
            .unix_path
            .map_or_else(|| self.url.clone(), |path| path.display().to_string());
        let message = format!("could not reach {target}");
        Err(match last {
            Some(error) => error.context(message),
            None => anyhow!(message),
        })
    }

    async fn try_open(&self, protocol: &'static str) -> Result<Socket> {
        let mut request = self.url.as_str().into_client_request()?;
        request
            .headers_mut()
            .insert("Sec-WebSocket-Protocol", HeaderValue::from_static(protocol));

        with_connect_timeout(async {
            let stream: Box<dyn Transport> = match self.unix_path {
                Some(path) => Box::new(UnixStream::connect(path).await?),
                None => Box::new(connect_tcp(request.uri()).await?),
            };
            let (socket, _) = client_async_tls(request, stream).await?;
            Ok::<_, anyhow::Error>(socket)
        })
        .await
    }
}

/// Finds the local server's socket even outside a terminal started by Rex.
fn local_socket_candidates() -> Vec<PathBuf> {
    local_socket_candidates_from(env::var_os("HOME"), env::var_os("XDG_RUNTIME_DIR"))
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

async fn with_connect_timeout<T, E: Into<anyhow::Error>>(
    operation: impl Future<Output = std::result::Result<T, E>>,
) -> Result<T> {
    tokio::time::timeout(CONNECT_TIME, operation)
        .await
        .map_err(|_| {
            anyhow!(
                "the server did not answer within {}s",
                CONNECT_TIME.as_secs()
            )
        })?
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
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

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
                address.endpoint("/api/control").url,
                format!("{base}/api/control")
            );
            assert_eq!(
                address.endpoint("/api/data").url,
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
            address.endpoint("/api/control").url,
            "ws://localhost/api/control"
        );
        assert_eq!(address.endpoint("/api/data").url, "ws://localhost/api/data");
        assert!("unix://".parse::<ServerAddress>().is_err());
        assert!("unix:///tmp/bad%2.sock".parse::<ServerAddress>().is_err());
    }

    #[tokio::test]
    async fn skips_stale_local_socket_files() {
        let path = env::temp_dir().join(format!("zrex-stale-{}.sock", std::process::id()));
        let listener = UnixListener::bind(&path).unwrap();
        let live = ServerAddress::first_reachable_local([path.clone()]).await;
        drop(listener);
        let stale = ServerAddress::first_reachable_local([path.clone()]).await;
        std::fs::remove_file(&path).unwrap();
        assert_eq!(live, Some(ServerAddress::Unix(path)));
        assert_eq!(stale, None);
    }

    #[tokio::test]
    async fn detects_running_local_server_and_returns_none_when_absent() {
        let path = env::temp_dir().join(format!("zrex-detect-{}.sock", std::process::id()));
        let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = tcp_listener.local_addr().unwrap().to_string();

        // Prefers a live Unix socket over loopback TCP.
        let unix_listener = UnixListener::bind(&path).unwrap();
        assert_eq!(
            ServerAddress::detect_local([path.clone()], &tcp_addr).await,
            Some(ServerAddress::Unix(path.clone()))
        );
        drop(unix_listener);

        // Falls back to loopback TCP when the Unix socket is stale/absent.
        assert_eq!(
            ServerAddress::detect_local([path.clone()], &tcp_addr).await,
            Some(ServerAddress::Network(format!("ws://{tcp_addr}")))
        );

        // Returns None when neither Unix socket nor loopback TCP is accepting connections.
        drop(tcp_listener);
        assert_eq!(
            ServerAddress::detect_local([path.clone()], &tcp_addr).await,
            None
        );
        std::fs::remove_file(&path).unwrap();
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
