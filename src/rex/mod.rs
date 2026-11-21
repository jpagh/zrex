use std::env;
use std::ffi::OsString;
use std::fmt::Write as _;
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

/// Local Unix socket and loopback probes should fail quickly so a wedged local
/// server never stalls startup.
pub const LOCAL_PROBE_TIME: Duration = Duration::from_secs(1);

const OPEN_TRIES: u32 = 3;
const DEFAULT_LOOPBACK_ADDR: &str = "127.0.0.1:7297";

#[derive(Debug, Clone, PartialEq, Eq)]
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
        let raw = format!("{scheme}://{rest}");
        let request = raw.as_str().into_client_request()?;
        let uri = request.uri();
        let authority = uri
            .authority()
            .ok_or_else(|| anyhow!("the server URL has no host"))?;
        let host = uri
            .host()
            .filter(|host| !host.is_empty())
            .ok_or_else(|| anyhow!("the server URL has no host"))?;
        let host_port = authority
            .as_str()
            .split_once('@')
            .map_or(authority.as_str(), |(_, host_port)| host_port);
        if let Some(port_str) = host_port
            .strip_prefix(host)
            .and_then(|tail| tail.strip_prefix(':'))
            && (port_str.is_empty()
                || !port_str.bytes().all(|b| b.is_ascii_digit())
                || port_str.parse::<u16>().is_err())
        {
            bail!("invalid port in server URL");
        }
        let default_port = if scheme == "wss" { 443 } else { 80 };
        let port = uri.port_u16().filter(|&port| port != default_port);
        let userinfo = authority
            .as_str()
            .split_once('@')
            .map(|(user, _)| user)
            .filter(|user| !user.is_empty());
        let path_and_query = uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .filter(|pq| *pq != "/");

        let mut normalized = format!("{scheme}://");
        if let Some(user) = userinfo {
            normalized.push_str(user);
            normalized.push('@');
        }
        normalized.push_str(&host.to_ascii_lowercase());
        if let Some(port) = port {
            let _ = write!(normalized, ":{port}");
        }
        if let Some(pq) = path_and_query {
            normalized.push_str(pq);
        }
        Ok(Self::Network(normalized))
    }
}

impl ServerAddress {
    pub async fn local_or_loopback() -> Self {
        Self::first_reachable_local(local_socket_candidates())
            .await
            .unwrap_or_else(|| Self::Network(format!("ws://{DEFAULT_LOOPBACK_ADDR}")))
    }

    async fn first_reachable_local(candidates: impl IntoIterator<Item = PathBuf>) -> Option<Self> {
        for path in candidates {
            if path.metadata().is_ok_and(|m| m.file_type().is_socket())
                && with_timeout(LOCAL_PROBE_TIME, UnixStream::connect(&path))
                    .await
                    .is_ok()
            {
                return Some(Self::Unix(path));
            }
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
            match self.try_open(protocol, CONNECT_TIME).await {
                Ok(socket) => return Ok(socket),
                Err(error) => last = Some(error),
            }
        }
        Err(self.unreachable_error(last))
    }

    pub(super) async fn open_once(
        &self,
        protocol: &'static str,
        timeout: Duration,
    ) -> Result<Socket> {
        self.try_open(protocol, timeout)
            .await
            .map_err(|error| self.unreachable_error(Some(error)))
    }

    fn unreachable_error(&self, cause: Option<anyhow::Error>) -> anyhow::Error {
        let target = self
            .unix_path
            .map_or_else(|| self.url.clone(), |path| path.display().to_string());
        let message = format!("could not reach {target}");
        match cause {
            Some(error) => error.context(message),
            None => anyhow!(message),
        }
    }

    async fn try_open(&self, protocol: &'static str, timeout: Duration) -> Result<Socket> {
        let mut request = self.url.as_str().into_client_request()?;
        request
            .headers_mut()
            .insert("Sec-WebSocket-Protocol", HeaderValue::from_static(protocol));

        with_timeout(timeout, async {
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

pub(super) fn format_timeout(timeout: Duration) -> String {
    if timeout.subsec_millis() == 0 && timeout.as_secs() > 0 {
        format!("{}s", timeout.as_secs())
    } else {
        format!("{}ms", timeout.as_millis())
    }
}

async fn with_timeout<T, E: Into<anyhow::Error>>(
    timeout: Duration,
    operation: impl Future<Output = std::result::Result<T, E>>,
) -> Result<T> {
    tokio::time::timeout(timeout, operation)
        .await
        .map_err(|_| {
            anyhow!(
                "the server did not answer within {}",
                format_timeout(timeout)
            )
        })?
        .map_err(Into::into)
}

async fn frame(socket: &mut Socket, what: &str) -> Result<Option<Message>> {
    frame_with_timeout(socket, what, CONNECT_TIME).await
}

async fn frame_with_timeout(
    socket: &mut Socket,
    what: &str,
    timeout: Duration,
) -> Result<Option<Message>> {
    match tokio::time::timeout(timeout, socket.next()).await {
        Ok(Some(frame)) => Ok(Some(frame?)),
        Ok(None) => Ok(None),
        Err(_) => bail!(
            "the server sent no {what} within {}",
            format_timeout(timeout)
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

    #[test]
    fn normalizes_and_validates_network_urls() {
        assert_eq!(
            "https://Example.COM:443/".parse::<ServerAddress>().unwrap(),
            "https://example.com".parse::<ServerAddress>().unwrap()
        );
        assert_eq!(
            "wss://EXAMPLE.COM:443".parse::<ServerAddress>().unwrap(),
            ServerAddress::Network("wss://example.com".to_owned())
        );
        assert_eq!(
            "http://localhost:80".parse::<ServerAddress>().unwrap(),
            "http://localhost".parse::<ServerAddress>().unwrap()
        );
        assert_eq!(
            "ws://LOCALHOST:80/".parse::<ServerAddress>().unwrap(),
            ServerAddress::Network("ws://localhost".to_owned())
        );

        // Non-default ports and paths (with trailing '/' trimmed) are preserved.
        assert_eq!(
            "http://Example.COM:7297/rex/"
                .parse::<ServerAddress>()
                .unwrap(),
            ServerAddress::Network("ws://example.com:7297/rex".to_owned())
        );
        assert_eq!(
            "http://example.com:443".parse::<ServerAddress>().unwrap(),
            ServerAddress::Network("ws://example.com:443".to_owned())
        );
        assert_eq!(
            "https://example.com:80".parse::<ServerAddress>().unwrap(),
            ServerAddress::Network("wss://example.com:80".to_owned())
        );

        // IPv6 brackets are preserved, hex host lowercased, and default port stripped.
        assert_eq!(
            "[::1]:7297".parse::<ServerAddress>().unwrap(),
            ServerAddress::Network("ws://[::1]:7297".to_owned())
        );
        assert_eq!(
            "https://[2001:DB8::1]:443/api/"
                .parse::<ServerAddress>()
                .unwrap(),
            ServerAddress::Network("wss://[2001:db8::1]/api".to_owned())
        );
        assert_eq!(
            "http://[::1]:80/".parse::<ServerAddress>().unwrap(),
            ServerAddress::Network("ws://[::1]".to_owned())
        );

        // Malformed URLs are rejected immediately at parse time.
        for bad in [
            "http://bad host",
            "http://:7297",
            "http://example.com:99999",
            "http://example.com:abc",
            "http://example.com:",
            "http://[::1",
            "http:///path",
        ] {
            assert!(bad.parse::<ServerAddress>().is_err(), "expected {bad:?} to fail");
        }
    }

    async fn serve_one_rex_client<S>(stream: S)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        #[allow(
            clippy::result_large_err,
            reason = "tungstenite fixes the callback error type"
        )]
        let mut ws = accept_hdr_async(stream, |req: &Request, mut res: Response| {
            if let Some(proto) = req.headers().get("Sec-WebSocket-Protocol") {
                res.headers_mut()
                    .insert("Sec-WebSocket-Protocol", proto.clone());
            }
            Ok(res)
        })
        .await
        .unwrap();

        let Some(Ok(Message::Text(hello_text))) = ws.next().await else {
            return;
        };
        let hello: serde_json::Value = serde_json::from_str(&hello_text).unwrap();
        assert_eq!(hello["type"], "hello");

        ws.send(Message::text(
            serde_json::json!({
                "type": "welcome",
                "api_revision": proto::API_REVISION,
            })
            .to_string(),
        ))
        .await
        .unwrap();

        while let Some(Ok(msg)) = ws.next().await {
            if let Message::Text(text) = msg {
                let req: serde_json::Value = serde_json::from_str(&text).unwrap();
                ws.send(Message::text(
                    serde_json::json!({
                        "type": "response",
                        "id": req["id"],
                        "seq": 1,
                        "payload": {"ok": true}
                    })
                    .to_string(),
                ))
                .await
                .unwrap();
            }
        }
    }

    #[tokio::test]
    async fn connect_local_if_running_handles_unix_tcp_stale_excluded_and_absent() {
        let unix_path = env::temp_dir().join(format!("zrex-ctrl-local-{}.sock", std::process::id()));
        let stale_path =
            env::temp_dir().join(format!("zrex-ctrl-stale-{}.sock", std::process::id()));
        let non_rex_path =
            env::temp_dir().join(format!("zrex-ctrl-nonrex-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&unix_path);
        let _ = std::fs::remove_file(&stale_path);
        let _ = std::fs::remove_file(&non_rex_path);

        // Create a stale Unix socket file (listener dropped).
        drop(UnixListener::bind(&stale_path).unwrap());

        // Create a non-Rex Unix socket that accepts and immediately closes.
        let non_rex_listener = UnixListener::bind(&non_rex_path).unwrap();
        let non_rex_task = tokio::spawn(async move {
            while let Ok((stream, _)) = non_rex_listener.accept().await {
                drop(stream);
            }
        });

        let unix_listener = UnixListener::bind(&unix_path).unwrap();
        let unix_task = tokio::spawn(async move {
            while let Ok((stream, _)) = unix_listener.accept().await {
                tokio::spawn(serve_one_rex_client(stream));
            }
        });

        let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = tcp_listener.local_addr().unwrap().to_string();
        let tcp_task = tokio::spawn(async move {
            while let Ok((stream, _)) = tcp_listener.accept().await {
                tokio::spawn(serve_one_rex_client(stream));
            }
        });

        // 1. Skips stale and non-Rex sockets and connects cleanly to the live Unix Rex server.
        let candidates = vec![
            stale_path.clone(),
            non_rex_path.clone(),
            unix_path.clone(),
        ];
        let (addr, mut ctrl, _events) =
            control::Control::connect_local_in(candidates.clone(), &tcp_addr, &[])
                .await
                .unwrap();
        assert_eq!(addr, ServerAddress::Unix(unix_path.clone()));
        assert_eq!(
            ctrl.call("server.version", serde_json::Value::Null)
                .await
                .unwrap()["ok"],
            true
        );
        drop(ctrl);

        // 2. Excluding the configured local Unix socket stops without falling
        // through to loopback TCP (avoiding duplicate entries when Rex listens
        // on both).
        let exclude_unix = [ServerAddress::Unix(unix_path.clone())];
        assert!(
            control::Control::connect_local_in(candidates.clone(), &tcp_addr, &exclude_unix)
                .await
                .is_none()
        );

        // 3. When only stale/non-Rex sockets exist, falls back to loopback TCP.
        let (addr, mut ctrl, _events) = control::Control::connect_local_in(
            [stale_path.clone(), non_rex_path.clone()],
            &tcp_addr,
            &[],
        )
        .await
        .unwrap();
        let expected_tcp = ServerAddress::Network(format!("ws://{tcp_addr}"));
        assert_eq!(addr, expected_tcp);
        assert_eq!(
            ctrl.call("server.version", serde_json::Value::Null)
                .await
                .unwrap()["ok"],
            true
        );
        drop(ctrl);

        // 4. Excluding loopback TCP when no live Unix socket exists returns None.
        assert!(
            control::Control::connect_local_in(
                [stale_path.clone()],
                &tcp_addr,
                std::slice::from_ref(&expected_tcp),
            )
            .await
            .is_none()
        );

        // 5. Returns None when no Rex servers are listening.
        unix_task.abort();
        tcp_task.abort();
        non_rex_task.abort();
        assert!(
            control::Control::connect_local_in([stale_path.clone()], &tcp_addr, &[])
                .await
                .is_none()
        );

        let _ = std::fs::remove_file(&unix_path);
        let _ = std::fs::remove_file(&stale_path);
        let _ = std::fs::remove_file(&non_rex_path);
    }

    #[test]
    fn formats_whole_and_subsecond_timeouts() {
        assert_eq!(format_timeout(Duration::from_secs(10)), "10s");
        assert_eq!(format_timeout(Duration::from_secs(1)), "1s");
        assert_eq!(format_timeout(Duration::from_millis(200)), "200ms");
        assert_eq!(format_timeout(Duration::from_millis(1500)), "1500ms");
        assert_eq!(format_timeout(Duration::ZERO), "0ms");
    }
}
