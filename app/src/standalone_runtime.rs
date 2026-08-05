use std::{
    future::Future,
    io,
    net::{Ipv4Addr, SocketAddr},
};

use rutilus_infra_redfish::NV_REDFISH_DEVELOPMENT_BASELINE;
use rutilus_web::WebProductInfo;
use thiserror::Error;
use tokio::{net::TcpListener, sync::oneshot};

const PRODUCT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// User-facing behavior for the foreground Standalone server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StandaloneRunOptions {
    open_browser: bool,
}

impl StandaloneRunOptions {
    #[must_use]
    pub const fn new(open_browser: bool) -> Self {
        Self { open_browser }
    }

    #[must_use]
    pub const fn open_browser(self) -> bool {
        self.open_browser
    }
}

impl Default for StandaloneRunOptions {
    fn default() -> Self {
        Self::new(true)
    }
}

/// A socket already bound to an OS-assigned port on IPv4 loopback only.
#[derive(Debug)]
pub struct StandaloneBinding {
    listener: TcpListener,
    address: SocketAddr,
}

impl StandaloneBinding {
    /// Binds the Standalone listener without exposing a non-loopback option.
    ///
    /// # Errors
    ///
    /// Returns [`StandaloneRunError::Bind`] when no loopback socket can be
    /// opened, or [`StandaloneRunError::LocalAddress`] when the OS cannot
    /// report the selected ephemeral port.
    pub async fn bind() -> Result<Self, StandaloneRunError> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(StandaloneRunError::Bind)?;
        let address = listener
            .local_addr()
            .map_err(StandaloneRunError::LocalAddress)?;
        Ok(Self { listener, address })
    }

    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    #[must_use]
    pub fn url(&self) -> String {
        format!("http://{}/", self.address)
    }

    /// Serves the embedded Web application until a tracked shutdown future
    /// resolves, then waits for Axum's graceful drain to complete.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the bound listener fails while serving.
    pub async fn serve_until<Shutdown>(
        self,
        options: StandaloneRunOptions,
        shutdown: Shutdown,
    ) -> io::Result<()>
    where
        Shutdown: Future<Output = ()> + Send + 'static,
    {
        let url = self.url();
        println!("Rutilus Standalone is listening at {url}");
        if options.open_browser() {
            launch_browser(url).await;
        }
        axum::serve(
            self.listener,
            rutilus_web::router(WebProductInfo::new(
                PRODUCT_VERSION,
                NV_REDFISH_DEVELOPMENT_BASELINE,
            )),
        )
        .with_graceful_shutdown(shutdown)
        .await
    }
}

/// Runs the foreground Standalone posture until Ctrl-C, with structured Axum
/// shutdown and no non-loopback plaintext mode.
///
/// # Errors
///
/// Returns [`StandaloneRunError`] when loopback binding, signal registration,
/// or HTTP serving fails.
pub async fn run_standalone(options: StandaloneRunOptions) -> Result<(), StandaloneRunError> {
    let binding = StandaloneBinding::bind().await?;
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();
    let server = binding.serve_until(options, async move {
        let _result = shutdown_receiver.await;
    });
    tokio::pin!(server);

    tokio::select! {
        result = &mut server => result.map_err(StandaloneRunError::Serve),
        signal = tokio::signal::ctrl_c() => {
            signal.map_err(StandaloneRunError::Signal)?;
            let _result = shutdown_sender.send(());
            server.await.map_err(StandaloneRunError::Serve)
        }
    }
}

async fn launch_browser(url: String) {
    let result = tokio::task::spawn_blocking(move || webbrowser::open(&url)).await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(error)) => eprintln!("Could not open the default browser: {error}"),
        Err(error) => eprintln!("Browser launch task failed: {error}"),
    }
}

/// A controlled failure before or during the local foreground server.
#[derive(Debug, Error)]
pub enum StandaloneRunError {
    #[error("failed to bind the Standalone loopback listener: {0}")]
    Bind(#[source] io::Error),
    #[error("failed to read the Standalone listener address: {0}")]
    LocalAddress(#[source] io::Error),
    #[error("failed to register the Standalone shutdown signal: {0}")]
    Signal(#[source] io::Error),
    #[error("Standalone HTTP server failed: {0}")]
    Serve(#[source] io::Error),
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpStream,
    };

    use super::*;

    #[tokio::test]
    async fn binds_only_loopback_and_serves_until_tracked_shutdown() -> Result<(), Box<dyn Error>> {
        let binding = StandaloneBinding::bind().await?;
        let address = binding.address();
        assert!(address.ip().is_loopback());
        assert_ne!(address.port(), 0);
        assert_eq!(binding.url(), format!("http://{address}/"));

        let (shutdown_sender, shutdown_receiver) = oneshot::channel();
        let server = tokio::spawn(binding.serve_until(
            StandaloneRunOptions::new(false),
            async move {
                let _result = shutdown_receiver.await;
            },
        ));
        let mut stream = TcpStream::connect(address).await?;
        stream
            .write_all(
                b"GET /api/v1/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        let response = String::from_utf8(response)?;
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("{\"status\":\"ok\"}"));

        shutdown_sender
            .send(())
            .map_err(|()| std::io::Error::other("server shutdown receiver was dropped"))?;
        server.await??;
        Ok(())
    }

    #[test]
    fn standalone_options_default_to_browser_launch() {
        assert!(StandaloneRunOptions::default().open_browser());
        assert!(!StandaloneRunOptions::new(false).open_browser());
    }
}
