//! Protocol-neutral local service-loop preparation.
//!
//! This module owns connection lifecycle only. A later integration must supply
//! the frozen controld-facing authentication, framing, and message handler.

use std::convert::Infallible;
use std::io;
use std::os::unix::net::{UnixListener, UnixStream};

use thiserror::Error;

/// Service-loop failures without protocol-specific details.
#[derive(Debug, Error)]
pub enum ServiceLoopError {
    #[error("local connection acceptance failed")]
    Accept(#[source] io::Error),
    #[error("local connection handling failed")]
    Handle(#[source] io::Error),
}

/// Hand one local connection to a caller-supplied protocol implementation.
pub fn serve_connection(
    stream: UnixStream,
    handler: &mut impl FnMut(UnixStream) -> io::Result<()>,
) -> Result<(), ServiceLoopError> {
    handler(stream).map_err(ServiceLoopError::Handle)
}

/// Accept and handle one local connection.
pub fn accept_one(
    listener: &UnixListener,
    handler: &mut impl FnMut(UnixStream) -> io::Result<()>,
) -> Result<(), ServiceLoopError> {
    let (stream, _) = listener.accept().map_err(ServiceLoopError::Accept)?;
    serve_connection(stream, handler)
}

/// Run the sequential local connection loop.
///
/// Sequential handling preserves the Phase-1 concurrency ceiling. The caller
/// remains responsible for supplying a listener and the frozen C3 handler.
pub fn run_service_loop(
    listener: &UnixListener,
    handler: &mut impl FnMut(UnixStream) -> io::Result<()>,
) -> Result<Infallible, ServiceLoopError> {
    loop {
        accept_one(listener, handler)?;
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::Shutdown;

    use super::*;

    #[test]
    fn protocol_neutral_handler_receives_one_end_of_socket_pair() {
        let (mut client, server) = UnixStream::pair().expect("socket pair");
        client.write_all(b"opaque").expect("write fixture bytes");
        client.shutdown(Shutdown::Write).expect("finish fixture");

        let mut observed = Vec::new();
        serve_connection(server, &mut |mut stream| {
            stream.read_to_end(&mut observed).map(|_| ())
        })
        .expect("serve connection");

        assert_eq!(observed, b"opaque");
    }
}
