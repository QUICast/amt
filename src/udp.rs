use crate::ecn::EcnCodepoint;
use polling::{Event, Poller};
use quinn_udp::{RecvMeta, Transmit, UdpSockRef, UdpSocketState};
use std::io::{self, ErrorKind, IoSliceMut};
use std::net::{SocketAddr, UdpSocket};

const RELAY_TUNNEL_SOCKET_BUFFER_TARGET: usize = 4 * 1024 * 1024;

/// Blocking-daemon UDP socket with per-datagram ECN metadata.
pub(crate) struct AmtUdpSocket {
    socket: UdpSocket,
    backend: SocketBackend,
    buffers: SocketBufferSizes,
}

enum SocketBackend {
    Standard,
    Ecn(UdpSocketState),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SocketBufferSizes {
    pub receive: usize,
    pub send: usize,
}

pub(crate) struct AmtUdpRegistration<'a> {
    socket: &'a UdpSocket,
    poller: &'a Poller,
    key: usize,
}

impl AmtUdpRegistration<'_> {
    pub(crate) fn rearm(&self) -> io::Result<()> {
        self.poller.modify(self.socket, Event::readable(self.key))
    }
}

impl Drop for AmtUdpRegistration<'_> {
    fn drop(&mut self) {
        let _ = self.poller.delete(self.socket);
    }
}

impl AmtUdpSocket {
    pub(crate) fn bind(address: SocketAddr, require_ecn: bool) -> io::Result<Self> {
        Self::bind_inner(address, require_ecn, None)
    }

    pub(crate) fn bind_relay(address: SocketAddr, require_ecn: bool) -> io::Result<Self> {
        Self::bind_inner(
            address,
            require_ecn,
            Some(RELAY_TUNNEL_SOCKET_BUFFER_TARGET),
        )
    }

    fn bind_inner(
        address: SocketAddr,
        require_ecn: bool,
        buffer_target: Option<usize>,
    ) -> io::Result<Self> {
        let socket = UdpSocket::bind(address)?;
        let buffers = configure_socket_buffers(&socket, buffer_target)?;
        let state = configure_tunnel_socket(&socket)?;
        let backend = if require_ecn {
            verify_ecn_receive(&socket)?;
            SocketBackend::Ecn(state)
        } else {
            SocketBackend::Standard
        };
        Ok(Self {
            socket,
            backend,
            buffers,
        })
    }

    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub(crate) const fn buffer_sizes(&self) -> SocketBufferSizes {
        self.buffers
    }

    pub(crate) fn register_readable<'a>(
        &'a self,
        poller: &'a Poller,
        key: usize,
    ) -> io::Result<AmtUdpRegistration<'a>> {
        // SAFETY: the returned guard borrows both the socket and poller and
        // unregisters the socket before either can be dropped.
        unsafe {
            poller.add(&self.socket, Event::readable(key))?;
        }
        Ok(AmtUdpRegistration {
            socket: &self.socket,
            poller,
            key,
        })
    }

    pub(crate) fn recv_from(
        &self,
        buffer: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, EcnCodepoint)> {
        let SocketBackend::Ecn(state) = &self.backend else {
            return self
                .socket
                .recv_from(buffer)
                .map(|(len, peer)| (len, peer, EcnCodepoint::NotEct));
        };
        let mut buffers = [IoSliceMut::new(buffer)];
        let mut metadata = [RecvMeta::default()];
        let count = state.recv(UdpSockRef::from(&self.socket), &mut buffers, &mut metadata)?;
        if count != 1 {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "UDP receive returned an unexpected datagram count",
            ));
        }

        let metadata = metadata[0];
        if metadata.len > buffer.len() || metadata.stride != metadata.len {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "coalesced or truncated UDP datagram reached the AMT control socket",
            ));
        }

        Ok((metadata.len, metadata.addr, from_quinn_ecn(metadata.ecn)))
    }

    pub(crate) fn send_to(
        &self,
        datagram: &[u8],
        destination: SocketAddr,
        ecn: EcnCodepoint,
    ) -> io::Result<usize> {
        match &self.backend {
            SocketBackend::Standard if ecn == EcnCodepoint::NotEct => {
                self.socket.send_to(datagram, destination)
            }
            SocketBackend::Standard => Err(io::Error::new(
                ErrorKind::Unsupported,
                "cannot send an ECN-marked datagram on a compatibility-mode AMT socket",
            )),
            SocketBackend::Ecn(state) => {
                state.try_send(
                    UdpSockRef::from(&self.socket),
                    &Transmit {
                        destination,
                        ecn: to_quinn_ecn(ecn),
                        contents: datagram,
                        segment_size: None,
                        src_ip: None,
                    },
                )?;
                Ok(datagram.len())
            }
        }
    }
}

fn configure_socket_buffers(
    socket: &UdpSocket,
    target: Option<usize>,
) -> io::Result<SocketBufferSizes> {
    let socket = socket2::SockRef::from(socket);
    if let Some(target) = target {
        if socket.recv_buffer_size()? < target {
            let _ = socket.set_recv_buffer_size(target);
        }
        if socket.send_buffer_size()? < target {
            let _ = socket.set_send_buffer_size(target);
        }
    }
    Ok(SocketBufferSizes {
        receive: socket.recv_buffer_size()?,
        send: socket.send_buffer_size()?,
    })
}

fn configure_tunnel_socket(socket: &UdpSocket) -> io::Result<UdpSocketState> {
    let state = UdpSocketState::new(UdpSockRef::from(socket))?;
    if state.may_fragment() {
        return Err(io::Error::new(
            ErrorKind::Unsupported,
            "the operating system cannot enforce non-fragmenting AMT UDP transmission",
        ));
    }
    disable_receive_coalescing(socket, &state)?;
    Ok(state)
}

#[cfg(unix)]
fn verify_ecn_receive(socket: &UdpSocket) -> io::Result<()> {
    let socket = socket2::SockRef::from(socket);
    let enabled = if socket.local_addr()?.is_ipv4() {
        socket.recv_tos_v4()?
    } else {
        socket.recv_tclass_v6()?
    };
    if enabled {
        Ok(())
    } else {
        Err(io::Error::new(
            ErrorKind::Unsupported,
            "the operating system did not enable ECN receive metadata",
        ))
    }
}

#[cfg(not(unix))]
#[cfg(not(windows))]
fn verify_ecn_receive(_socket: &UdpSocket) -> io::Result<()> {
    Ok(())
}

#[cfg(windows)]
fn verify_ecn_receive(socket: &UdpSocket) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        IP_RECVECN, IPPROTO_IP, IPPROTO_IPV6, IPV6_RECVECN, SOCKET_ERROR, WSAGetLastError,
        setsockopt,
    };

    let (level, option) = if socket.local_addr()?.is_ipv4() {
        (IPPROTO_IP, IP_RECVECN)
    } else {
        (IPPROTO_IPV6, IPV6_RECVECN)
    };
    let enabled = 1u32;
    let result = unsafe {
        setsockopt(
            socket.as_raw_socket() as usize,
            level,
            option,
            (&enabled as *const u32).cast(),
            std::mem::size_of_val(&enabled) as i32,
        )
    };
    if result == SOCKET_ERROR {
        Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }))
    } else {
        Ok(())
    }
}

fn from_quinn_ecn(ecn: Option<quinn_udp::EcnCodepoint>) -> EcnCodepoint {
    match ecn {
        Some(quinn_udp::EcnCodepoint::Ect0) => EcnCodepoint::Ect0,
        Some(quinn_udp::EcnCodepoint::Ect1) => EcnCodepoint::Ect1,
        Some(quinn_udp::EcnCodepoint::Ce) => EcnCodepoint::Ce,
        None => EcnCodepoint::NotEct,
    }
}

fn to_quinn_ecn(ecn: EcnCodepoint) -> Option<quinn_udp::EcnCodepoint> {
    match ecn {
        EcnCodepoint::NotEct => None,
        EcnCodepoint::Ect0 => Some(quinn_udp::EcnCodepoint::Ect0),
        EcnCodepoint::Ect1 => Some(quinn_udp::EcnCodepoint::Ect1),
        EcnCodepoint::Ce => Some(quinn_udp::EcnCodepoint::Ce),
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn disable_receive_coalescing(socket: &UdpSocket, state: &UdpSocketState) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    if state.gro_segments() <= 1 {
        return Ok(());
    }
    let disabled: libc::c_int = 0;
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_UDP,
            libc::UDP_GRO,
            (&disabled as *const libc::c_int).cast(),
            std::mem::size_of_val(&disabled) as libc::socklen_t,
        )
    };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn disable_receive_coalescing(_socket: &UdpSocket, _state: &UdpSocketState) -> io::Result<()> {
    // quinn-udp 0.6 leaves Windows receive coalescing disabled by default.
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android", windows)))]
fn disable_receive_coalescing(_socket: &UdpSocket, _state: &UdpSocketState) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn converts_all_ecn_codepoints() {
        for ecn in [
            EcnCodepoint::NotEct,
            EcnCodepoint::Ect0,
            EcnCodepoint::Ect1,
            EcnCodepoint::Ce,
        ] {
            assert_eq!(from_quinn_ecn(to_quinn_ecn(ecn)), ecn);
        }
    }

    #[test]
    fn compatibility_socket_uses_plain_udp_and_rejects_marked_sends() {
        let receiver = AmtUdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)), false).unwrap();
        let sender = AmtUdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)), false).unwrap();
        let destination = receiver.local_addr().unwrap();

        sender
            .send_to(b"plain", destination, EcnCodepoint::NotEct)
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut buffer = [0u8; 16];
        loop {
            match receiver.recv_from(&mut buffer) {
                Ok((len, _, ecn)) => {
                    assert_eq!(&buffer[..len], b"plain");
                    assert_eq!(ecn, EcnCodepoint::NotEct);
                    break;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "timed out waiting for plain UDP datagram"
                    );
                    std::thread::yield_now();
                }
                Err(error) => panic!("failed to receive plain datagram: {error}"),
            }
        }

        assert_eq!(
            sender
                .send_to(b"marked", destination, EcnCodepoint::Ect0)
                .unwrap_err()
                .kind(),
            ErrorKind::Unsupported
        );
    }

    #[test]
    fn supported_ipv4_socket_enforces_no_outer_fragmentation() {
        let socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let state = configure_tunnel_socket(&socket).unwrap();

        assert!(!state.may_fragment());
    }

    #[test]
    fn readable_registration_wakes_and_rearms() {
        let receiver = AmtUdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)), false).unwrap();
        let sender = AmtUdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)), false).unwrap();
        let poller = Poller::new().unwrap();
        let registration = receiver.register_readable(&poller, 7).unwrap();
        let destination = receiver.local_addr().unwrap();
        let mut events = polling::Events::new();
        let mut buffer = [0u8; 16];

        // The relay rearms before its first wait and after every bounded drain.
        registration.rearm().unwrap();

        for payload in [b"first".as_slice(), b"second".as_slice()] {
            sender
                .send_to(payload, destination, EcnCodepoint::NotEct)
                .unwrap();
            events.clear();
            poller
                .wait(&mut events, Some(Duration::from_secs(1)))
                .unwrap();
            assert!(events.iter().any(|event| event.key == 7 && event.readable));
            let (len, _, _) = receiver.recv_from(&mut buffer).unwrap();
            assert_eq!(&buffer[..len], payload);
            registration.rearm().unwrap();
        }
    }

    #[test]
    fn relay_tunnel_socket_reports_nonzero_buffers() {
        let socket =
            AmtUdpSocket::bind_relay(SocketAddr::from(([127, 0, 0, 1], 0)), false).unwrap();
        let buffers = socket.buffer_sizes();

        assert_ne!(buffers.receive, 0);
        assert_ne!(buffers.send, 0);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn sends_and_receives_outer_ecn_on_loopback() {
        let receiver = AmtUdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)), true).unwrap();
        let sender = AmtUdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)), true).unwrap();
        let destination = receiver.local_addr().unwrap();
        sender
            .send_to(b"ecn", destination, EcnCodepoint::Ect1)
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(1);
        let mut buffer = [0u8; 16];
        loop {
            match receiver.recv_from(&mut buffer) {
                Ok((len, _, ecn)) => {
                    assert_eq!(&buffer[..len], b"ecn");
                    assert_eq!(ecn, EcnCodepoint::Ect1);
                    break;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "timed out waiting for ECN datagram"
                    );
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("failed to receive ECN datagram: {error}"),
            }
        }
    }
}
