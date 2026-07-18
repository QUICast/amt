use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;
use tokio_quiche::datagram_socket::{DatagramSocketRecv, DatagramSocketSend};
use tokio_quiche::socket::{Socket, SocketCapabilities};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayPathSnapshot {
    pub reachable: bool,
    pub outages: u64,
    pub recoveries: u64,
    pub locally_dropped_datagrams: u64,
}

impl Default for GatewayPathSnapshot {
    fn default() -> Self {
        Self {
            reachable: true,
            outages: 0,
            recoveries: 0,
            locally_dropped_datagrams: 0,
        }
    }
}

struct GatewayPathCounters {
    reachable: AtomicBool,
    outages: AtomicU64,
    recoveries: AtomicU64,
    locally_dropped_datagrams: AtomicU64,
}

impl Default for GatewayPathCounters {
    fn default() -> Self {
        Self {
            reachable: AtomicBool::new(true),
            outages: AtomicU64::new(0),
            recoveries: AtomicU64::new(0),
            locally_dropped_datagrams: AtomicU64::new(0),
        }
    }
}

#[derive(Clone, Default)]
pub struct GatewayPathStats {
    counters: Arc<GatewayPathCounters>,
}

impl GatewayPathStats {
    pub fn snapshot(&self) -> GatewayPathSnapshot {
        GatewayPathSnapshot {
            reachable: self.counters.reachable.load(Ordering::Acquire),
            outages: self.counters.outages.load(Ordering::Relaxed),
            recoveries: self.counters.recoveries.load(Ordering::Relaxed),
            locally_dropped_datagrams: self
                .counters
                .locally_dropped_datagrams
                .load(Ordering::Relaxed),
        }
    }

    fn record_unreachable(&self, dropped_datagram: bool) {
        if self.counters.reachable.swap(false, Ordering::AcqRel) {
            self.counters.outages.fetch_add(1, Ordering::Relaxed);
        }
        if dropped_datagram {
            self.counters
                .locally_dropped_datagrams
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    fn record_receive(&self) {
        if !self.counters.reachable.load(Ordering::Relaxed)
            && self
                .counters
                .reachable
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        {
            self.counters.recoveries.fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub(super) fn gateway_socket(
    socket: UdpSocket,
    peer_address: SocketAddr,
) -> io::Result<(Socket<RoamingUdpSend, RoamingUdpRecv>, GatewayPathStats)> {
    let local_address = socket.local_addr()?;
    let socket = Arc::new(socket);
    let path_stats = GatewayPathStats::default();

    Ok((
        Socket {
            send: RoamingUdpSend {
                socket: Arc::clone(&socket),
                peer_address,
                path_stats: path_stats.clone(),
            },
            recv: RoamingUdpRecv {
                socket,
                peer_address,
                path_stats: path_stats.clone(),
            },
            local_addr: local_address,
            peer_addr: peer_address,
            capabilities: SocketCapabilities::default(),
        },
        path_stats,
    ))
}

pub(super) struct RoamingUdpSend {
    socket: Arc<UdpSocket>,
    peer_address: SocketAddr,
    path_stats: GatewayPathStats,
}

impl DatagramSocketSend for RoamingUdpSend {
    fn poll_send(&self, cx: &mut Context<'_>, buffer: &[u8]) -> Poll<io::Result<usize>> {
        self.poll_send_to(cx, buffer, self.peer_address)
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buffer: &[u8],
        address: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        tolerate_path_loss(
            self.socket.poll_send_to(cx, buffer, address),
            buffer.len(),
            &self.path_stats,
        )
    }
}

pub(super) struct RoamingUdpRecv {
    socket: Arc<UdpSocket>,
    peer_address: SocketAddr,
    path_stats: GatewayPathStats,
}

impl DatagramSocketRecv for RoamingUdpRecv {
    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.poll_recv_from(cx, buffer) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_recv_from(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<SocketAddr>> {
        match self.socket.poll_recv_from(cx, buffer) {
            Poll::Ready(Ok(address)) => {
                if address == self.peer_address {
                    self.path_stats.record_receive();
                }
                Poll::Ready(Ok(address))
            }
            Poll::Ready(Err(error)) if is_transient_path_error(&error) => {
                self.path_stats.record_unreachable(false);
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            result => result,
        }
    }
}

fn tolerate_path_loss(
    result: Poll<io::Result<usize>>,
    datagram_len: usize,
    path_stats: &GatewayPathStats,
) -> Poll<io::Result<usize>> {
    match result {
        Poll::Ready(Err(error)) if is_transient_path_error(&error) => {
            // A route outage is indistinguishable from packet loss to QUIC.
            // Reporting the datagram as sent keeps the connection and its CIDs
            // alive so loss recovery can probe the replacement route.
            path_stats.record_unreachable(true);
            Poll::Ready(Ok(datagram_len))
        }
        result => result,
    }
}

fn is_transient_path_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::AddrNotAvailable
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkDown
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::NotConnected
            | io::ErrorKind::TimedOut
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_stats_count_outage_edges_and_confirm_recovery_on_receive() {
        let stats = GatewayPathStats::default();
        stats.record_unreachable(true);
        stats.record_unreachable(true);
        assert_eq!(
            stats.snapshot(),
            GatewayPathSnapshot {
                reachable: false,
                outages: 1,
                recoveries: 0,
                locally_dropped_datagrams: 2,
            }
        );

        stats.record_receive();
        stats.record_receive();
        assert_eq!(
            stats.snapshot(),
            GatewayPathSnapshot {
                reachable: true,
                outages: 1,
                recoveries: 1,
                locally_dropped_datagrams: 2,
            }
        );
    }

    #[test]
    fn only_route_and_transient_udp_errors_are_hidden() {
        assert!(is_transient_path_error(&io::Error::from(
            io::ErrorKind::NetworkUnreachable
        )));
        assert!(is_transient_path_error(&io::Error::from(
            io::ErrorKind::AddrNotAvailable
        )));
        assert!(!is_transient_path_error(&io::Error::from(
            io::ErrorKind::PermissionDenied
        )));
        assert!(!is_transient_path_error(&io::Error::from(
            io::ErrorKind::InvalidInput
        )));
    }

    #[test]
    fn transient_send_failure_is_reported_to_quic_as_packet_loss() {
        let stats = GatewayPathStats::default();
        let result = tolerate_path_loss(
            Poll::Ready(Err(io::Error::from(io::ErrorKind::NetworkUnreachable))),
            1_200,
            &stats,
        );
        assert!(matches!(result, Poll::Ready(Ok(1_200))));
        assert_eq!(
            stats.snapshot(),
            GatewayPathSnapshot {
                reachable: false,
                outages: 1,
                recoveries: 0,
                locally_dropped_datagrams: 1,
            }
        );

        let result = tolerate_path_loss(
            Poll::Ready(Err(io::Error::from(io::ErrorKind::PermissionDenied))),
            1_200,
            &stats,
        );
        assert!(matches!(
            result,
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::PermissionDenied
        ));
    }
}
