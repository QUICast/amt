//! Transport configuration and negotiated-capability checks for quiche.

use crate::control::{DataMode, Settings};
use crate::session::{GatewaySessionConfig, RelaySessionConfig};
use crate::{ALPN, ApplicationError, EndpointRole, MIN_GATEWAY_DATAGRAM_SIZE, ProtocolError};
use std::fmt;

const DEFAULT_CONTROL_WINDOW: u64 = 256 * 1024;
const DEFAULT_RELIABLE_STREAM_WINDOW: u64 = 256 * 1024;
const DEFAULT_RELIABLE_STREAM_CREDIT: u64 = 16;
const DEFAULT_DATAGRAM_QUEUE_LEN: usize = 1_024;

#[derive(Debug)]
pub enum ConfigureError {
    InvalidProfile(ProtocolError),
    Quiche(quiche::Error),
}

impl fmt::Display for ConfigureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProfile(error) => write!(formatter, "invalid AMTQ profile: {error}"),
            Self::Quiche(error) => write!(formatter, "failed to configure quiche: {error}"),
        }
    }
}

impl std::error::Error for ConfigureError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidProfile(error) => Some(error),
            Self::Quiche(error) => Some(error),
        }
    }
}

impl From<ProtocolError> for ConfigureError {
    fn from(error: ProtocolError) -> Self {
        Self::InvalidProfile(error)
    }
}

impl From<quiche::Error> for ConfigureError {
    fn from(error: quiche::Error) -> Self {
        Self::Quiche(error)
    }
}

/// Local QUIC transport parameters required by an AMTQ endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointConfig {
    pub role: EndpointRole,
    pub reliable_block_mode: bool,
    pub control_window: u64,
    pub reliable_stream_window: u64,
    pub reliable_stream_credit: u64,
    pub datagram_recv_queue_len: usize,
    pub datagram_send_queue_len: usize,
}

impl EndpointConfig {
    pub const fn gateway(reliable_block_mode: bool) -> Self {
        Self {
            role: EndpointRole::Gateway,
            reliable_block_mode,
            control_window: DEFAULT_CONTROL_WINDOW,
            reliable_stream_window: DEFAULT_RELIABLE_STREAM_WINDOW,
            reliable_stream_credit: if reliable_block_mode {
                DEFAULT_RELIABLE_STREAM_CREDIT
            } else {
                0
            },
            datagram_recv_queue_len: DEFAULT_DATAGRAM_QUEUE_LEN,
            datagram_send_queue_len: 0,
        }
    }

    pub const fn relay(reliable_block_mode: bool) -> Self {
        Self {
            role: EndpointRole::Relay,
            reliable_block_mode,
            control_window: DEFAULT_CONTROL_WINDOW,
            reliable_stream_window: DEFAULT_RELIABLE_STREAM_WINDOW,
            reliable_stream_credit: 0,
            datagram_recv_queue_len: 0,
            datagram_send_queue_len: DEFAULT_DATAGRAM_QUEUE_LEN,
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.control_window == 0 {
            return Err(settings_error(
                "AMTQ control-stream flow-control window is zero",
            ));
        }
        if self.role == EndpointRole::Gateway {
            if self.datagram_recv_queue_len == 0 {
                return Err(settings_error(
                    "AMTQ Gateway DATAGRAM receive queue is disabled",
                ));
            }
            if self.datagram_send_queue_len != 0 {
                return Err(settings_error(
                    "AMTQ Gateway DATAGRAM send queue must be disabled",
                ));
            }
            if self.reliable_block_mode && self.reliable_stream_credit == 0 {
                return Err(settings_error(
                    "AMTQ Gateway Reliable Block Mode has no stream credit",
                ));
            }
        } else {
            if self.datagram_recv_queue_len != 0 {
                return Err(settings_error(
                    "AMTQ Relay DATAGRAM receive queue must be disabled",
                ));
            }
            if self.datagram_send_queue_len == 0 {
                return Err(settings_error("AMTQ Relay DATAGRAM send queue is disabled"));
            }
        }
        Ok(())
    }

    /// Applies the AMTQ profile to a raw quiche configuration.
    ///
    /// TLS credentials and peer verification remain the caller's
    /// responsibility. This function intentionally does not enable 0-RTT.
    pub fn apply(&self, config: &mut quiche::Config) -> Result<(), ConfigureError> {
        self.validate()?;
        config.set_application_protos(&[ALPN])?;
        config.set_initial_max_data(
            self.control_window.saturating_add(
                self.reliable_stream_window
                    .saturating_mul(self.reliable_stream_credit.max(1)),
            ),
        );
        config.set_initial_max_stream_data_bidi_local(self.control_window);
        config.set_initial_max_stream_data_bidi_remote(self.control_window);
        config.set_initial_max_stream_data_uni(self.reliable_stream_window);
        config.set_disable_active_migration(false);
        config.set_active_connection_id_limit(4);

        match self.role {
            EndpointRole::Gateway => {
                config.enable_dgram(
                    true,
                    self.datagram_recv_queue_len,
                    self.datagram_send_queue_len,
                );
                config.set_initial_max_streams_bidi(0);
                config.set_initial_max_streams_uni(self.reliable_stream_credit);
            }
            EndpointRole::Relay => {
                config.enable_dgram(
                    false,
                    self.datagram_recv_queue_len,
                    self.datagram_send_queue_len,
                );
                config.set_initial_max_streams_bidi(1);
                config.set_initial_max_streams_uni(0);
            }
        }
        Ok(())
    }

    pub const fn local_initial_max_streams_uni(&self) -> u64 {
        match self.role {
            EndpointRole::Gateway => self.reliable_stream_credit,
            EndpointRole::Relay => 0,
        }
    }
}

/// Exact peer transport parameters consumed by the AMTQ session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCapabilities {
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub max_datagram_frame_size: Option<u64>,
}

impl PeerCapabilities {
    pub fn from_connection<F: quiche::BufFactory>(
        connection: &quiche::Connection<F>,
        local_role: EndpointRole,
    ) -> Result<Self, ProtocolError> {
        if !connection.is_established() {
            return Err(ProtocolError::new(
                ApplicationError::Protocol,
                "AMTQ transport validation ran before the QUIC handshake completed",
            ));
        }
        if connection.is_in_early_data() {
            return Err(ProtocolError::new(
                ApplicationError::Protocol,
                "AMTQ application data is prohibited in QUIC 0-RTT",
            ));
        }
        if connection.application_proto() != ALPN {
            return Err(settings_error("QUIC did not negotiate the AMTQ ALPN"));
        }

        let peer = connection
            .peer_transport_params()
            .ok_or_else(|| settings_error("QUIC peer transport parameters are unavailable"))?;
        let capabilities = Self {
            initial_max_streams_bidi: peer.initial_max_streams_bidi,
            initial_max_streams_uni: peer.initial_max_streams_uni,
            max_datagram_frame_size: peer.max_datagram_frame_size,
        };
        capabilities.validate(local_role)?;
        Ok(capabilities)
    }

    pub fn validate(self, local_role: EndpointRole) -> Result<(), ProtocolError> {
        match local_role {
            EndpointRole::Gateway if self.initial_max_streams_bidi == 0 => Err(settings_error(
                "AMTQ Relay does not permit control Stream 0",
            )),
            EndpointRole::Relay
                if self
                    .max_datagram_frame_size
                    .is_none_or(|size| size < MIN_GATEWAY_DATAGRAM_SIZE) =>
            {
                Err(settings_error(
                    "AMTQ Gateway did not advertise the required DATAGRAM size",
                ))
            }
            _ => Ok(()),
        }
    }

    pub fn gateway_session_config(
        self,
        local: &EndpointConfig,
        settings: Settings,
    ) -> Result<GatewaySessionConfig, ProtocolError> {
        if local.role != EndpointRole::Gateway {
            return Err(settings_error(
                "Gateway session was given a Relay transport profile",
            ));
        }
        local.validate()?;
        if settings.supports(DataMode::ReliableBlock) != local.reliable_block_mode {
            return Err(settings_error(
                "AMTQ Gateway SETTINGS and QUIC stream capabilities disagree",
            ));
        }
        Ok(GatewaySessionConfig {
            settings,
            relay_initial_max_streams_bidi: self.initial_max_streams_bidi,
            gateway_initial_max_streams_uni: local.local_initial_max_streams_uni(),
            ..GatewaySessionConfig::default()
        })
    }

    pub fn relay_session_config(
        self,
        local: &EndpointConfig,
        settings: Settings,
    ) -> Result<RelaySessionConfig, ProtocolError> {
        if local.role != EndpointRole::Relay {
            return Err(settings_error(
                "Relay session was given a Gateway transport profile",
            ));
        }
        local.validate()?;
        if settings.supports(DataMode::ReliableBlock) != local.reliable_block_mode {
            return Err(settings_error(
                "AMTQ Relay SETTINGS and QUIC stream capabilities disagree",
            ));
        }
        Ok(RelaySessionConfig {
            settings,
            gateway_max_datagram_frame_size: self.max_datagram_frame_size,
            gateway_initial_max_streams_uni: self.initial_max_streams_uni,
            ..RelaySessionConfig::default()
        })
    }
}

pub fn close_with_protocol_error<F: quiche::BufFactory>(
    connection: &mut quiche::Connection<F>,
    error: &ProtocolError,
) -> Result<(), quiche::Error> {
    connection.close(true, error.code.code(), error.reason.as_bytes())
}

const fn settings_error(reason: &'static str) -> ProtocolError {
    ProtocolError::new(ApplicationError::Settings, reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_profiles_are_directional() {
        let gateway = EndpointConfig::gateway(true);
        assert_eq!(gateway.role, EndpointRole::Gateway);
        assert!(gateway.reliable_stream_credit > 0);
        assert!(gateway.datagram_recv_queue_len > 0);
        assert_eq!(gateway.datagram_send_queue_len, 0);

        let relay = EndpointConfig::relay(false);
        assert_eq!(relay.role, EndpointRole::Relay);
        assert_eq!(relay.reliable_stream_credit, 0);
        assert_eq!(relay.datagram_recv_queue_len, 0);
        assert!(relay.datagram_send_queue_len > 0);
    }

    #[test]
    fn exact_peer_capabilities_are_validated_by_role() {
        let relay = PeerCapabilities {
            initial_max_streams_bidi: 0,
            initial_max_streams_uni: 0,
            max_datagram_frame_size: None,
        };
        assert_eq!(
            relay.validate(EndpointRole::Gateway).unwrap_err().code,
            ApplicationError::Settings
        );

        let gateway = PeerCapabilities {
            initial_max_streams_bidi: 0,
            initial_max_streams_uni: 0,
            max_datagram_frame_size: Some(MIN_GATEWAY_DATAGRAM_SIZE - 1),
        };
        assert_eq!(
            gateway.validate(EndpointRole::Relay).unwrap_err().code,
            ApplicationError::Settings
        );
    }

    #[test]
    fn applying_a_profile_validates_it_in_release_builds() {
        let mut profile = EndpointConfig::gateway(false);
        profile.datagram_recv_queue_len = 0;
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        assert!(matches!(
            profile.apply(&mut config),
            Err(ConfigureError::InvalidProfile(ProtocolError {
                code: ApplicationError::Settings,
                ..
            }))
        ));
    }
}
