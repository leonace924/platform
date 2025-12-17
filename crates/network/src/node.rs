//! Network node implementation

use crate::behaviour::{MiniChainBehaviour, MiniChainBehaviourEvent, SyncRequest, SyncResponse};
use futures::StreamExt;
use libp2p::{
    gossipsub, identify,
    identity::Keypair,
    mdns, noise,
    request_response::{self, ResponseChannel},
    swarm::SwarmEvent,
    tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder,
};
use parking_lot::RwLock;
use platform_core::SignedNetworkMessage;
use std::{collections::HashSet, sync::Arc, time::Duration};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Network node configuration
#[derive(Clone, Debug)]
pub struct NodeConfig {
    /// Listen address
    pub listen_addr: Multiaddr,

    /// Bootstrap peers
    pub bootstrap_peers: Vec<Multiaddr>,

    /// Idle connection timeout
    pub idle_timeout: Duration,

    /// Enable mDNS for local peer discovery
    pub enable_mdns: bool,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            listen_addr: "/ip4/0.0.0.0/tcp/0".parse().unwrap(),
            bootstrap_peers: vec![],
            idle_timeout: Duration::from_secs(60),
            enable_mdns: false, // Disabled by default to avoid errors on special interfaces
        }
    }
}

/// Events emitted by the network node
#[derive(Debug)]
pub enum NetworkEvent {
    /// New peer connected
    PeerConnected(PeerId),

    /// Peer disconnected
    PeerDisconnected(PeerId),

    /// Message received from gossip
    MessageReceived { from: PeerId, data: Vec<u8> },

    /// Sync request received
    SyncRequest {
        from: PeerId,
        request: SyncRequest,
        channel: ResponseChannelWrapper,
    },
}

/// Wrapper for response channel (to make it Send)
pub struct ResponseChannelWrapper(pub ResponseChannel<SyncResponse>);

impl std::fmt::Debug for ResponseChannelWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ResponseChannelWrapper(...)")
    }
}

unsafe impl Send for ResponseChannelWrapper {}
unsafe impl Sync for ResponseChannelWrapper {}

/// Network node
pub struct NetworkNode {
    /// libp2p swarm
    swarm: Swarm<MiniChainBehaviour>,

    /// Local peer ID
    local_peer_id: PeerId,

    /// Connected peers
    peers: Arc<RwLock<HashSet<PeerId>>>,

    /// Event sender
    event_tx: mpsc::Sender<NetworkEvent>,

    /// Event receiver (to be taken by the consumer)
    event_rx: Option<mpsc::Receiver<NetworkEvent>>,
}

impl NetworkNode {
    /// Create a new network node
    pub async fn new(config: NodeConfig) -> anyhow::Result<Self> {
        let local_key = Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());

        info!("Local peer ID: {}", local_peer_id);

        let behaviour = MiniChainBehaviour::new(&local_key, config.enable_mdns)?;

        let swarm = SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_dns()?
            .with_behaviour(|_| behaviour)?
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(config.idle_timeout))
            .build();

        let (event_tx, event_rx) = mpsc::channel(1000);

        Ok(Self {
            swarm,
            local_peer_id,
            peers: Arc::new(RwLock::new(HashSet::new())),
            event_tx,
            event_rx: Some(event_rx),
        })
    }

    /// Get local peer ID
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// Get connected peers
    pub fn peers(&self) -> Vec<PeerId> {
        self.peers.read().iter().cloned().collect()
    }

    /// Take the event receiver (can only be called once)
    pub fn take_event_receiver(&mut self) -> Option<mpsc::Receiver<NetworkEvent>> {
        self.event_rx.take()
    }

    /// Start listening
    pub async fn start(&mut self, config: &NodeConfig) -> anyhow::Result<()> {
        // Subscribe to gossip topic
        self.swarm.behaviour_mut().subscribe()?;

        // Start listening
        self.swarm.listen_on(config.listen_addr.clone())?;
        info!("Listening on {:?}", config.listen_addr);

        // Connect to bootstrap peers
        for addr in &config.bootstrap_peers {
            info!("Dialing bootstrap peer: {}", addr);
            self.swarm.dial(addr.clone())?;
        }

        Ok(())
    }

    /// Broadcast a message via gossip
    pub fn broadcast(&mut self, message: &SignedNetworkMessage) -> anyhow::Result<()> {
        let data = bincode::serialize(message)?;
        self.swarm.behaviour_mut().publish(data)?;
        debug!("Broadcast message: {:?}", message.message);
        Ok(())
    }

    /// Broadcast raw bytes via gossip (for pre-serialized messages)
    pub fn broadcast_raw(&mut self, data: Vec<u8>) -> anyhow::Result<()> {
        self.swarm.behaviour_mut().publish(data)?;
        Ok(())
    }

    /// Send a sync request to a peer
    pub fn send_sync_request(&mut self, peer: PeerId, request: SyncRequest) {
        self.swarm
            .behaviour_mut()
            .request_response
            .send_request(&peer, request);
    }

    /// Send a sync response
    pub fn send_sync_response(&mut self, channel: ResponseChannelWrapper, response: SyncResponse) {
        let _ = self
            .swarm
            .behaviour_mut()
            .request_response
            .send_response(channel.0, response);
    }

    /// Process the next swarm event (single step)
    pub async fn process_next_event(&mut self) {
        match self.swarm.select_next_some().await {
            SwarmEvent::Behaviour(event) => {
                self.handle_behaviour_event(event).await;
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Listening on {}", address);
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                info!("Connected to peer: {}", peer_id);
                self.peers.write().insert(peer_id);
                let _ = self
                    .event_tx
                    .send(NetworkEvent::PeerConnected(peer_id))
                    .await;
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                info!("Disconnected from peer: {}", peer_id);
                self.peers.write().remove(&peer_id);
                let _ = self
                    .event_tx
                    .send(NetworkEvent::PeerDisconnected(peer_id))
                    .await;
            }
            SwarmEvent::IncomingConnection { .. } => {}
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                if let Some(peer_id) = peer_id {
                    warn!("Failed to connect to {}: {}", peer_id, error);
                }
            }
            _ => {}
        }
    }

    /// Run the event loop (should be spawned as a task)
    pub async fn run(&mut self) {
        loop {
            self.process_next_event().await;
        }
    }

    async fn handle_behaviour_event(&mut self, event: MiniChainBehaviourEvent) {
        match event {
            MiniChainBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                propagation_source,
                message,
                ..
            }) => {
                debug!("Gossip message from {}", propagation_source);
                let _ = self
                    .event_tx
                    .send(NetworkEvent::MessageReceived {
                        from: propagation_source,
                        data: message.data,
                    })
                    .await;
            }
            MiniChainBehaviourEvent::Mdns(mdns::Event::Discovered(list)) => {
                for (peer_id, addr) in list {
                    info!("mDNS discovered peer: {} at {}", peer_id, addr);
                    self.swarm
                        .behaviour_mut()
                        .gossipsub
                        .add_explicit_peer(&peer_id);
                    let _ = self.swarm.dial(addr);
                }
            }
            MiniChainBehaviourEvent::Mdns(mdns::Event::Expired(list)) => {
                for (peer_id, _) in list {
                    debug!("mDNS peer expired: {}", peer_id);
                    self.swarm
                        .behaviour_mut()
                        .gossipsub
                        .remove_explicit_peer(&peer_id);
                }
            }
            MiniChainBehaviourEvent::RequestResponse(request_response::Event::Message {
                peer,
                message,
            }) => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    debug!("Sync request from {}: {:?}", peer, request);
                    let _ = self
                        .event_tx
                        .send(NetworkEvent::SyncRequest {
                            from: peer,
                            request,
                            channel: ResponseChannelWrapper(channel),
                        })
                        .await;
                }
                request_response::Message::Response { response, .. } => {
                    debug!("Sync response from {}: {:?}", peer, response);
                }
            },
            MiniChainBehaviourEvent::Identify(identify::Event::Received {
                peer_id, info, ..
            }) => {
                // When we receive identify info from a peer, learn about their listen addresses
                info!(
                    "Identify received from {}: {:?}",
                    peer_id, info.listen_addrs
                );

                // Add to gossipsub mesh
                self.swarm
                    .behaviour_mut()
                    .gossipsub
                    .add_explicit_peer(&peer_id);

                // Also connect to other peers they know about through their observed addr
                // This helps with peer discovery in small networks
                for addr in info.listen_addrs {
                    // Only dial if it's a different peer and looks like a valid address
                    if !self.peers.read().contains(&peer_id) {
                        debug!("Discovered peer address via identify: {}", addr);
                    }
                }
            }
            MiniChainBehaviourEvent::Identify(identify::Event::Sent { peer_id, .. }) => {
                debug!("Identify sent to {}", peer_id);
            }
            _ => {}
        }
    }

    /// Add a peer to connect to
    pub fn dial_peer(&mut self, addr: Multiaddr) -> anyhow::Result<()> {
        self.swarm.dial(addr)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_node_creation() {
        let config = NodeConfig::default();
        let node = NetworkNode::new(config).await;
        assert!(node.is_ok());
    }
}
