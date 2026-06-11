// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dmq

import (
	"context"
	"errors"
	"net"
)

var errTopicNodeNil = errors.New("dmq topic node is nil")

// TopicNodeConfig configures a TopicNode.
type TopicNodeConfig struct {
	// Topic is the DMQ topic name. Required.
	Topic string

	// ManagerConfig configures the node's underlying Manager.
	ManagerConfig ManagerConfig

	// TopicConfig configures the node's single topic.
	TopicConfig TopicConfig

	// TopologyFile and StaticPeers are merged into TopicConfig.Discovery before
	// the topic is registered.
	TopologyFile string
	StaticPeers  []Peer

	// NodeToNode configures node-to-node networking. Networking starts only
	// when a listen address, peers, or a peer discovery source is configured.
	NodeToNode NodeToNodeConfig
}

// TopicNode is a single-topic DMQ node that bundles a Manager, one registered
// topic, and (when configured) a node-to-node service into one unit with a
// single lifecycle.
type TopicNode struct {
	topic   string
	manager *Manager
	service *NodeToNodeService
}

// NewTopicNode creates a Manager, registers the topic, and starts
// node-to-node networking when a listen address, peers, or a peer discovery
// source is configured. On failure, everything already started is shut down
// before returning. Release the node with Shutdown or Close.
func NewTopicNode(ctx context.Context, cfg TopicNodeConfig) (*TopicNode, error) {
	if ctx == nil {
		return nil, errors.New("context is nil")
	}
	topicCfg := cfg.TopicConfig
	if cfg.TopologyFile != "" || len(cfg.StaticPeers) > 0 {
		discovery, err := NewDiscoveryConfig(cfg.TopologyFile, cfg.StaticPeers)
		if err != nil {
			return nil, err
		}
		topicCfg.Discovery = mergeDiscoveryConfig(topicCfg.Discovery, discovery)
	}

	manager := NewManager(cfg.ManagerConfig)
	shutdownCtx := context.WithoutCancel(ctx)
	if err := manager.RegisterTopic(cfg.Topic, topicCfg); err != nil {
		_ = manager.Shutdown(shutdownCtx)
		return nil, err
	}

	node := &TopicNode{
		topic:   cfg.Topic,
		manager: manager,
	}
	if topicNodeNetworkConfigured(topicCfg, cfg.NodeToNode) {
		service, err := manager.StartNodeToNode(ctx, cfg.Topic, cfg.NodeToNode)
		if err != nil {
			_ = manager.Shutdown(shutdownCtx)
			return nil, err
		}
		node.service = service
	}
	return node, nil
}

// Topic returns the node's topic name.
func (n *TopicNode) Topic() string {
	if n == nil {
		return ""
	}
	return n.topic
}

// Manager returns the node's underlying Manager, for operations not exposed
// directly on TopicNode.
func (n *TopicNode) Manager() *Manager {
	if n == nil {
		return nil
	}
	return n.manager
}

// NodeToNodeService returns the node's networking service, or nil when
// networking was not configured.
func (n *TopicNode) NodeToNodeService() *NodeToNodeService {
	if n == nil {
		return nil
	}
	return n.service
}

// Publish signs and submits a message body on the node's topic. See
// Manager.Publish.
func (n *TopicNode) Publish(ctx context.Context, body []byte) (*DmqMessage, error) {
	if n == nil || n.manager == nil {
		return nil, errTopicNodeNil
	}
	return n.manager.Publish(ctx, n.topic, body)
}

// SubmitSigned submits an already signed message on the node's topic. See
// Manager.SubmitSigned.
func (n *TopicNode) SubmitSigned(ctx context.Context, msg *DmqMessage) error {
	if n == nil || n.manager == nil {
		return errTopicNodeNil
	}
	return n.manager.SubmitSigned(ctx, n.topic, msg)
}

// Subscribe registers a local fanout subscription on the node's topic. See
// Manager.Subscribe.
func (n *TopicNode) Subscribe() (*Subscription, error) {
	if n == nil || n.manager == nil {
		return nil, errTopicNodeNil
	}
	return n.manager.Subscribe(n.topic)
}

// ListenAddr returns the node-to-node listener address, or nil when no
// listener is running.
func (n *TopicNode) ListenAddr() net.Addr {
	if n == nil || n.service == nil {
		return nil
	}
	return n.service.ListenAddr()
}

// PeerCount returns the number of established node-to-node peer connections,
// or zero when networking is not running.
func (n *TopicNode) PeerCount() int {
	if n == nil || n.service == nil {
		return 0
	}
	return n.service.PeerCount()
}

// Shutdown stops the node's networking, topic, and Manager. See
// Manager.Shutdown.
func (n *TopicNode) Shutdown(ctx context.Context) error {
	if n == nil || n.manager == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("context is nil")
	}
	return n.manager.Shutdown(ctx)
}

// Close is Shutdown with a background context, satisfying io.Closer.
func (n *TopicNode) Close() error {
	return n.Shutdown(context.Background())
}

func mergeDiscoveryConfig(base, overlay DiscoveryConfig) DiscoveryConfig {
	if overlay.Topology != nil {
		base.Topology = overlay.Topology
	}
	if len(overlay.StaticPeers) > 0 {
		base.StaticPeers = append(clonePeers(base.StaticPeers), overlay.StaticPeers...)
	}
	return base
}

func topicNodeNetworkConfigured(topicCfg TopicConfig, nodeCfg NodeToNodeConfig) bool {
	return nodeCfg.ListenAddress != "" ||
		len(nodeCfg.Peers) > 0 ||
		topicCfg.Discovery.Topology != nil ||
		len(topicCfg.Discovery.StaticPeers) > 0 ||
		topicCfg.Discovery.LedgerPeers.Enabled
}
