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

type TopicNodeConfig struct {
	Topic string

	ManagerConfig ManagerConfig
	TopicConfig   TopicConfig

	// TopologyFile and StaticPeers are merged into TopicConfig.Discovery before
	// the topic is registered.
	TopologyFile string
	StaticPeers  []Peer

	NodeToNode NodeToNodeConfig
}

type TopicNode struct {
	topic   string
	manager *Manager
	service *NodeToNodeService
}

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

func (n *TopicNode) Topic() string {
	if n == nil {
		return ""
	}
	return n.topic
}

func (n *TopicNode) Manager() *Manager {
	if n == nil {
		return nil
	}
	return n.manager
}

func (n *TopicNode) NodeToNodeService() *NodeToNodeService {
	if n == nil {
		return nil
	}
	return n.service
}

func (n *TopicNode) Publish(ctx context.Context, body []byte) (*DmqMessage, error) {
	if n == nil || n.manager == nil {
		return nil, errTopicNodeNil
	}
	return n.manager.Publish(ctx, n.topic, body)
}

func (n *TopicNode) SubmitSigned(ctx context.Context, msg *DmqMessage) error {
	if n == nil || n.manager == nil {
		return errTopicNodeNil
	}
	return n.manager.SubmitSigned(ctx, n.topic, msg)
}

func (n *TopicNode) Subscribe() (*Subscription, error) {
	if n == nil || n.manager == nil {
		return nil, errTopicNodeNil
	}
	return n.manager.Subscribe(n.topic)
}

func (n *TopicNode) ListenAddr() net.Addr {
	if n == nil || n.service == nil {
		return nil
	}
	return n.service.ListenAddr()
}

func (n *TopicNode) PeerCount() int {
	if n == nil || n.service == nil {
		return 0
	}
	return n.service.PeerCount()
}

func (n *TopicNode) Shutdown(ctx context.Context) error {
	if n == nil || n.manager == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("context is nil")
	}
	return n.manager.Shutdown(ctx)
}

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
