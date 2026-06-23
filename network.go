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
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/blinklabs-io/gouroboros/connection"
	"github.com/blinklabs-io/gouroboros/muxer"
	"github.com/blinklabs-io/gouroboros/protocol"
	"github.com/blinklabs-io/gouroboros/protocol/handshake"
	"github.com/blinklabs-io/gouroboros/protocol/messagesubmission"
)

const (
	defaultNodeToNodeRequestInterval  = time.Second
	defaultNodeToNodeRequestCount     = uint16(64)
	defaultNodeToNodeDialTimeout      = 10 * time.Second
	defaultNodeToNodeHandshakeTimeout = 10 * time.Second
)

// StartNodeToNode starts a DMQ node-to-node service for a registered topic.
// The service listens, dials configured peers, and exchanges messages through
// the Manager's MessageSubmission topic queue.
func (m *Manager) StartNodeToNode(ctx context.Context, topic string, cfg NodeToNodeConfig) (*NodeToNodeService, error) {
	if ctx == nil {
		return nil, errors.New("context is nil")
	}
	rt, err := m.topic(topic)
	if err != nil {
		return nil, err
	}
	if rt.cfg.NetworkMagic == 0 {
		return nil, ErrNetworkMagicRequired
	}
	if !rt.cfg.Authentication.Required {
		if !rt.cfg.Authentication.AllowUnauthenticated {
			return nil, ErrAuthenticationRequired
		}
		rt.logger.Warn(
			"starting DMQ node-to-node networking without message authentication; " +
				"messages from remote peers are accepted and relayed after only " +
				"deterministic message-id and TTL checks, with NO KES signature, " +
				"operational certificate, or SPO registration verification. Set " +
				"TopicConfig.Authentication.Required and configure an authenticator " +
				"(KES verifier and active SPO pool set) before exposing this node to " +
				"untrusted peers",
		)
	}
	s := newNodeToNodeService(m, rt, ctx, cfg)
	if err := m.registerService(s); err != nil {
		return nil, err
	}
	if err := s.start(ctx); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

// NodeToNodeService runs DMQ node-to-node networking for one topic: an
// optional TCP listener for inbound peers and reconnecting outbound dials,
// each exchanging messages with the topic queue through the CIP-0137
// message-submission protocol. Create one with Manager.StartNodeToNode.
type NodeToNodeService struct {
	manager *Manager
	topic   *topicRuntime
	cfg     NodeToNodeConfig

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu        sync.Mutex
	closed    bool
	listener  net.Listener
	peers     map[*nodeToNodePeerConnection]struct{}
	outbound  map[string]struct{}
	listenErr error
}

func newNodeToNodeService(manager *Manager, topic *topicRuntime, ctx context.Context, cfg NodeToNodeConfig) *NodeToNodeService {
	cfg.Reconnect = defaultReconnectConfig(cfg.Reconnect)
	ctx, cancel := context.WithCancel(ctx)
	return &NodeToNodeService{
		manager:  manager,
		topic:    topic,
		cfg:      cfg,
		ctx:      ctx,
		cancel:   cancel,
		peers:    make(map[*nodeToNodePeerConnection]struct{}),
		outbound: make(map[string]struct{}),
	}
}

func (s *NodeToNodeService) start(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if s.cfg.ListenAddress != "" {
		listener, err := new(net.ListenConfig).Listen(ctx, "tcp", s.cfg.ListenAddress)
		if err != nil {
			return fmt.Errorf("listen DMQ node-to-node address %q: %w", s.cfg.ListenAddress, err)
		}
		s.mu.Lock()
		s.listener = listener
		s.mu.Unlock()
		s.wg.Add(1)
		go s.acceptLoop(listener)
	}
	go s.closeOnDone(ctx)

	peers, err := s.manager.TopicPeers(ctx, s.topic.name)
	if err != nil {
		s.Close()
		return err
	}
	for _, peer := range append(peers, s.cfg.Peers...) {
		s.AddPeer(peer)
	}
	return nil
}

func (s *NodeToNodeService) closeOnDone(ctx context.Context) {
	select {
	case <-ctx.Done():
	case <-s.ctx.Done():
	}
	_ = s.Close()
}

// Close stops the listener and all peer connections and waits for the
// service's goroutines to finish. It is idempotent and is also triggered by
// cancellation of the context passed to Manager.StartNodeToNode.
func (s *NodeToNodeService) Close() error {
	s.mu.Lock()
	if s.closed {
		listenErr := s.listenErr
		s.mu.Unlock()
		return listenErr
	}
	s.closed = true
	listener := s.listener
	peers := make([]*nodeToNodePeerConnection, 0, len(s.peers))
	for peer := range s.peers {
		peers = append(peers, peer)
	}
	s.mu.Unlock()

	s.cancel()
	s.manager.unregisterService(s)
	var errs []error
	if listener != nil {
		errs = append(errs, listener.Close())
	}
	for _, peer := range peers {
		peer.Close()
	}
	s.wg.Wait()
	s.mu.Lock()
	listenErr := s.listenErr
	s.mu.Unlock()
	if listenErr != nil && !errors.Is(listenErr, net.ErrClosed) {
		errs = append(errs, listenErr)
	}
	return errors.Join(errs...)
}

// ListenAddr returns the address the inbound listener is bound to, or nil
// when no listener was configured.
func (s *NodeToNodeService) ListenAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// PeerCount returns the number of currently established peer connections,
// inbound and outbound.
func (s *NodeToNodeService) PeerCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.peers)
}

// AddPeer starts a reconnecting outbound dial loop for the peer. Peers with
// no address or host, duplicates of already-tracked outbound addresses, and
// peers added after Close are ignored.
func (s *NodeToNodeService) AddPeer(peer Peer) {
	peer, ok := normalizeNodeToNodePeer(peer)
	if !ok {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	if _, exists := s.outbound[peer.Address]; exists {
		s.mu.Unlock()
		return
	}
	s.outbound[peer.Address] = struct{}{}
	s.wg.Add(1)
	s.mu.Unlock()
	go s.outboundLoop(peer)
}

func (s *NodeToNodeService) acceptLoop(listener net.Listener) {
	defer s.wg.Done()
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
			}
			s.setListenError(err)
			s.callError(fmt.Errorf("accept DMQ node-to-node peer: %w", err))
			_ = listener.Close()
			s.cancel()
			return
		}
		if conn == nil {
			err := errors.New("accept DMQ node-to-node peer: accepted nil connection")
			s.setListenError(err)
			s.callError(err)
			_ = listener.Close()
			s.cancel()
			return
		}
		remoteAddr := conn.RemoteAddr()
		if remoteAddr == nil {
			s.callError(errors.New("accept DMQ node-to-node peer: accepted connection with nil remote address"))
			_ = conn.Close()
			continue
		}
		peer := Peer{
			Address: remoteAddr.String(),
			Source:  PeerSourcePeerSharing,
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := s.handleConnection(conn, peer, true); err != nil &&
				!errors.Is(err, context.Canceled) &&
				!errors.Is(err, net.ErrClosed) {
				s.callError(fmt.Errorf("DMQ node-to-node peer %s: %w", peer.Address, err))
			}
		}()
	}
}

func (s *NodeToNodeService) setListenError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listenErr = err
}

func (s *NodeToNodeService) outboundLoop(peer Peer) {
	defer s.wg.Done()
	backoff := s.cfg.Reconnect.InitialBackoff
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}
		err := s.dialAndServe(peer)
		if err == nil {
			backoff = s.cfg.Reconnect.InitialBackoff
		}
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
			s.callError(fmt.Errorf("DMQ node-to-node peer %s: %w", peer.Address, err))
		}
		select {
		case <-s.ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > s.cfg.Reconnect.MaxBackoff {
			backoff = s.cfg.Reconnect.MaxBackoff
		}
	}
}

func (s *NodeToNodeService) dialAndServe(peer Peer) error {
	dialer := net.Dialer{Timeout: s.dialTimeout()}
	conn, err := dialer.DialContext(s.ctx, "tcp", peer.Address)
	if err != nil {
		return err
	}
	return s.handleConnection(conn, peer, false)
}

func (s *NodeToNodeService) handleConnection(conn net.Conn, peer Peer, server bool) error {
	peerConn, err := newNodeToNodePeerConnection(s, conn, peer, server)
	if err != nil {
		_ = conn.Close()
		return err
	}
	s.addConnection(peerConn)
	s.callPeerConnected(peer)
	peerConn.Wait()
	s.removeConnection(peerConn)
	err = peerConn.err()
	s.callPeerDisconnected(peer, err)
	return err
}

func (s *NodeToNodeService) addConnection(peer *nodeToNodePeerConnection) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		peer.Close()
		return
	}
	s.peers[peer] = struct{}{}
}

func (s *NodeToNodeService) removeConnection(peer *nodeToNodePeerConnection) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.peers, peer)
}

func (s *NodeToNodeService) requestInterval() time.Duration {
	if s.cfg.RequestInterval > 0 {
		return s.cfg.RequestInterval
	}
	return defaultNodeToNodeRequestInterval
}

func (s *NodeToNodeService) requestCount() uint16 {
	if s.cfg.RequestCount > 0 {
		return s.cfg.RequestCount
	}
	return defaultNodeToNodeRequestCount
}

func (s *NodeToNodeService) dialTimeout() time.Duration {
	if s.cfg.DialTimeout > 0 {
		return s.cfg.DialTimeout
	}
	return defaultNodeToNodeDialTimeout
}

func (s *NodeToNodeService) callPeerConnected(peer Peer) {
	if s.cfg.Hooks.OnPeerConnected != nil {
		s.cfg.Hooks.OnPeerConnected(s.ctx, s.topic.name, peer)
	}
}

func (s *NodeToNodeService) callPeerDisconnected(peer Peer, err error) {
	if s.cfg.Hooks.OnPeerDisconnected != nil {
		s.cfg.Hooks.OnPeerDisconnected(s.ctx, s.topic.name, peer, err)
	}
}

func (s *NodeToNodeService) callError(err error) {
	if err == nil {
		return
	}
	s.topic.callError(s.ctx, err)
	if s.cfg.Hooks.OnError != nil {
		s.cfg.Hooks.OnError(s.ctx, s.topic.name, err)
	}
}

func normalizeNodeToNodePeer(peer Peer) (Peer, bool) {
	if peer.Address == "" {
		if peer.Host == "" {
			return Peer{}, false
		}
		peer = newPeer(peer.Host, peer.Port, peer)
	}
	if peer.Source == "" {
		peer.Source = PeerSourceStatic
	}
	return peer, true
}

type nodeToNodePeerConnection struct {
	service *NodeToNodeService
	peer    Peer
	conn    net.Conn
	muxer   *muxer.Muxer

	errorCh      chan error
	protoErrorCh chan error
	done         chan struct{}
	closeOnce    sync.Once
	errMu        sync.Mutex
	lastErr      error

	messageSubmission *messagesubmission.MessageSubmission
}

func newNodeToNodePeerConnection(
	service *NodeToNodeService,
	conn net.Conn,
	peer Peer,
	server bool,
) (*nodeToNodePeerConnection, error) {
	p := &nodeToNodePeerConnection{
		service:      service,
		peer:         peer,
		conn:         conn,
		muxer:        muxer.New(conn),
		errorCh:      make(chan error, 2),
		protoErrorCh: make(chan error, 10),
		done:         make(chan struct{}),
	}
	version, err := p.handshake(server)
	if err != nil {
		p.Close()
		return nil, err
	}
	if err := p.startMessageSubmission(version); err != nil {
		p.Close()
		return nil, err
	}
	go p.forwardErrors()
	go p.runRequestLoop()
	return p, nil
}

func (p *nodeToNodePeerConnection) handshake(server bool) (version uint16, err error) {
	finished := make(chan uint16, 1)
	protoOptions := protocol.ProtocolOptions{
		ConnectionId: p.connectionID(),
		Muxer:        p.muxer,
		ErrorChan:    p.protoErrorCh,
		Mode:         protocol.ProtocolModeNodeToNode,
	}
	if server {
		protoOptions.Role = protocol.ProtocolRoleServer
	} else {
		protoOptions.Role = protocol.ProtocolRoleClient
	}
	handshakeConfig := handshake.NewConfig(
		handshake.WithProtocolVersionMap(
			protocol.GetProtocolVersionMapDMQNtN(
				p.service.topic.cfg.NetworkMagic,
				true,
				false,
				false,
			),
		),
		handshake.WithFinishedFunc(
			func(_ handshake.CallbackContext, version uint16, _ protocol.VersionData) error {
				finished <- version
				return nil
			},
		),
	)
	hs := handshake.New(protoOptions, &handshakeConfig)
	if err := p.conn.SetDeadline(time.Now().Add(defaultNodeToNodeHandshakeTimeout)); err != nil {
		return 0, err
	}
	defer func() {
		if deadlineErr := p.conn.SetDeadline(time.Time{}); deadlineErr != nil && err == nil {
			err = deadlineErr
		}
	}()
	if server {
		hs.Server.Start()
	} else {
		hs.Client.Start()
	}
	p.muxer.StartOnce()

	select {
	case <-p.service.ctx.Done():
		return 0, p.service.ctx.Err()
	case err := <-p.protoErrorCh:
		return 0, err
	case err := <-p.muxer.ErrorChan():
		return 0, err
	case version := <-finished:
		return version, nil
	}
}

func (p *nodeToNodePeerConnection) startMessageSubmission(version uint16) error {
	msgCfg, err := p.service.manager.messageSubmissionConfig(p.service.ctx, p.service.topic.name, &p.peer)
	if err != nil {
		return err
	}
	protoOptions := protocol.ProtocolOptions{
		ConnectionId: p.connectionID(),
		Muxer:        p.muxer,
		ErrorChan:    p.protoErrorCh,
		Mode:         protocol.ProtocolModeNodeToNode,
		Version:      version,
	}
	p.messageSubmission = messagesubmission.New(protoOptions, &msgCfg)
	p.messageSubmission.Client.Start()
	p.messageSubmission.Server.Start()
	p.muxer.SetDiffusionMode(muxer.DiffusionModeInitiatorAndResponder)
	p.muxer.Start()
	if version == protocol.ProtocolVersionDMQNtN1 {
		if err := p.messageSubmission.Client.Init(); err != nil {
			return err
		}
	}
	return nil
}

func (p *nodeToNodePeerConnection) runRequestLoop() {
	for {
		select {
		case <-p.service.ctx.Done():
			p.Close()
			return
		case <-p.done:
			return
		default:
		}
		if p.messageSubmission != nil && p.messageSubmission.Server != nil {
			if err := p.messageSubmission.Server.RequestMessageIdsBlocking(
				0,
				p.service.requestCount(),
			); err != nil {
				p.sendError(fmt.Errorf("request DMQ message IDs: %w", err))
				return
			}
		}
		timer := time.NewTimer(p.service.requestInterval())
		select {
		case <-p.service.ctx.Done():
			timer.Stop()
			p.Close()
			return
		case <-p.done:
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (p *nodeToNodePeerConnection) forwardErrors() {
	defer p.Close()
	select {
	case <-p.service.ctx.Done():
		return
	case <-p.done:
		return
	case err, ok := <-p.protoErrorCh:
		if ok && err != nil {
			p.sendError(err)
		}
	case err, ok := <-p.muxer.ErrorChan():
		if ok && err != nil {
			p.sendError(err)
		}
	}
}

func (p *nodeToNodePeerConnection) sendError(err error) {
	p.service.callError(err)
	p.errMu.Lock()
	p.lastErr = err
	p.errMu.Unlock()
	select {
	case p.errorCh <- err:
	default:
	}
}

func (p *nodeToNodePeerConnection) err() error {
	p.errMu.Lock()
	defer p.errMu.Unlock()
	return p.lastErr
}

func (p *nodeToNodePeerConnection) Wait() {
	select {
	case <-p.service.ctx.Done():
		p.Close()
	case <-p.done:
	case <-p.errorCh:
		p.Close()
	}
}

func (p *nodeToNodePeerConnection) Close() {
	p.closeOnce.Do(func() {
		close(p.done)
		if p.messageSubmission != nil {
			if p.messageSubmission.Server != nil {
				_ = p.messageSubmission.Server.Done()
			}
			if p.messageSubmission.Client != nil {
				_ = p.messageSubmission.Client.Stop()
			}
		}
		if p.muxer != nil {
			p.muxer.Stop()
		}
		if p.conn != nil {
			_ = p.conn.Close()
		}
	})
}

func (p *nodeToNodePeerConnection) connectionID() connection.ConnectionId {
	return connection.ConnectionId{
		LocalAddr:  p.conn.LocalAddr(),
		RemoteAddr: p.conn.RemoteAddr(),
	}
}
