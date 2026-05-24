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
	"io"
	"math/big"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/blinklabs-io/dingo/peergov"
	dtopology "github.com/blinklabs-io/dingo/topology"
	gcbor "github.com/blinklabs-io/gouroboros/cbor"
	"github.com/blinklabs-io/gouroboros/protocol/localstatequery"
)

type DiscoveryConfig struct {
	Topology    *dtopology.TopologyConfig
	StaticPeers []Peer

	PeerSharing      bool
	PeerSharingQuota int
	TopologyQuota    int

	LedgerPeers LedgerPeerDiscoveryConfig
}

type LedgerPeerDiscoveryConfig struct {
	Enabled bool

	UseLedgerAfterSlot int64
	RefreshInterval    time.Duration
	Target             int
	BigLedgerTarget    int

	Provider         LedgerPeerSnapshotProvider
	AllowUnsupported bool
}

// LedgerPeerSnapshotProvider supplies Cardano ledger relay snapshots.
type LedgerPeerSnapshotProvider interface {
	LedgerPeerSnapshot(ctx context.Context, kind LedgerPeerSnapshotKind) (LedgerPeerSnapshot, error)
}

type LedgerPeerSnapshotKind string

const (
	LedgerPeerSnapshotAll LedgerPeerSnapshotKind = "all-ledger-peers"
	LedgerPeerSnapshotBig LedgerPeerSnapshotKind = "big-ledger-peers"
)

type LedgerPeerSnapshot struct {
	Slot  uint64
	Peers []LedgerPeer
}

type LedgerPeer struct {
	PoolID string
	Stake  uint64
	Relays []LedgerRelay
}

type LedgerRelayKind string

const (
	LedgerRelaySingleHostAddress LedgerRelayKind = "single-host-address"
	LedgerRelaySingleHostName    LedgerRelayKind = "single-host-name"
	LedgerRelaySRV               LedgerRelayKind = "srv"
)

type LedgerRelay struct {
	Kind LedgerRelayKind

	Hostname string
	SRVName  string
	Port     uint
	IPv4     net.IP
	IPv6     net.IP
}

type LedgerPeerPools struct {
	All []Peer
	Big []Peer
}

type Peer struct {
	Address string
	Host    string
	Port    uint

	Source      PeerSource
	PoolID      string
	Stake       uint64
	Valency     uint
	WarmValency uint
	Advertise   bool
	Trustable   bool
}

type PeerSource string

const (
	PeerSourceStatic            PeerSource = "static"
	PeerSourceTopologyLocalRoot PeerSource = "topology-local-root"
	PeerSourceTopologyPublic    PeerSource = "topology-public-root"
	PeerSourceTopologyBootstrap PeerSource = "topology-bootstrap"
	PeerSourcePeerSharing       PeerSource = "peer-sharing"
	PeerSourceLedger            PeerSource = "ledger"
	PeerSourceBigLedger         PeerSource = "big-ledger"
)

func defaultDiscoveryConfig(cfg DiscoveryConfig) DiscoveryConfig {
	if cfg.TopologyQuota <= 0 {
		cfg.TopologyQuota = 20
	}
	if cfg.PeerSharingQuota <= 0 {
		cfg.PeerSharingQuota = 20
	}
	if cfg.LedgerPeers.RefreshInterval <= 0 {
		cfg.LedgerPeers.RefreshInterval = time.Hour
	}
	if cfg.LedgerPeers.Target == 0 {
		cfg.LedgerPeers.Target = 20
	}
	if cfg.LedgerPeers.BigLedgerTarget == 0 {
		cfg.LedgerPeers.BigLedgerTarget = 5
	}
	return cfg
}

func ReadTopology(r io.Reader) (*dtopology.TopologyConfig, error) {
	return dtopology.NewTopologyConfigFromReader(r)
}

func TopologyPeers(cfg *dtopology.TopologyConfig) []Peer {
	if cfg == nil {
		return nil
	}
	var peers []Peer
	for _, root := range cfg.LocalRoots {
		for _, ap := range root.AccessPoints {
			peers = append(peers, newPeer(ap.Address, ap.Port, Peer{
				Source:      PeerSourceTopologyLocalRoot,
				Valency:     root.Valency,
				WarmValency: root.WarmValency,
				Advertise:   root.Advertise,
				Trustable:   root.Trustable,
			}))
		}
	}
	for _, root := range cfg.PublicRoots {
		for _, ap := range root.AccessPoints {
			peers = append(peers, newPeer(ap.Address, ap.Port, Peer{
				Source:      PeerSourceTopologyPublic,
				Valency:     root.Valency,
				WarmValency: root.WarmValency,
				Advertise:   root.Advertise,
			}))
		}
	}
	for _, ap := range cfg.BootstrapPeers {
		peers = append(peers, newPeer(ap.Address, ap.Port, Peer{
			Source: PeerSourceTopologyBootstrap,
		}))
	}
	return peers
}

func BuildLedgerPeerPools(snapshot LedgerPeerSnapshot) LedgerPeerPools {
	all := make([]Peer, 0, len(snapshot.Peers))
	for _, lp := range snapshot.Peers {
		for _, relay := range lp.Relays {
			all = append(all, ledgerRelayPeers(lp, relay)...)
		}
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Stake == all[j].Stake {
			return all[i].Address < all[j].Address
		}
		return all[i].Stake > all[j].Stake
	})
	big := bigLedgerPeers(snapshot.Peers)
	return LedgerPeerPools{All: all, Big: big}
}

func (r LedgerRelay) IsSRV() bool {
	return r.Kind == LedgerRelaySRV || r.SRVName != "" ||
		(r.Kind == "" && r.Hostname != "" && r.Port == 0)
}

func ledgerRelayPeers(lp LedgerPeer, relay LedgerRelay) []Peer {
	base := Peer{
		Source: PeerSourceLedger,
		PoolID: lp.PoolID,
		Stake:  lp.Stake,
	}
	if relay.IsSRV() {
		host := relay.SRVName
		if host == "" {
			host = relay.Hostname
		}
		if host == "" {
			return nil
		}
		return []Peer{newPeer(host, relay.Port, base)}
	}

	port := relay.Port
	if port == 0 {
		port = 3001
	}
	peers := make([]Peer, 0, 3)
	if relay.Hostname != "" {
		peers = append(peers, newPeer(relay.Hostname, port, base))
	}
	if len(relay.IPv4) > 0 {
		peers = append(peers, newPeer(relay.IPv4.String(), port, base))
	}
	if len(relay.IPv6) > 0 {
		peers = append(peers, newPeer(relay.IPv6.String(), port, base))
	}
	return peers
}

func bigLedgerPeers(peers []LedgerPeer) []Peer {
	pools := make(map[string]LedgerPeer, len(peers))
	poolOrder := make([]string, 0, len(peers))
	var total uint64
	for i, peer := range peers {
		if peer.Stake == 0 {
			continue
		}
		key := ledgerPeerPoolKey(peer, i)
		current, ok := pools[key]
		if !ok {
			pools[key] = peer
			poolOrder = append(poolOrder, key)
			total += peer.Stake
			continue
		}
		if peer.Stake > current.Stake {
			total += peer.Stake - current.Stake
			pools[key] = peer
		}
	}
	if total == 0 || len(pools) == 0 {
		return nil
	}
	sort.SliceStable(poolOrder, func(i, j int) bool {
		left := pools[poolOrder[i]]
		right := pools[poolOrder[j]]
		if left.Stake == right.Stake {
			return poolOrder[i] < poolOrder[j]
		}
		return left.Stake > right.Stake
	})

	selectedPools := make(map[string]struct{}, len(poolOrder))
	threshold := total - total/10
	var acc uint64
	for _, key := range poolOrder {
		pool := pools[key]
		selectedPools[key] = struct{}{}
		acc += pool.Stake
		if acc >= threshold {
			break
		}
	}

	big := make([]Peer, 0, len(peers))
	for i, peer := range peers {
		if _, ok := selectedPools[ledgerPeerPoolKey(peer, i)]; !ok {
			continue
		}
		for _, relay := range peer.Relays {
			relayPeers := ledgerRelayPeers(peer, relay)
			for j := range relayPeers {
				relayPeers[j].Source = PeerSourceBigLedger
			}
			big = append(big, relayPeers...)
		}
	}
	return big
}

func ledgerPeerPoolKey(peer LedgerPeer, index int) string {
	if peer.PoolID != "" {
		return "pool:" + peer.PoolID
	}
	return "idx:" + strconv.Itoa(index)
}

func (t *topicRuntime) discoverPeers(ctx context.Context) ([]Peer, error) {
	if !t.cfg.Discovery.LedgerPeers.Enabled {
		return t.peerSelector.Peers(), nil
	}
	cfg := t.cfg.Discovery.LedgerPeers
	if cfg.Provider == nil {
		if cfg.AllowUnsupported {
			return t.peerSelector.Peers(), nil
		}
		return nil, ErrLedgerPeerSnapshotProviderUnset
	}
	snapshot, err := cfg.Provider.LedgerPeerSnapshot(ctx, LedgerPeerSnapshotAll)
	if err != nil {
		if cfg.AllowUnsupported && errors.Is(err, ErrLedgerPeerSnapshotUnsupported) {
			return t.peerSelector.Peers(), nil
		}
		return nil, err
	}
	pools := BuildLedgerPeerPools(snapshot)
	t.peerSelector.setPeersForSources(
		[]PeerSource{PeerSourceLedger, PeerSourceBigLedger},
		append(pools.All, pools.Big...),
	)
	peers := t.peerSelector.Peers()
	if t.cfg.Hooks.OnPeerDiscovered != nil {
		t.cfg.Hooks.OnPeerDiscovered(ctx, t.name, peers)
	}
	return peers, nil
}

type DingoLedgerPeerProviderAdapter struct {
	Provider       peergov.LedgerPeerProvider
	StakedProvider StakedLedgerPeerProvider
	AllowRelayOnly bool
}

type StakedLedgerPeerProvider interface {
	GetLedgerPeers() ([]LedgerPeer, error)
	CurrentSlot() uint64
}

func (a DingoLedgerPeerProviderAdapter) LedgerPeerSnapshot(ctx context.Context, kind LedgerPeerSnapshotKind) (LedgerPeerSnapshot, error) {
	if a.StakedProvider != nil {
		return stakedProviderSnapshot(ctx, a.StakedProvider)
	}
	if provider, ok := a.Provider.(StakedLedgerPeerProvider); ok {
		return stakedProviderSnapshot(ctx, provider)
	}
	if a.Provider == nil {
		return LedgerPeerSnapshot{}, ErrLedgerPeerSnapshotProviderUnset
	}
	if !a.AllowRelayOnly {
		return LedgerPeerSnapshot{}, fmt.Errorf(
			"%w: dingo peergov.LedgerPeerProvider does not expose pool stake metadata; use StakedProvider or LocalStateQueryLedgerPeerSnapshotProvider",
			ErrLedgerPeerSnapshotUnsupported,
		)
	}
	if kind == LedgerPeerSnapshotBig {
		return LedgerPeerSnapshot{}, fmt.Errorf(
			"%w: relay-only dingo peergov.LedgerPeerProvider cannot produce big-ledger peers",
			ErrLedgerPeerSnapshotUnsupported,
		)
	}
	select {
	case <-ctx.Done():
		return LedgerPeerSnapshot{}, ctx.Err()
	default:
	}
	relays, err := a.Provider.GetPoolRelays()
	if err != nil {
		return LedgerPeerSnapshot{}, err
	}
	peers := make([]LedgerPeer, 0, len(relays))
	for _, relay := range relays {
		peers = append(peers, LedgerPeer{
			Relays: []LedgerRelay{dingoRelayToLedgerRelay(relay)},
		})
	}
	return LedgerPeerSnapshot{Slot: a.Provider.CurrentSlot(), Peers: peers}, nil
}

func stakedProviderSnapshot(ctx context.Context, provider StakedLedgerPeerProvider) (LedgerPeerSnapshot, error) {
	select {
	case <-ctx.Done():
		return LedgerPeerSnapshot{}, ctx.Err()
	default:
	}
	peers, err := provider.GetLedgerPeers()
	if err != nil {
		return LedgerPeerSnapshot{}, err
	}
	return LedgerPeerSnapshot{Slot: provider.CurrentSlot(), Peers: cloneLedgerPeers(peers)}, nil
}

type LocalStateQueryLedgerPeerSnapshotClient interface {
	GetLedgerPeerSnapshot(localstatequery.LedgerPeerKind) (*localstatequery.LedgerPeerSnapshotResult, error)
}

type LocalStateQueryLedgerPeerSnapshotProvider struct {
	Client LocalStateQueryLedgerPeerSnapshotClient
}

func (p LocalStateQueryLedgerPeerSnapshotProvider) LedgerPeerSnapshot(ctx context.Context, kind LedgerPeerSnapshotKind) (LedgerPeerSnapshot, error) {
	if p.Client == nil {
		return LedgerPeerSnapshot{}, ErrLedgerPeerSnapshotProviderUnset
	}
	peerKind, err := localStateQueryLedgerPeerKind(kind)
	if err != nil {
		return LedgerPeerSnapshot{}, err
	}
	select {
	case <-ctx.Done():
		return LedgerPeerSnapshot{}, ctx.Err()
	default:
	}
	snapshot, err := p.Client.GetLedgerPeerSnapshot(peerKind)
	if errors.Is(err, localstatequery.ErrLedgerPeerSnapshotUnsupportedVersion) {
		return LedgerPeerSnapshot{}, ErrLedgerPeerSnapshotUnsupported
	}
	if err != nil {
		return LedgerPeerSnapshot{}, err
	}
	select {
	case <-ctx.Done():
		return LedgerPeerSnapshot{}, ctx.Err()
	default:
	}
	return convertLocalStateQueryLedgerPeerSnapshot(snapshot), nil
}

func localStateQueryLedgerPeerKind(kind LedgerPeerSnapshotKind) (localstatequery.LedgerPeerKind, error) {
	switch kind {
	case "", LedgerPeerSnapshotAll:
		return localstatequery.LedgerPeerKindAll, nil
	case LedgerPeerSnapshotBig:
		return localstatequery.LedgerPeerKindBig, nil
	default:
		return 0, fmt.Errorf("unknown ledger peer snapshot kind: %s", kind)
	}
}

func convertLocalStateQueryLedgerPeerSnapshot(snapshot *localstatequery.LedgerPeerSnapshotResult) LedgerPeerSnapshot {
	if snapshot == nil {
		return LedgerPeerSnapshot{}
	}
	ret := LedgerPeerSnapshot{
		Peers: make([]LedgerPeer, 0, len(snapshot.Pools)),
	}
	if snapshot.Slot.HasSlot {
		ret.Slot = snapshot.Slot.Slot
	}
	for _, pool := range snapshot.Pools {
		peer := LedgerPeer{
			Stake:  ledgerStakeFromRat(pool.Detail.PoolStake),
			Relays: make([]LedgerRelay, 0, len(pool.Detail.Relays)),
		}
		for _, relay := range pool.Detail.Relays {
			peer.Relays = append(peer.Relays, localStateQueryRelayToLedgerRelay(relay))
		}
		ret.Peers = append(ret.Peers, peer)
	}
	return ret
}

func ledgerStakeFromRat(stake *gcbor.Rat) uint64 {
	if stake == nil || stake.Rat == nil || stake.Sign() <= 0 {
		return 0
	}
	maxUint64 := new(big.Int).SetUint64(^uint64(0))
	scaled := new(big.Int).Mul(stake.Num(), maxUint64)
	scaled.Quo(scaled, stake.Denom())
	if !scaled.IsUint64() {
		return ^uint64(0)
	}
	return scaled.Uint64()
}

func localStateQueryRelayToLedgerRelay(relay localstatequery.RelayAccessPoint) LedgerRelay {
	switch relay.Kind {
	case localstatequery.RelayKindIPv4:
		ret := LedgerRelay{Kind: LedgerRelaySingleHostAddress}
		if relay.Port != nil {
			ret.Port = uint(*relay.Port)
		}
		if relay.IPv4 != nil {
			ret.IPv4 = cloneIP(*relay.IPv4)
		}
		return ret
	case localstatequery.RelayKindIPv6:
		ret := LedgerRelay{Kind: LedgerRelaySingleHostAddress}
		if relay.Port != nil {
			ret.Port = uint(*relay.Port)
		}
		if relay.IPv6 != nil {
			ret.IPv6 = cloneIP(*relay.IPv6)
		}
		return ret
	case localstatequery.RelayKindDomain:
		ret := LedgerRelay{Kind: LedgerRelaySingleHostName}
		if relay.Port != nil {
			ret.Port = uint(*relay.Port)
		}
		if relay.Domain != nil {
			ret.Hostname = *relay.Domain
		}
		return ret
	case localstatequery.RelayKindSRV:
		ret := LedgerRelay{Kind: LedgerRelaySRV}
		if relay.Domain != nil {
			ret.SRVName = *relay.Domain
		}
		return ret
	default:
		return LedgerRelay{}
	}
}

func dingoRelayToLedgerRelay(relay peergov.PoolRelay) LedgerRelay {
	kind := LedgerRelaySingleHostName
	if relay.Hostname != "" && relay.Port == 0 {
		kind = LedgerRelaySRV
	}
	ret := LedgerRelay{
		Kind:     kind,
		Hostname: relay.Hostname,
		Port:     relay.Port,
	}
	if relay.IPv4 != nil {
		ret.Kind = LedgerRelaySingleHostAddress
		ret.IPv4 = append(net.IP(nil), (*relay.IPv4)...)
	}
	if relay.IPv6 != nil {
		ret.Kind = LedgerRelaySingleHostAddress
		ret.IPv6 = append(net.IP(nil), (*relay.IPv6)...)
	}
	return ret
}

func newPeer(host string, port uint, base Peer) Peer {
	base.Host = host
	base.Port = port
	if port == 0 {
		base.Address = host
	} else {
		base.Address = net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10))
	}
	return base
}

func clonePeerPtr(peer *Peer) *Peer {
	if peer == nil {
		return nil
	}
	cp := *peer
	return &cp
}

func cloneLedgerPeers(peers []LedgerPeer) []LedgerPeer {
	if peers == nil {
		return nil
	}
	ret := make([]LedgerPeer, len(peers))
	for i, peer := range peers {
		ret[i] = LedgerPeer{
			PoolID: peer.PoolID,
			Stake:  peer.Stake,
			Relays: cloneLedgerRelays(peer.Relays),
		}
	}
	return ret
}

func cloneLedgerRelays(relays []LedgerRelay) []LedgerRelay {
	if relays == nil {
		return nil
	}
	ret := make([]LedgerRelay, len(relays))
	for i, relay := range relays {
		ret[i] = relay
		ret[i].IPv4 = cloneIP(relay.IPv4)
		ret[i].IPv6 = cloneIP(relay.IPv6)
	}
	return ret
}

func cloneIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	ret := make(net.IP, len(ip))
	copy(ret, ip)
	return ret
}

type PeerSelectionConfig struct {
	TopologyQuota  int
	PeerShareQuota int
	LedgerQuota    int
	BigLedgerQuota int
}

type PeerSelector struct {
	mu    sync.RWMutex
	cfg   PeerSelectionConfig
	peers map[string]Peer
}

func NewPeerSelector(cfg PeerSelectionConfig) *PeerSelector {
	return &PeerSelector{
		cfg:   cfg,
		peers: make(map[string]Peer),
	}
}

func (s *PeerSelector) AddPeers(peers []Peer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addPeersLocked(peers)
}

func (s *PeerSelector) setPeersForSources(sources []PeerSource, peers []Peer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sourceSet := make(map[PeerSource]struct{}, len(sources))
	for _, source := range sources {
		sourceSet[source] = struct{}{}
	}
	for key, peer := range s.peers {
		if _, ok := sourceSet[peer.Source]; ok {
			delete(s.peers, key)
		}
	}
	s.addPeersLocked(peers)
}

func (s *PeerSelector) addPeersLocked(peers []Peer) {
	for _, peer := range peers {
		if peer.Address == "" {
			if peer.Host == "" {
				continue
			}
			peer = newPeer(peer.Host, peer.Port, peer)
		}
		key := fmt.Sprintf("%s/%s", peer.Source, peer.Address)
		s.peers[key] = peer
	}
}

func (s *PeerSelector) Peers() []Peer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ret := make([]Peer, 0, len(s.peers))
	for _, peer := range s.peers {
		ret = append(ret, peer)
	}
	sortPeers(ret)
	return ret
}

func (s *PeerSelector) Select(n int) []Peer {
	peers := s.Peers()
	selected := make([]Peer, 0, len(peers))
	counts := map[peerQuotaClass]int{}
	for _, peer := range peers {
		class, quota := quotaForSource(peer.Source, s.cfg)
		if quota > 0 && counts[class] >= quota {
			continue
		}
		selected = append(selected, peer)
		counts[class]++
		if n > 0 && len(selected) >= n {
			break
		}
	}
	return selected
}

type peerQuotaClass string

const (
	peerQuotaClassTopology peerQuotaClass = "topology"
	peerQuotaClassSharing  peerQuotaClass = "peer-sharing"
	peerQuotaClassLedger   peerQuotaClass = "ledger"
	peerQuotaClassBig      peerQuotaClass = "big-ledger"
)

func quotaForSource(source PeerSource, cfg PeerSelectionConfig) (peerQuotaClass, int) {
	if isTopologyQuotaSource(source) {
		return peerQuotaClassTopology, cfg.TopologyQuota
	}
	switch source {
	case PeerSourceTopologyLocalRoot, PeerSourceTopologyPublic, PeerSourceTopologyBootstrap, PeerSourceStatic:
		return peerQuotaClassTopology, cfg.TopologyQuota
	case PeerSourcePeerSharing:
		return peerQuotaClassSharing, cfg.PeerShareQuota
	case PeerSourceLedger:
		return peerQuotaClassLedger, cfg.LedgerQuota
	case PeerSourceBigLedger:
		return peerQuotaClassBig, cfg.BigLedgerQuota
	}
	return peerQuotaClass(source), 0
}

func isTopologyQuotaSource(source PeerSource) bool {
	switch source {
	case PeerSourceTopologyLocalRoot, PeerSourceTopologyPublic, PeerSourceTopologyBootstrap, PeerSourceStatic:
		return true
	case PeerSourcePeerSharing, PeerSourceLedger, PeerSourceBigLedger:
		return false
	}
	return false
}

func sortPeers(peers []Peer) {
	sort.SliceStable(peers, func(i, j int) bool {
		if peers[i].Source == peers[j].Source {
			return peers[i].Address < peers[j].Address
		}
		return peers[i].Source < peers[j].Source
	})
}
