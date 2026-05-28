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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNetworkParamsFromShelleyGenesis(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shelley-genesis.json")
	if err := os.WriteFile(path, []byte(`{
		"systemStart": "2026-01-01T00:00:00Z",
		"slotLength": 0.1,
		"epochLength": 5,
		"slotsPerKESPeriod": 10,
		"maxKESEvolutions": 60
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	params, err := NetworkParamsFromShelleyGenesis(path)
	if err != nil {
		t.Fatal(err)
	}
	if params.SlotLength != 100*time.Millisecond {
		t.Fatalf("SlotLength=%s, want 100ms", params.SlotLength)
	}
	period, err := CurrentKESPeriodFor(params, params.Start.Add(25*params.SlotLength))
	if err != nil {
		t.Fatal(err)
	}
	if period != 2 {
		t.Fatalf("KES period=%d, want 2", period)
	}
	epoch, err := CurrentEpochFor(params, params.Start.Add(12*params.SlotLength))
	if err != nil {
		t.Fatal(err)
	}
	if epoch != 2 {
		t.Fatalf("epoch=%d, want 2", epoch)
	}
}

func TestNetworkParamsFromShelleyGenesisUsesAbsoluteStartSlot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shelley-genesis.json")
	if err := os.WriteFile(path, []byte(`{
		"systemStart": "2026-01-01T00:00:00Z",
		"slotLength": 1,
		"epochLength": 100,
		"slotsPerKESPeriod": 10,
		"maxKESEvolutions": 60,
		"absoluteStartSlot": 95
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	params, err := NetworkParamsFromShelleyGenesis(path)
	if err != nil {
		t.Fatal(err)
	}
	if params.AbsoluteStartSlot != 95 {
		t.Fatalf("AbsoluteStartSlot=%d, want 95", params.AbsoluteStartSlot)
	}
	period, err := CurrentKESPeriodFor(params, params.Start.Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if period != 10 {
		t.Fatalf("KES period=%d, want 10", period)
	}
	start := KESPeriodStart(params, 11)
	if !start.Equal(params.Start.Add(15 * time.Second)) {
		t.Fatalf("KES period start=%s, want %s", start, params.Start.Add(15*time.Second))
	}
}

func TestNetworkParamsForMagicMainnetUsesShelleyStartOffset(t *testing.T) {
	params, err := NetworkParamsForMagic(764824073)
	if err != nil {
		t.Fatal(err)
	}
	if params.AbsoluteStartSlot != CardanoMainnetShelleyStartSlot {
		t.Fatalf("AbsoluteStartSlot=%d, want %d", params.AbsoluteStartSlot, CardanoMainnetShelleyStartSlot)
	}
	period, err := CurrentKESPeriodFor(params, params.Start)
	if err != nil {
		t.Fatal(err)
	}
	if period != 34 {
		t.Fatalf("KES period=%d, want 34", period)
	}
}

func TestNetworkParamsForMagicPreprodUsesShelleyStartOffset(t *testing.T) {
	params, err := NetworkParamsForMagic(1)
	if err != nil {
		t.Fatal(err)
	}
	if !params.Start.Equal(cardanoPreprodShelleyStart) {
		t.Fatalf("Start=%s, want %s", params.Start, cardanoPreprodShelleyStart)
	}
	if params.AbsoluteStartSlot != CardanoPreprodShelleyStartSlot {
		t.Fatalf("AbsoluteStartSlot=%d, want %d", params.AbsoluteStartSlot, CardanoPreprodShelleyStartSlot)
	}
	tests := []struct {
		relativeSlot uint64
		wantPeriod   uint64
	}{
		{relativeSlot: 0, wantPeriod: 0},
		{relativeSlot: 43199, wantPeriod: 0},
		{relativeSlot: 43200, wantPeriod: 1},
		{relativeSlot: 172800, wantPeriod: 2},
	}
	for _, tt := range tests {
		now := params.Start.Add(time.Duration(tt.relativeSlot) * params.SlotLength)
		period, err := CurrentKESPeriodFor(params, now)
		if err != nil {
			t.Fatal(err)
		}
		if period != tt.wantPeriod {
			t.Fatalf("relative slot %d KES period=%d, want %d", tt.relativeSlot, period, tt.wantPeriod)
		}
	}
}

func TestNetworkParamsFromMainnetShelleyGenesisUsesShelleyStartOffset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shelley-genesis.json")
	if err := os.WriteFile(path, []byte(`{
		"systemStart": "2017-09-23T21:44:51Z",
		"slotLength": 1,
		"epochLength": 432000,
		"slotsPerKESPeriod": 129600,
		"maxKESEvolutions": 62,
		"networkMagic": 764824073
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	params, err := NetworkParamsFromShelleyGenesis(path)
	if err != nil {
		t.Fatal(err)
	}
	if !params.Start.Equal(cardanoMainnetShelleyStart) {
		t.Fatalf("Start=%s, want %s", params.Start, cardanoMainnetShelleyStart)
	}
	if params.AbsoluteStartSlot != CardanoMainnetShelleyStartSlot {
		t.Fatalf("AbsoluteStartSlot=%d, want %d", params.AbsoluteStartSlot, CardanoMainnetShelleyStartSlot)
	}
}

func TestKESSignerSignsArbitraryPayload(t *testing.T) {
	dir := t.TempDir()
	kesPath, opcertPath := writeSignerFixtures(t, dir, 5)
	params := NetworkParams{
		Start:             time.Unix(0, 0).UTC(),
		SlotLength:        time.Second,
		EpochLength:       100,
		SlotsPerKESPeriod: 10,
		MaxKESEvolutions:  60,
	}
	signer, err := NewKESSignerWithClock(kesPath, opcertPath, params, func() time.Time {
		return params.Start.Add(55 * time.Second)
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("arbitrary payload")
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	if signed.Period != 0 {
		t.Fatalf("relative KES period=%d, want 0", signed.Period)
	}
	cert := signer.OperationalCertificate()
	if !VerifyKESSignature(cert.KESVKey, signed.Period, payload, signed.Signature) {
		t.Fatal("KES signature did not verify")
	}
}

func TestKESSignerSignAtRejectsNetworkKESLimit(t *testing.T) {
	dir := t.TempDir()
	kesPath, opcertPath := writeSignerFixtures(t, dir, 5)
	params := NetworkParams{
		Start:             time.Unix(0, 0).UTC(),
		SlotLength:        time.Second,
		EpochLength:       100,
		SlotsPerKESPeriod: 10,
		MaxKESEvolutions:  1,
	}
	signer, err := NewKESSignerWithClock(kesPath, opcertPath, params, func() time.Time {
		return params.Start.Add(55 * time.Second)
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.SignAt(1, []byte("payload")); err == nil || !strings.Contains(err.Error(), "past op cert validity") {
		t.Fatalf("SignAt beyond network KES limit error=%v, want op cert validity error", err)
	}
	if _, err := signer.SignAt(0, []byte("payload")); err != nil {
		t.Fatalf("SignAt mutated key before rejecting invalid period: %v", err)
	}
}

func TestExternalKESSignerSignAtRejectsNetworkKESLimit(t *testing.T) {
	dir := t.TempDir()
	_, opcertPath := writeSignerFixtures(t, dir, 5)
	params := NetworkParams{
		Start:             time.Unix(0, 0).UTC(),
		SlotLength:        time.Second,
		EpochLength:       100,
		SlotsPerKESPeriod: 10,
		MaxKESEvolutions:  1,
	}
	signer, err := NewExternalKESSignerFromConfig(ExternalKESSignerConfig{
		Command:                    filepath.Join(dir, "not-run"),
		OperationalCertificatePath: opcertPath,
		Network:                    params,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.SignAt(1, []byte("payload")); err == nil || !strings.Contains(err.Error(), "past op cert validity") {
		t.Fatalf("SignAt beyond network KES limit error=%v, want op cert validity error", err)
	}
}

func TestOperationalCredentialHelpers(t *testing.T) {
	dir := t.TempDir()
	kesPath, opcertPath := writeSignerFixtures(t, dir, 5)
	if err := ValidateOperationalCredentials(kesPath, opcertPath); err != nil {
		t.Fatal(err)
	}
	cert, err := LoadOperationalCertificate(opcertPath)
	if err != nil {
		t.Fatal(err)
	}
	coldVKey, err := ColdVerificationKeyFromOpCert(opcertPath)
	if err != nil {
		t.Fatal(err)
	}
	poolA, err := PoolIDFromColdKey(coldVKey)
	if err != nil {
		t.Fatal(err)
	}
	poolB, err := PoolIDFromColdKey(cert.ColdVKey)
	if err != nil {
		t.Fatal(err)
	}
	if poolA != poolB {
		t.Fatalf("pool IDs differ: %s != %s", poolA, poolB)
	}
}

func TestKESSignerCanBuildDMQMessage(t *testing.T) {
	dir := t.TempDir()
	kesPath, opcertPath := writeSignerFixtures(t, dir, 5)
	params := NetworkParams{
		Start:             time.Unix(0, 0).UTC(),
		SlotLength:        time.Second,
		EpochLength:       100,
		SlotsPerKESPeriod: 10,
		MaxKESEvolutions:  60,
	}
	signer, err := NewKESSignerWithClock(kesPath, opcertPath, params, func() time.Time {
		return params.Start.Add(55 * time.Second)
	})
	if err != nil {
		t.Fatal(err)
	}
	managerSigner := NewKESSigningProviderSigner(signer)
	msg, err := managerSigner.Sign(context.Background(), "topic", DmqMessagePayload{
		MessageBody: []byte("body"),
		ExpiresAt:   uint32(time.Now().Add(time.Minute).Unix()),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.ID()) == 0 {
		t.Fatal("message ID was not computed")
	}
}

func TestKESSigningProviderSignerRejectsMismatchedSignedPeriod(t *testing.T) {
	dir := t.TempDir()
	_, opcertPath := writeSignerFixtures(t, dir, 5)
	cert, err := LoadOperationalCertificate(opcertPath)
	if err != nil {
		t.Fatal(err)
	}
	managerSigner := NewKESSigningProviderSigner(mismatchedPeriodKESProvider{cert: cert})
	_, err = managerSigner.Sign(context.Background(), "topic", DmqMessagePayload{
		MessageBody: []byte("body"),
		ExpiresAt:   uint32(time.Now().Add(time.Minute).Unix()),
	})
	if err == nil || !strings.Contains(err.Error(), "returned relative period 1") {
		t.Fatalf("Sign error=%v, want mismatched KES period error", err)
	}
}

type mismatchedPeriodKESProvider struct {
	cert KESSigningCertificate
}

func (p mismatchedPeriodKESProvider) Sign(payload []byte) (SignedKESPayload, error) {
	return p.SignAt(0, payload)
}

func (p mismatchedPeriodKESProvider) SignAt(period uint64, payload []byte) (SignedKESPayload, error) {
	_ = payload
	return SignedKESPayload{
		VKey:      cloneBytes(p.cert.KESVKey),
		Period:    period + 1,
		Signature: []byte("sig"),
	}, nil
}

func (p mismatchedPeriodKESProvider) CurrentPeriod() (uint64, error) {
	return 0, nil
}

func (p mismatchedPeriodKESProvider) OperationalCertificate() KESSigningCertificate {
	return cloneKESSigningCertificate(p.cert)
}
