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
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestReloadingFileSignerReloadsCredentialFiles(t *testing.T) {
	dir := t.TempDir()
	kesPath, opcertPath := writeSignerFixturesWithSeed(t, dir, 5, 0x42)
	currentPeriod := uint64(5)
	signer, err := NewReloadingFileSigner(FileSignerConfig{
		KESSigningKeyPath:          kesPath,
		OperationalCertificatePath: opcertPath,
		KESPeriodFunc: func(context.Context) (uint64, error) {
			return currentPeriod, nil
		},
	})
	if err != nil {
		t.Fatalf("NewReloadingFileSigner: %v", err)
	}

	first, err := signer.Sign(context.Background(), "topic", reloadTestPayload("before"))
	if err != nil {
		t.Fatalf("Sign before reload: %v", err)
	}
	verifyDmqMessageKESSignature(t, first)
	firstVKey := cloneBytes(first.OperationalCertificate.KESVerificationKey)

	writeSignerFixturesWithSeed(t, dir, 10, 0x43)
	currentPeriod = 10
	if err := signer.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	second, err := signer.Sign(context.Background(), "topic", reloadTestPayload("after"))
	if err != nil {
		t.Fatalf("Sign after reload: %v", err)
	}
	verifyDmqMessageKESSignature(t, second)
	if second.Payload.KESPeriod != 10 {
		t.Fatalf("payload KES period=%d, want 10", second.Payload.KESPeriod)
	}
	if second.OperationalCertificate.KESPeriod != 10 {
		t.Fatalf("op cert KES period=%d, want 10", second.OperationalCertificate.KESPeriod)
	}
	if bytes.Equal(firstVKey, second.OperationalCertificate.KESVerificationKey) {
		t.Fatal("reload did not switch to the replacement KES verification key")
	}
}

func TestReloadingKESSigningProviderReloadsCredentialFiles(t *testing.T) {
	dir := t.TempDir()
	kesPath, opcertPath := writeSignerFixturesWithSeed(t, dir, 5, 0x42)
	params := reloadTestNetworkParams()
	now := params.Start.Add(55 * time.Second)
	provider, err := NewReloadingKESSignerWithClock(kesPath, opcertPath, params, func() time.Time {
		return now
	})
	if err != nil {
		t.Fatalf("NewReloadingKESSignerWithClock: %v", err)
	}
	signer := NewKESSigningProviderSigner(provider)

	first, err := signer.Sign(context.Background(), "topic", reloadTestPayload("before"))
	if err != nil {
		t.Fatalf("Sign before reload: %v", err)
	}
	verifyDmqMessageKESSignature(t, first)
	firstVKey := cloneBytes(first.OperationalCertificate.KESVerificationKey)

	writeSignerFixturesWithSeed(t, dir, 10, 0x43)
	now = params.Start.Add(105 * time.Second)
	if err := provider.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	second, err := signer.Sign(context.Background(), "topic", reloadTestPayload("after"))
	if err != nil {
		t.Fatalf("Sign after reload: %v", err)
	}
	verifyDmqMessageKESSignature(t, second)
	if second.Payload.KESPeriod != 10 {
		t.Fatalf("payload KES period=%d, want 10", second.Payload.KESPeriod)
	}
	if second.OperationalCertificate.KESPeriod != 10 {
		t.Fatalf("op cert KES period=%d, want 10", second.OperationalCertificate.KESPeriod)
	}
	if bytes.Equal(firstVKey, second.OperationalCertificate.KESVerificationKey) {
		t.Fatal("reload did not switch to the replacement KES verification key")
	}
}

func TestReloadingKESSigningProviderFailedReloadKeepsActiveProvider(t *testing.T) {
	dir := t.TempDir()
	kesPath, opcertPath := writeSignerFixturesWithSeed(t, dir, 5, 0x42)
	params := reloadTestNetworkParams()
	provider, err := NewReloadingKESSignerWithClock(kesPath, opcertPath, params, func() time.Time {
		return params.Start.Add(55 * time.Second)
	})
	if err != nil {
		t.Fatalf("NewReloadingKESSignerWithClock: %v", err)
	}
	certBefore := provider.OperationalCertificate()

	writeKESKeyFixture(t, kesPath, 0x43)
	if err := provider.Reload(); !errors.Is(err, ErrKESKeyMismatch) {
		t.Fatalf("Reload error=%v, want %v", err, ErrKESKeyMismatch)
	}

	certAfter := provider.OperationalCertificate()
	if !bytes.Equal(certBefore.KESVKey, certAfter.KESVKey) {
		t.Fatal("failed reload replaced the active provider")
	}
	signed, err := provider.Sign([]byte("payload"))
	if err != nil {
		t.Fatalf("Sign after failed reload: %v", err)
	}
	if !bytes.Equal(signed.VKey, certBefore.KESVKey) {
		t.Fatal("sign after failed reload used replacement key material")
	}
}

func TestReloadingSignerRejectsTypedNilFactoryResult(t *testing.T) {
	good := &reloadTestSigner{}
	var nilSigner *reloadTypedNilSigner
	calls := 0
	signer, err := NewReloadingSigner(func() (Signer, error) {
		calls++
		if calls == 1 {
			return good, nil
		}
		return nilSigner, nil
	})
	if err != nil {
		t.Fatalf("NewReloadingSigner: %v", err)
	}

	err = signer.Reload()
	if err == nil || !strings.Contains(err.Error(), "nil signer") {
		t.Fatalf("Reload error=%v, want nil signer error", err)
	}
	if got := signer.ActiveSigner(); got != good {
		t.Fatal("typed-nil reload replaced the active signer")
	}
	if _, err := signer.Sign(context.Background(), "topic", reloadTestPayload("after")); err != nil {
		t.Fatalf("Sign after rejected reload: %v", err)
	}
}

func TestNewReloadingSignerRejectsTypedNilFactoryResult(t *testing.T) {
	var nilSigner *reloadTypedNilSigner
	_, err := NewReloadingSigner(func() (Signer, error) {
		return nilSigner, nil
	})
	if err == nil || !strings.Contains(err.Error(), "nil signer") {
		t.Fatalf("NewReloadingSigner error=%v, want nil signer error", err)
	}
}

func TestReloadingKESSigningProviderRejectsTypedNilFactoryResult(t *testing.T) {
	good := &reloadTestKESProvider{
		signed: SignedKESPayload{
			VKey:      []byte("good"),
			Signature: []byte("signature"),
		},
	}
	var nilProvider *reloadTypedNilKESProvider
	calls := 0
	provider, err := NewReloadingKESSigningProvider(func() (KESSigningProvider, error) {
		calls++
		if calls == 1 {
			return good, nil
		}
		return nilProvider, nil
	})
	if err != nil {
		t.Fatalf("NewReloadingKESSigningProvider: %v", err)
	}

	err = provider.Reload()
	if err == nil || !strings.Contains(err.Error(), "nil provider") {
		t.Fatalf("Reload error=%v, want nil provider error", err)
	}
	if got := provider.ActiveProvider(); got != good {
		t.Fatal("typed-nil reload replaced the active provider")
	}
	signed, err := provider.Sign([]byte("payload"))
	if err != nil {
		t.Fatalf("Sign after rejected reload: %v", err)
	}
	if !bytes.Equal(signed.VKey, good.signed.VKey) {
		t.Fatal("sign after rejected reload used replacement provider")
	}
}

func TestNewReloadingKESSigningProviderRejectsTypedNilFactoryResult(t *testing.T) {
	var nilProvider *reloadTypedNilKESProvider
	_, err := NewReloadingKESSigningProvider(func() (KESSigningProvider, error) {
		return nilProvider, nil
	})
	if err == nil || !strings.Contains(err.Error(), "nil provider") {
		t.Fatalf("NewReloadingKESSigningProvider error=%v, want nil provider error", err)
	}
}

func TestKESSigningProviderSignerRejectsTypedNilActiveProviderSnapshot(t *testing.T) {
	var nilProvider *reloadTypedNilKESProvider
	signer := NewKESSigningProviderSigner(reloadTypedNilSnapshotter{provider: nilProvider})

	_, err := signer.Sign(context.Background(), "topic", reloadTestPayload("snapshot"))
	if !errors.Is(err, ErrSignerRequired) {
		t.Fatalf("Sign error=%v, want %v", err, ErrSignerRequired)
	}
}

type reloadTypedNilSnapshotter struct {
	provider KESSigningProvider
}

func (s reloadTypedNilSnapshotter) Sign(payload []byte) (SignedKESPayload, error) {
	return s.provider.Sign(payload)
}

func (s reloadTypedNilSnapshotter) SignAt(period uint64, payload []byte) (SignedKESPayload, error) {
	return s.provider.SignAt(period, payload)
}

func (s reloadTypedNilSnapshotter) CurrentPeriod() (uint64, error) {
	return s.provider.CurrentPeriod()
}

func (s reloadTypedNilSnapshotter) OperationalCertificate() KESSigningCertificate {
	return s.provider.OperationalCertificate()
}

func (s reloadTypedNilSnapshotter) ActiveProvider() KESSigningProvider {
	return s.provider
}

type reloadTestSigner struct{}

func (s *reloadTestSigner) Sign(ctx context.Context, topic string, payload DmqMessagePayload) (*DmqMessage, error) {
	if s == nil {
		panic("typed-nil signer used")
	}
	_ = ctx
	_ = topic
	return &DmqMessage{Payload: payload}, nil
}

type reloadTypedNilSigner struct{}

func (s *reloadTypedNilSigner) Sign(ctx context.Context, topic string, payload DmqMessagePayload) (*DmqMessage, error) {
	if s == nil {
		panic("typed-nil signer used")
	}
	_ = ctx
	_ = topic
	return &DmqMessage{Payload: payload}, nil
}

type reloadTestKESProvider struct {
	signed SignedKESPayload
}

func (p *reloadTestKESProvider) Sign(payload []byte) (SignedKESPayload, error) {
	if p == nil {
		panic("typed-nil KES provider used")
	}
	_ = payload
	return p.signed, nil
}

func (p *reloadTestKESProvider) SignAt(period uint64, payload []byte) (SignedKESPayload, error) {
	if p == nil {
		panic("typed-nil KES provider used")
	}
	_ = payload
	signed := p.signed
	signed.Period = period
	return signed, nil
}

func (p *reloadTestKESProvider) CurrentPeriod() (uint64, error) {
	if p == nil {
		panic("typed-nil KES provider used")
	}
	return p.signed.Period, nil
}

func (p *reloadTestKESProvider) OperationalCertificate() KESSigningCertificate {
	if p == nil {
		panic("typed-nil KES provider used")
	}
	return KESSigningCertificate{KESVKey: cloneBytes(p.signed.VKey)}
}

type reloadTypedNilKESProvider struct{}

func (p *reloadTypedNilKESProvider) Sign(payload []byte) (SignedKESPayload, error) {
	if p == nil {
		panic("typed-nil KES provider used")
	}
	_ = payload
	return SignedKESPayload{}, nil
}

func (p *reloadTypedNilKESProvider) SignAt(period uint64, payload []byte) (SignedKESPayload, error) {
	if p == nil {
		panic("typed-nil KES provider used")
	}
	_ = period
	_ = payload
	return SignedKESPayload{}, nil
}

func (p *reloadTypedNilKESProvider) CurrentPeriod() (uint64, error) {
	if p == nil {
		panic("typed-nil KES provider used")
	}
	return 0, nil
}

func (p *reloadTypedNilKESProvider) OperationalCertificate() KESSigningCertificate {
	if p == nil {
		panic("typed-nil KES provider used")
	}
	return KESSigningCertificate{}
}

func reloadTestPayload(body string) DmqMessagePayload {
	return DmqMessagePayload{
		MessageBody: []byte(body),
		ExpiresAt:   uint32(time.Now().Add(time.Minute).Unix()),
	}
}

func reloadTestNetworkParams() NetworkParams {
	return NetworkParams{
		Start:             time.Unix(0, 0).UTC(),
		SlotLength:        time.Second,
		EpochLength:       100,
		SlotsPerKESPeriod: 10,
		MaxKESEvolutions:  60,
	}
}

func verifyDmqMessageKESSignature(t *testing.T, msg *DmqMessage) {
	t.Helper()
	signingBytes, err := PayloadSigningBytes(msg.Payload)
	if err != nil {
		t.Fatal(err)
	}
	relPeriod, err := relativeKESPeriod(msg.Payload.KESPeriod, msg.OperationalCertificate.KESPeriod)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyKESSignature(msg.OperationalCertificate.KESVerificationKey, relPeriod, signingBytes, msg.KESSignature) {
		t.Fatal("KES signature did not verify")
	}
}
