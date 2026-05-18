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
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/blinklabs-io/gouroboros/kes"
	pcommon "github.com/blinklabs-io/gouroboros/protocol/common"
)

type FileSignerConfig struct {
	KESSigningKeyPath          string
	OperationalCertificatePath string

	// KESPeriod is used when KESPeriodFunc is nil and Publish did not set a
	// period on the payload. It is the absolute chain KES period.
	KESPeriod uint64

	KESPeriodFunc func(context.Context) (uint64, error)
}

type FileSigner struct {
	mu sync.Mutex

	kesSKey  *kes.SecretKey
	kesVKey  []byte
	opCert   OperationalCertificate
	coldVKey []byte

	defaultKESPeriod uint64
	kesPeriodFunc    func(context.Context) (uint64, error)
}

func NewFileSigner(cfg FileSignerConfig) (*FileSigner, error) {
	if cfg.KESSigningKeyPath == "" {
		return nil, errors.New("KES signing key path is required")
	}
	if cfg.OperationalCertificatePath == "" {
		return nil, errors.New("operational certificate path is required")
	}
	kesKey, err := bursa.LoadKeyFromFile(cfg.KESSigningKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load KES signing key: %w", err)
	}
	if len(kesKey.SKey) != kes.CardanoKesSecretKeySize {
		return nil, fmt.Errorf("invalid KES signing key size: expected %d got %d", kes.CardanoKesSecretKeySize, len(kesKey.SKey))
	}
	opCertKey, err := bursa.LoadKeyFromFile(cfg.OperationalCertificatePath)
	if err != nil {
		return nil, fmt.Errorf("load operational certificate: %w", err)
	}
	if len(opCertKey.VKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid opcert KES verification key size: expected %d got %d", ed25519.PublicKeySize, len(opCertKey.VKey))
	}
	if len(opCertKey.OpCertColdVKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid opcert cold verification key size: expected %d got %d", ed25519.PublicKeySize, len(opCertKey.OpCertColdVKey))
	}
	if len(opCertKey.OpCertSignature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid opcert cold signature size: expected %d got %d", ed25519.SignatureSize, len(opCertKey.OpCertSignature))
	}
	if !bytes.Equal(kesKey.VKey, opCertKey.VKey) {
		return nil, errors.New("opcert KES verification key does not match KES signing key")
	}
	s := &FileSigner{
		kesSKey: &kes.SecretKey{
			Depth:  kes.CardanoKesDepth,
			Period: 0,
			Data:   cloneBytes(kesKey.SKey),
		},
		kesVKey: cloneBytes(kesKey.VKey),
		opCert: OperationalCertificate{
			KESVerificationKey: cloneBytes(opCertKey.VKey),
			IssueNumber:        opCertKey.OpCertIssueNumber,
			KESPeriod:          opCertKey.OpCertKesPeriod,
			ColdSignature:      cloneBytes(opCertKey.OpCertSignature),
		},
		coldVKey:         cloneBytes(opCertKey.OpCertColdVKey),
		defaultKESPeriod: cfg.KESPeriod,
		kesPeriodFunc:    cfg.KESPeriodFunc,
	}
	if s.defaultKESPeriod == 0 {
		s.defaultKESPeriod = s.opCert.KESPeriod
	}
	if err := s.ValidateOperationalCertificate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *FileSigner) Sign(ctx context.Context, topic string, payload DmqMessagePayload) (*DmqMessage, error) {
	_ = topic
	period, err := s.currentKESPeriod(ctx, payload)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	payload.MessageID = nil
	payload.KESPeriod = period
	if payload.ExpiresAt == 0 {
		return nil, errors.New("payload expiration is required")
	}

	relativePeriod, err := s.relativeKESPeriod(period)
	if err != nil {
		return nil, err
	}
	if err := s.evolveToRelativePeriod(relativePeriod); err != nil {
		return nil, err
	}
	wrappedPayload, err := wrappedPayloadCBOR(payload)
	if err != nil {
		return nil, err
	}
	sig, err := kes.Sign(s.kesSKey, relativePeriod, wrappedPayload)
	if err != nil {
		return nil, fmt.Errorf("KES sign: %w", err)
	}
	msg := &DmqMessage{
		Payload:                payload,
		KESSignature:           sig,
		OperationalCertificate: cloneOperationalCertificate(s.opCert),
		ColdVerificationKey:    cloneBytes(s.coldVKey),
	}
	if err := msg.SetComputedMessageID(); err != nil {
		return nil, err
	}
	return msg, nil
}

func (s *FileSigner) ValidateOperationalCertificate() error {
	if len(s.opCert.KESVerificationKey) != ed25519.PublicKeySize {
		return errors.New("opcert KES verification key must be 32 bytes")
	}
	if len(s.coldVKey) != ed25519.PublicKeySize {
		return errors.New("opcert cold verification key must be 32 bytes")
	}
	if len(s.opCert.ColdSignature) != ed25519.SignatureSize {
		return errors.New("opcert cold signature must be 64 bytes")
	}
	var body [48]byte
	copy(body[:32], s.opCert.KESVerificationKey)
	binary.BigEndian.PutUint64(body[32:40], s.opCert.IssueNumber)
	binary.BigEndian.PutUint64(body[40:48], s.opCert.KESPeriod)
	if !ed25519.Verify(s.coldVKey, body[:], s.opCert.ColdSignature) {
		return errors.New("opcert cold signature verification failed")
	}
	return nil
}

func (s *FileSigner) KESVerificationKey() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneBytes(s.kesVKey)
}

func (s *FileSigner) OperationalCertificate() OperationalCertificate {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneOperationalCertificate(s.opCert)
}

func (s *FileSigner) ColdVerificationKey() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneBytes(s.coldVKey)
}

// Verify checks only that msg.KESSignature is a valid KES signature over the
// payload under the KES verification key embedded in msg.OperationalCertificate.
// It does NOT establish identity: it does not validate the operational
// certificate's cold-key signature, does not confirm msg.ColdVerificationKey
// belongs to a registered SPO, does not check that the embedded KES key matches
// this signer's own key, and does not verify the deterministic message ID.
// Because every input to the verification comes from the message itself, a
// caller who treats a true return as proof of authenticity will accept messages
// from any party that can produce a self-consistent CBOR. For incoming-message
// authentication use the pcommon.MessageAuthenticator path wired through
// Manager with TopicConfig.Authentication.Required set.
func (s *FileSigner) Verify(msg *DmqMessage) (bool, error) {
	if msg == nil {
		return false, errors.New("message is nil")
	}
	wrappedPayload, err := wrappedPayloadCBOR(msg.Payload)
	if err != nil {
		return false, err
	}
	relativePeriod, err := relativeKESPeriod(msg.Payload.KESPeriod, msg.OperationalCertificate.KESPeriod)
	if err != nil {
		return false, err
	}
	return kes.VerifySignedKES(msg.OperationalCertificate.KESVerificationKey, relativePeriod, wrappedPayload, msg.KESSignature), nil
}

func (s *FileSigner) currentKESPeriod(ctx context.Context, payload DmqMessagePayload) (uint64, error) {
	if payload.KESPeriod != 0 {
		return payload.KESPeriod, nil
	}
	if s.kesPeriodFunc != nil {
		return s.kesPeriodFunc(ctx)
	}
	return s.defaultKESPeriod, nil
}

func (s *FileSigner) relativeKESPeriod(period uint64) (uint64, error) {
	return relativeKESPeriod(period, s.opCert.KESPeriod)
}

func relativeKESPeriod(period, opCertStart uint64) (uint64, error) {
	if period < opCertStart {
		return 0, fmt.Errorf("KES period %d is before opcert start period %d", period, opCertStart)
	}
	return period - opCertStart, nil
}

func (s *FileSigner) evolveToRelativePeriod(period uint64) error {
	if s.kesSKey.Period > period {
		return fmt.Errorf("cannot evolve KES key backward: current period %d, requested %d", s.kesSKey.Period, period)
	}
	key := s.kesSKey
	for key.Period < period {
		next, err := kes.Update(key)
		if err != nil {
			return fmt.Errorf("update KES key to period %d: %w", period, err)
		}
		key = next
	}
	s.kesSKey = key
	return nil
}

func wrappedPayloadCBOR(payload DmqMessagePayload) ([]byte, error) {
	payload.MessageID = nil
	payloadCBOR, err := cbor.Encode(payload)
	if err != nil {
		return nil, fmt.Errorf("encode DMQ payload: %w", err)
	}
	wrapped, err := cbor.Encode(payloadCBOR)
	if err != nil {
		return nil, fmt.Errorf("wrap DMQ payload: %w", err)
	}
	return wrapped, nil
}

func ComputeMessageID(payload DmqMessagePayload) ([]byte, error) {
	return pcommon.ComputeDmqMessageID(payload)
}

func cloneOperationalCertificate(src OperationalCertificate) OperationalCertificate {
	return OperationalCertificate{
		KESVerificationKey: cloneBytes(src.KESVerificationKey),
		IssueNumber:        src.IssueNumber,
		KESPeriod:          src.KESPeriod,
		ColdSignature:      cloneBytes(src.ColdSignature),
	}
}
