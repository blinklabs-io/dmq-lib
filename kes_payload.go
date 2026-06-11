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
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/blinklabs-io/gouroboros/kes"
	"golang.org/x/crypto/blake2b"
)

const defaultExternalKESSignerTimeout = 5 * time.Second

// TextEnvelope is the cardano-cli JSON key/certificate file format.
type TextEnvelope struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	CborHex     string `json:"cborHex"`
}

// KESSigningKey is a KES secret key and its verification key, as loaded from
// a cardano-cli text-envelope file.
type KESSigningKey struct {
	SecretKeyBytes  []byte
	VerificationKey []byte
}

// KESSigningCertificate is the Cardano operational certificate material needed
// to sign arbitrary payloads with an SPO KES key.
type KESSigningCertificate struct {
	KESVKey     []byte
	IssueNumber uint64
	KESPeriod   uint64
	Signature   []byte
	ColdVKey    []byte
}

// SignedKESPayload is the result of signing a payload with a
// KESSigningProvider: the KES verification key, the relative KES period the
// signature was made at, and the signature itself.
type SignedKESPayload struct {
	VKey      []byte
	Period    uint64
	Signature []byte
}

// OperationalCredentialStatus reports the KES validity window of an
// operational certificate at a point in time, as computed by
// NewOperationalCredentialStatus.
type OperationalCredentialStatus struct {
	// KESVKey is the certificate's KES verification key.
	KESVKey []byte

	// OpCertKESPeriod is the certificate's starting absolute KES period.
	OpCertKESPeriod uint64

	// CurrentKESPeriod is the absolute KES period at the evaluation time.
	CurrentKESPeriod uint64

	// RelativeKESPeriod is CurrentKESPeriod minus OpCertKESPeriod.
	RelativeKESPeriod uint64

	// MaxKESEvolutions is the number of KES evolutions the certificate
	// supports.
	MaxKESEvolutions uint64

	// RemainingKESEvolutions is how many evolutions remain before the
	// certificate must be rotated.
	RemainingKESEvolutions uint64

	// ExpiresAt is the wall-clock time at which the certificate's KES
	// validity ends.
	ExpiresAt time.Time
}

// KESSigningProvider signs arbitrary payload bytes at a relative KES period.
// CurrentPeriod and SignAt use periods relative to the operational certificate
// start period.
type KESSigningProvider interface {
	Sign(payload []byte) (SignedKESPayload, error)
	SignAt(period uint64, payload []byte) (SignedKESPayload, error)
	CurrentPeriod() (uint64, error)
	OperationalCertificate() KESSigningCertificate
}

// KESSigningProviderSigner adapts a KESSigningProvider to the package's
// Signer interface so it can sign DMQ messages for Manager.Publish.
type KESSigningProviderSigner struct {
	Provider KESSigningProvider
}

// KESSigner is an in-process KESSigningProvider backed by a KES key and
// operational certificate loaded from cardano-cli text-envelope files. It
// derives the current relative period from the network clock, evolves its
// in-memory KES key forward as periods advance, and is safe for concurrent
// use.
type KESSigner struct {
	mu      sync.Mutex
	network NetworkParams
	kesKey  *kes.SecretKey
	opCert  KESSigningCertificate
	now     func() time.Time
}

// ExternalKESSignerConfig configures an ExternalKESSigner.
type ExternalKESSignerConfig struct {
	// Command is the absolute path of the helper executable invoked for each
	// signature. It receives the relative KES period as its only argument and
	// the payload on stdin, and must print the signature (hex or base64) to
	// stdout.
	Command string

	// OperationalCertificatePath is the path to the operational certificate
	// file in cardano-cli text-envelope format.
	OperationalCertificatePath string

	// Network supplies the timing parameters used to derive KES periods.
	Network NetworkParams

	// Timeout bounds each helper invocation. Zero uses a 5-second default.
	Timeout time.Duration

	// Now overrides the time source. Nil uses the system clock.
	Now func() time.Time

	// EnvPrefix controls the environment variable prefix passed to the helper.
	// The default is DMQ, producing DMQ_KES_VKEY_HEX, DMQ_KES_PERIOD, and
	// DMQ_KES_SIGNER_OP_CERT_PATH.
	EnvPrefix string
}

// ExternalKESSigner is a KESSigningProvider that delegates each signature to
// an external helper process, keeping the KES secret key out of this process.
// The helper's output is verified against the operational certificate's KES
// verification key before being returned.
type ExternalKESSigner struct {
	command    string
	opCertPath string
	timeout    time.Duration
	network    NetworkParams
	opCert     KESSigningCertificate
	now        func() time.Time
	envPrefix  string
}

// ReadTextEnvelope reads a cardano-cli text-envelope file and returns its
// decoded CBOR content and envelope type.
func ReadTextEnvelope(path string) (cborData []byte, kind string, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("read %q: %w", path, err)
	}
	var env TextEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, "", fmt.Errorf("parse text-envelope %q: %w", path, err)
	}
	cborData, err = hex.DecodeString(env.CborHex)
	if err != nil {
		return nil, "", fmt.Errorf("decode cborHex of %q: %w", path, err)
	}
	return cborData, env.Type, nil
}

// LoadKESSigningKey loads a KES signing key from a cardano-cli text-envelope
// file and validates the key sizes.
func LoadKESSigningKey(path string) (KESSigningKey, error) {
	loaded, err := bursa.LoadKeyFromFile(path)
	if err != nil {
		return KESSigningKey{}, fmt.Errorf("load KES signing key: %w", err)
	}
	if len(loaded.SKey) != kes.CardanoKesSecretKeySize {
		return KESSigningKey{}, fmt.Errorf("invalid KES signing key size: expected %d got %d", kes.CardanoKesSecretKeySize, len(loaded.SKey))
	}
	if len(loaded.VKey) != ed25519.PublicKeySize {
		return KESSigningKey{}, fmt.Errorf("invalid KES verification key size: expected %d got %d", ed25519.PublicKeySize, len(loaded.VKey))
	}
	return KESSigningKey{
		SecretKeyBytes:  cloneBytes(loaded.SKey),
		VerificationKey: cloneBytes(loaded.VKey),
	}, nil
}

// LoadOperationalCertificate loads an operational certificate from a
// cardano-cli text-envelope file and verifies its cold-key signature.
func LoadOperationalCertificate(path string) (KESSigningCertificate, error) {
	loaded, err := bursa.LoadKeyFromFile(path)
	if err != nil {
		return KESSigningCertificate{}, fmt.Errorf("load operational certificate: %w", err)
	}
	cert := KESSigningCertificate{
		KESVKey:     cloneBytes(loaded.VKey),
		IssueNumber: loaded.OpCertIssueNumber,
		KESPeriod:   loaded.OpCertKesPeriod,
		Signature:   cloneBytes(loaded.OpCertSignature),
		ColdVKey:    cloneBytes(loaded.OpCertColdVKey),
	}
	if err := ValidateOperationalCertificate(cert); err != nil {
		return KESSigningCertificate{}, err
	}
	return cert, nil
}

// ParseOperationalCertificateCBOR decodes the raw CBOR of an operational
// certificate. Unlike LoadOperationalCertificate it does not verify the
// cold-key signature; call ValidateOperationalCertificate for that.
func ParseOperationalCertificateCBOR(certBytes []byte) (KESSigningCertificate, error) {
	var outer []any
	if _, err := cbor.Decode(certBytes, &outer); err != nil {
		return KESSigningCertificate{}, fmt.Errorf("decode op cert cbor: %w", err)
	}
	if len(outer) != 2 {
		return KESSigningCertificate{}, fmt.Errorf("op cert outer: want 2 elements, got %d", len(outer))
	}
	inner, ok := outer[0].([]any)
	if !ok {
		return KESSigningCertificate{}, errors.New("op cert: first element not an array")
	}
	if len(inner) != 4 {
		return KESSigningCertificate{}, fmt.Errorf("op cert inner: want 4 elements, got %d", len(inner))
	}
	coldVKey, ok := outer[1].([]byte)
	if !ok || len(coldVKey) != ed25519.PublicKeySize {
		return KESSigningCertificate{}, errors.New("op cert: cold_vkey not 32 bytes")
	}
	kesVKey, ok := inner[0].([]byte)
	if !ok || len(kesVKey) != ed25519.PublicKeySize {
		return KESSigningCertificate{}, errors.New("op cert: kes_vkey not 32 bytes")
	}
	issueNumber, err := readCBORUint(inner[1], "issue_number")
	if err != nil {
		return KESSigningCertificate{}, err
	}
	kesPeriod, err := readCBORUint(inner[2], "kes_period")
	if err != nil {
		return KESSigningCertificate{}, err
	}
	sig, ok := inner[3].([]byte)
	if !ok || len(sig) != ed25519.SignatureSize {
		return KESSigningCertificate{}, errors.New("op cert: cold-key signature not 64 bytes")
	}
	return KESSigningCertificate{
		KESVKey:     cloneBytes(kesVKey),
		IssueNumber: issueNumber,
		KESPeriod:   kesPeriod,
		Signature:   cloneBytes(sig),
		ColdVKey:    cloneBytes(coldVKey),
	}, nil
}

func readCBORUint(v any, name string) (uint64, error) {
	switch x := v.(type) {
	case uint64:
		return x, nil
	case int64:
		if x < 0 {
			return 0, fmt.Errorf("op cert: %s negative", name)
		}
		return uint64(x), nil
	default:
		return 0, fmt.Errorf("op cert: %s has unexpected type %T", name, v)
	}
}

// ValidateOperationalCertificate checks the certificate's key and signature
// sizes and verifies the cold-key signature over the certificate body.
func ValidateOperationalCertificate(cert KESSigningCertificate) error {
	if len(cert.KESVKey) != ed25519.PublicKeySize {
		return fmt.Errorf("opcert KES verification key size: got %d, want %d", len(cert.KESVKey), ed25519.PublicKeySize)
	}
	if len(cert.ColdVKey) != ed25519.PublicKeySize {
		return fmt.Errorf("opcert cold verification key size: got %d, want %d", len(cert.ColdVKey), ed25519.PublicKeySize)
	}
	if len(cert.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("opcert cold signature size: got %d, want %d", len(cert.Signature), ed25519.SignatureSize)
	}
	var body [48]byte
	copy(body[:32], cert.KESVKey)
	binary.BigEndian.PutUint64(body[32:40], cert.IssueNumber)
	binary.BigEndian.PutUint64(body[40:48], cert.KESPeriod)
	if !ed25519.Verify(cert.ColdVKey, body[:], cert.Signature) {
		return errors.New("opcert cold signature verification failed")
	}
	return nil
}

// ValidateOperationalCredentials loads a KES signing key and operational
// certificate from files and confirms they belong together, returning
// ErrKESKeyMismatch when they do not.
func ValidateOperationalCredentials(kesKeyPath, opCertPath string) error {
	kesKey, err := LoadKESSigningKey(kesKeyPath)
	if err != nil {
		return err
	}
	cert, err := LoadOperationalCertificate(opCertPath)
	if err != nil {
		return err
	}
	if !bytes.Equal(kesKey.VerificationKey, cert.KESVKey) {
		return ErrKESKeyMismatch
	}
	return nil
}

// KESVerificationKeyFromOpCert loads an operational certificate file and
// returns its KES verification key.
func KESVerificationKeyFromOpCert(path string) ([]byte, error) {
	cert, err := LoadOperationalCertificate(path)
	if err != nil {
		return nil, err
	}
	return cloneBytes(cert.KESVKey), nil
}

// ColdVerificationKeyFromOpCert loads an operational certificate file and
// returns its cold verification key.
func ColdVerificationKeyFromOpCert(path string) ([]byte, error) {
	cert, err := LoadOperationalCertificate(path)
	if err != nil {
		return nil, err
	}
	return cloneBytes(cert.ColdVKey), nil
}

// PoolIDFromColdKey returns the Cardano pool ID for a 32-byte cold
// verification key: lowercase hex of blake2b-224(cold_vkey).
func PoolIDFromColdKey(coldVKey []byte) (string, error) {
	if len(coldVKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("cold_vkey size: got %d, want %d", len(coldVKey), ed25519.PublicKeySize)
	}
	h, err := blake2b.New(28, nil)
	if err != nil {
		return "", fmt.Errorf("blake2b-224: %w", err)
	}
	if _, err := h.Write(coldVKey); err != nil {
		return "", fmt.Errorf("hash cold_vkey: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// NewKESSigner creates an in-process KES signer from key and
// operational-certificate files, using the system clock to derive periods.
func NewKESSigner(kesKeyPath, opCertPath string, params NetworkParams) (*KESSigner, error) {
	return NewKESSignerWithClock(kesKeyPath, opCertPath, params, time.Now)
}

// NewKESSignerWithClock creates an in-process KES signer with an injected
// clock. It loads and cross-checks the KES key and operational certificate,
// returning ErrKESKeyMismatch when they do not belong together.
func NewKESSignerWithClock(kesKeyPath, opCertPath string, params NetworkParams, now func() time.Time) (*KESSigner, error) {
	if now == nil {
		now = time.Now
	}
	if params.Start.IsZero() || params.SlotsPerKESPeriod == 0 {
		return nil, errors.New("network params: start and slotsPerKESPeriod are required")
	}
	kesKey, err := LoadKESSigningKey(kesKeyPath)
	if err != nil {
		return nil, err
	}
	cert, err := LoadOperationalCertificate(opCertPath)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(kesKey.VerificationKey, cert.KESVKey) {
		return nil, ErrKESKeyMismatch
	}
	return &KESSigner{
		network: params,
		kesKey: &kes.SecretKey{
			Depth:  kes.CardanoKesDepth,
			Period: 0,
			Data:   cloneBytes(kesKey.SecretKeyBytes),
		},
		opCert: cert,
		now:    now,
	}, nil
}

// NewOperationalCredentialStatus reports the KES validity window of the
// operational certificate at opCertPath as of the given time. When kesKeyPath
// is non-empty the KES signing key is also loaded and cross-checked against
// the certificate. It returns an error when the certificate is not yet valid
// or its KES evolutions are exhausted.
func NewOperationalCredentialStatus(kesKeyPath, opCertPath string, params NetworkParams, now time.Time) (OperationalCredentialStatus, error) {
	if params.Start.IsZero() || params.SlotsPerKESPeriod == 0 {
		return OperationalCredentialStatus{}, errors.New("network params: start and slotsPerKESPeriod are required")
	}
	cert, err := LoadOperationalCertificate(opCertPath)
	if err != nil {
		return OperationalCredentialStatus{}, err
	}
	if strings.TrimSpace(kesKeyPath) != "" {
		kesKey, err := LoadKESSigningKey(kesKeyPath)
		if err != nil {
			return OperationalCredentialStatus{}, err
		}
		if !bytes.Equal(kesKey.VerificationKey, cert.KESVKey) {
			return OperationalCredentialStatus{}, ErrKESKeyMismatch
		}
	}
	absPeriod, err := CurrentKESPeriodFor(params, now)
	if err != nil {
		return OperationalCredentialStatus{}, err
	}
	if absPeriod < cert.KESPeriod {
		return OperationalCredentialStatus{}, fmt.Errorf("system clock yields KES period %d, before op cert period %d", absPeriod, cert.KESPeriod)
	}
	relPeriod := absPeriod - cert.KESPeriod
	maxPeriod := effectiveMaxKESEvolutions(params, kes.CardanoKesDepth)
	if relPeriod >= maxPeriod {
		return OperationalCredentialStatus{}, fmt.Errorf("KES period %d past op cert validity (max %d) - rotate operational certificate", relPeriod, maxPeriod-1)
	}
	return OperationalCredentialStatus{
		KESVKey:                cloneBytes(cert.KESVKey),
		OpCertKESPeriod:        cert.KESPeriod,
		CurrentKESPeriod:       absPeriod,
		RelativeKESPeriod:      relPeriod,
		MaxKESEvolutions:       maxPeriod,
		RemainingKESEvolutions: maxPeriod - relPeriod,
		ExpiresAt:              KESPeriodStart(params, cert.KESPeriod+maxPeriod),
	}, nil
}

// OperationalCertificate returns a copy of the signer's operational
// certificate.
func (s *KESSigner) OperationalCertificate() KESSigningCertificate {
	if s == nil {
		return KESSigningCertificate{}
	}
	return cloneKESSigningCertificate(s.opCert)
}

// CurrentPeriod returns the current KES period relative to the operational
// certificate's start period, derived from the configured clock and network
// parameters.
func (s *KESSigner) CurrentPeriod() (uint64, error) {
	if s == nil {
		return 0, ErrSignerRequired
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return currentRelativePeriodFor(s.network, s.opCert, s.now())
}

// Sign signs the payload at the current relative KES period.
func (s *KESSigner) Sign(payload []byte) (SignedKESPayload, error) {
	if s == nil {
		return SignedKESPayload{}, ErrSignerRequired
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	relPeriod, err := currentRelativePeriodFor(s.network, s.opCert, s.now())
	if err != nil {
		return SignedKESPayload{}, err
	}
	return s.signAtLocked(relPeriod, payload)
}

// SignAt signs the payload at the given relative KES period, evolving the
// in-memory KES key forward as needed. Signing at a period earlier than one
// already used fails, because KES keys cannot evolve backward.
func (s *KESSigner) SignAt(period uint64, payload []byte) (SignedKESPayload, error) {
	if s == nil {
		return SignedKESPayload{}, ErrSignerRequired
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.signAtLocked(period, payload)
}

func (s *KESSigner) signAtLocked(relPeriod uint64, payload []byte) (SignedKESPayload, error) {
	if err := validateRelativeKESPeriodForNetwork(relPeriod, s.network); err != nil {
		return SignedKESPayload{}, err
	}
	if err := s.advanceTo(relPeriod); err != nil {
		return SignedKESPayload{}, err
	}
	signature, err := kes.Sign(s.kesKey, relPeriod, payload)
	if err != nil {
		return SignedKESPayload{}, fmt.Errorf("KES sign: %w", err)
	}
	return SignedKESPayload{
		VKey:      cloneBytes(s.opCert.KESVKey),
		Period:    relPeriod,
		Signature: cloneBytes(signature),
	}, nil
}

func (s *KESSigner) advanceTo(period uint64) error {
	if period < s.kesKey.Period {
		return fmt.Errorf("KES key already at period %d, cannot sign at earlier period %d", s.kesKey.Period, period)
	}
	for s.kesKey.Period < period {
		next, err := kes.Update(s.kesKey)
		if err != nil {
			return fmt.Errorf("advance KES key from period %d: %w", s.kesKey.Period, err)
		}
		s.kesKey = next
	}
	return nil
}

// NewExternalKESSigner creates an external-process KES signer using the
// system clock to derive periods.
func NewExternalKESSigner(command, opCertPath string, params NetworkParams, timeout time.Duration) (*ExternalKESSigner, error) {
	return NewExternalKESSignerWithClock(command, opCertPath, params, timeout, time.Now)
}

// NewExternalKESSignerWithClock creates an external-process KES signer with
// an injected clock.
func NewExternalKESSignerWithClock(command, opCertPath string, params NetworkParams, timeout time.Duration, now func() time.Time) (*ExternalKESSigner, error) {
	return NewExternalKESSignerFromConfig(ExternalKESSignerConfig{
		Command:                    command,
		OperationalCertificatePath: opCertPath,
		Network:                    params,
		Timeout:                    timeout,
		Now:                        now,
	})
}

// NewExternalKESSignerFromConfig creates an external-process KES signer from
// config. It validates the helper command path, loads and verifies the
// operational certificate, and applies defaults for timeout, clock, and
// environment prefix.
func NewExternalKESSignerFromConfig(cfg ExternalKESSignerConfig) (*ExternalKESSigner, error) {
	command := strings.TrimSpace(cfg.Command)
	if command == "" {
		return nil, errors.New("KES signer command is required")
	}
	if strings.ContainsAny(command, "\x00\r\n") {
		return nil, errors.New("KES signer command contains invalid characters")
	}
	if !filepath.IsAbs(command) {
		return nil, errors.New("KES signer command must be an absolute path")
	}
	if cfg.Network.Start.IsZero() || cfg.Network.SlotsPerKESPeriod == 0 {
		return nil, errors.New("network params: start and slotsPerKESPeriod are required")
	}
	cert, err := LoadOperationalCertificate(cfg.OperationalCertificatePath)
	if err != nil {
		return nil, err
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultExternalKESSignerTimeout
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	envPrefix := strings.TrimSpace(cfg.EnvPrefix)
	if envPrefix == "" {
		envPrefix = "DMQ"
	}
	if !validEnvPrefix(envPrefix) {
		return nil, errors.New("external KES signer env prefix must contain only uppercase letters, digits, or underscores")
	}
	return &ExternalKESSigner{
		command:    command,
		opCertPath: cfg.OperationalCertificatePath,
		timeout:    timeout,
		network:    cfg.Network,
		opCert:     cert,
		now:        now,
		envPrefix:  envPrefix,
	}, nil
}

func validEnvPrefix(prefix string) bool {
	for _, r := range prefix {
		if r >= 'A' && r <= 'Z' {
			continue
		}
		if r >= '0' && r <= '9' {
			continue
		}
		if r == '_' {
			continue
		}
		return false
	}
	return true
}

// OperationalCertificate returns a copy of the signer's operational
// certificate.
func (s *ExternalKESSigner) OperationalCertificate() KESSigningCertificate {
	if s == nil {
		return KESSigningCertificate{}
	}
	return cloneKESSigningCertificate(s.opCert)
}

// CurrentPeriod returns the current KES period relative to the operational
// certificate's start period, derived from the configured clock and network
// parameters.
func (s *ExternalKESSigner) CurrentPeriod() (uint64, error) {
	if s == nil {
		return 0, ErrSignerRequired
	}
	return currentRelativePeriodFor(s.network, s.opCert, s.now())
}

// Sign signs the payload at the current relative KES period.
func (s *ExternalKESSigner) Sign(payload []byte) (SignedKESPayload, error) {
	if s == nil {
		return SignedKESPayload{}, ErrSignerRequired
	}
	period, err := s.CurrentPeriod()
	if err != nil {
		return SignedKESPayload{}, err
	}
	return s.SignAt(period, payload)
}

// SignAt invokes the helper command to sign the payload at the given relative
// KES period and verifies the returned signature before accepting it. The
// helper receives the period as its argument, the payload on stdin, and the
// EnvPrefix-derived environment variables.
func (s *ExternalKESSigner) SignAt(period uint64, payload []byte) (SignedKESPayload, error) {
	if s == nil {
		return SignedKESPayload{}, ErrSignerRequired
	}
	if err := validateRelativeKESPeriodForNetwork(period, s.network); err != nil {
		return SignedKESPayload{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, s.command, strconv.FormatUint(period, 10)) //nolint:gosec // Operator-configured external signer command is the custody boundary; no shell is used.
	cmd.Stdin = bytes.NewReader(payload)
	cmd.Env = append(os.Environ(),
		s.envPrefix+"_KES_VKEY_HEX="+hex.EncodeToString(s.opCert.KESVKey),
		s.envPrefix+"_KES_PERIOD="+strconv.FormatUint(period, 10),
		s.envPrefix+"_KES_SIGNER_OP_CERT_PATH="+s.opCertPath,
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return SignedKESPayload{}, fmt.Errorf("external KES signer timed out after %s", s.timeout)
		}
		errText := strings.TrimSpace(stderr.String())
		if errText != "" {
			return SignedKESPayload{}, fmt.Errorf("external KES signer: %w: %s", err, errText)
		}
		return SignedKESPayload{}, fmt.Errorf("external KES signer: %w", err)
	}
	signature, err := ParseExternalKESSignature(stdout.Bytes())
	if err != nil {
		return SignedKESPayload{}, err
	}
	if !VerifyKESSignature(s.opCert.KESVKey, period, payload, signature) {
		return SignedKESPayload{}, errors.New("external KES signer returned an invalid signature")
	}
	return SignedKESPayload{
		VKey:      cloneBytes(s.opCert.KESVKey),
		Period:    period,
		Signature: signature,
	}, nil
}

func currentRelativePeriodFor(network NetworkParams, cert KESSigningCertificate, now time.Time) (uint64, error) {
	absPeriod, err := CurrentKESPeriodFor(network, now)
	if err != nil {
		return 0, err
	}
	if absPeriod < cert.KESPeriod {
		return 0, fmt.Errorf("system clock yields KES period %d, before op cert period %d", absPeriod, cert.KESPeriod)
	}
	relPeriod := absPeriod - cert.KESPeriod
	if err := validateRelativeKESPeriodForNetwork(relPeriod, network); err != nil {
		return 0, err
	}
	return relPeriod, nil
}

func validateRelativeKESPeriodForNetwork(period uint64, network NetworkParams) error {
	maxPeriod := effectiveMaxKESEvolutions(network, kes.CardanoKesDepth)
	if period >= maxPeriod {
		return fmt.Errorf("KES period %d past op cert validity (max %d) - rotate operational certificate", period, maxPeriod-1)
	}
	return nil
}

func cryptoMaxKESEvolutions(depth uint64) uint64 {
	if depth >= 63 {
		return 1 << 63
	}
	return uint64(1) << depth
}

func effectiveMaxKESEvolutions(network NetworkParams, depth uint64) uint64 {
	cryptoMax := cryptoMaxKESEvolutions(depth)
	if network.MaxKESEvolutions == 0 || network.MaxKESEvolutions > cryptoMax {
		return cryptoMax
	}
	return network.MaxKESEvolutions
}

// ParseExternalKESSignature decodes an external KES signer's stdout, which
// must be a non-empty hex- or base64-encoded signature.
func ParseExternalKESSignature(raw []byte) ([]byte, error) {
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return nil, errors.New("external KES signer returned empty signature")
	}
	if sig, err := hex.DecodeString(text); err == nil {
		if len(sig) == 0 {
			return nil, errors.New("external KES signer returned empty hex signature")
		}
		return sig, nil
	}
	sig, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return nil, fmt.Errorf("external KES signer signature must be hex or base64: %w", err)
	}
	if len(sig) == 0 {
		return nil, errors.New("external KES signer returned empty base64 signature")
	}
	return sig, nil
}

// VerifyKESSignature reports whether signature is a valid KES signature over
// payload under vkey at the given relative KES period.
func VerifyKESSignature(vkey []byte, period uint64, payload, signature []byte) bool {
	return kes.VerifySignedKES(vkey, period, payload, signature)
}

// NewKESSigningProviderSigner wraps a KESSigningProvider as a Signer.
func NewKESSigningProviderSigner(provider KESSigningProvider) KESSigningProviderSigner {
	return KESSigningProviderSigner{Provider: provider}
}

// BuildSignedMessage signs a message body with the provider and returns a
// complete DMQ message with the given wire-format expiration. Use ExpiresAt
// to derive expiresAt from a TTL.
func BuildSignedMessage(ctx context.Context, provider KESSigningProvider, topic string, body []byte, expiresAt uint32) (*DmqMessage, error) {
	payload := DmqMessagePayload{
		MessageBody: cloneBytes(body),
		ExpiresAt:   expiresAt,
	}
	return NewKESSigningProviderSigner(provider).Sign(ctx, topic, payload)
}

// Sign implements Signer. It stamps the payload with the provider's current
// absolute KES period, signs the CIP-0137 signing bytes, cross-checks the
// returned key and period against the provider's operational certificate, and
// attaches the certificate and computed message ID. The payload must carry a
// non-zero ExpiresAt.
func (s KESSigningProviderSigner) Sign(ctx context.Context, topic string, payload DmqMessagePayload) (*DmqMessage, error) {
	_ = ctx
	_ = topic
	provider := s.Provider
	if snapshotter, ok := provider.(interface{ ActiveProvider() KESSigningProvider }); ok {
		provider = snapshotter.ActiveProvider()
	}
	if provider == nil || isNilInterface(provider) {
		return nil, ErrSignerRequired
	}
	if payload.ExpiresAt == 0 {
		return nil, errors.New("dmq payload expiration is required")
	}
	relPeriod, err := provider.CurrentPeriod()
	if err != nil {
		return nil, err
	}
	cert := provider.OperationalCertificate()
	if relPeriod > math.MaxUint64-cert.KESPeriod {
		return nil, fmt.Errorf("KES period overflow: op cert period %d plus relative period %d", cert.KESPeriod, relPeriod)
	}
	payload.MessageID = nil
	payload.KESPeriod = cert.KESPeriod + relPeriod

	signingBytes, err := PayloadSigningBytes(payload)
	if err != nil {
		return nil, err
	}
	signed, err := provider.SignAt(relPeriod, signingBytes)
	if err != nil {
		return nil, fmt.Errorf("KES sign: %w", err)
	}
	if !bytes.Equal(signed.VKey, cert.KESVKey) {
		return nil, ErrKESKeyMismatch
	}
	if signed.Period != relPeriod {
		return nil, fmt.Errorf("KES signer returned relative period %d for requested relative period %d", signed.Period, relPeriod)
	}
	msg := &DmqMessage{
		Payload:      payload,
		KESSignature: cloneBytes(signed.Signature),
		OperationalCertificate: OperationalCertificate{
			KESVerificationKey: cloneBytes(cert.KESVKey),
			IssueNumber:        cert.IssueNumber,
			KESPeriod:          cert.KESPeriod,
			ColdSignature:      cloneBytes(cert.Signature),
		},
		ColdVerificationKey: cloneBytes(cert.ColdVKey),
	}
	if err := msg.SetComputedMessageID(); err != nil {
		return nil, fmt.Errorf("compute dmq message id: %w", err)
	}
	return msg, nil
}

func cloneKESSigningCertificate(src KESSigningCertificate) KESSigningCertificate {
	return KESSigningCertificate{
		KESVKey:     cloneBytes(src.KESVKey),
		IssueNumber: src.IssueNumber,
		KESPeriod:   src.KESPeriod,
		Signature:   cloneBytes(src.Signature),
		ColdVKey:    cloneBytes(src.ColdVKey),
	}
}
