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
	"reflect"
	"sync"
	"time"
)

// ReloadingSignerFactory constructs a complete replacement Signer.
type ReloadingSignerFactory func() (Signer, error)

// ReloadingSigner delegates signing to the currently active Signer and swaps in
// a freshly constructed replacement when Reload succeeds.
type ReloadingSigner struct {
	mu      sync.RWMutex
	factory ReloadingSignerFactory
	signer  Signer
}

// NewReloadingSigner creates a reloadable Signer from a caller-provided factory.
func NewReloadingSigner(factory ReloadingSignerFactory) (*ReloadingSigner, error) {
	s := &ReloadingSigner{
		factory: factory,
	}
	if err := s.Reload(); err != nil {
		return nil, err
	}
	return s, nil
}

// NewReloadingFileSigner creates a reloadable Signer backed by FileSigner
// credentials.
func NewReloadingFileSigner(cfg FileSignerConfig) (*ReloadingSigner, error) {
	return NewReloadingSigner(func() (Signer, error) {
		return NewFileSigner(cfg)
	})
}

// Sign implements Signer by delegating to the currently active signer.
func (s *ReloadingSigner) Sign(ctx context.Context, topic string, payload DmqMessagePayload) (*DmqMessage, error) {
	signer := s.ActiveSigner()
	if signer == nil || isNilInterface(signer) {
		return nil, ErrSignerRequired
	}
	return signer.Sign(ctx, topic, payload)
}

// Reload constructs and validates a replacement signer, then swaps it in. The
// active signer is left unchanged when construction fails.
func (s *ReloadingSigner) Reload() error {
	if s == nil {
		return ErrSignerRequired
	}
	if s.factory == nil {
		return errors.New("dmq reloading signer factory is required")
	}
	next, err := s.factory()
	if err != nil {
		return err
	}
	if isNilInterface(next) {
		return errors.New("dmq reloading signer factory returned nil signer")
	}
	s.mu.Lock()
	s.signer = next
	s.mu.Unlock()
	return nil
}

// ActiveSigner returns the currently active signer.
func (s *ReloadingSigner) ActiveSigner() Signer {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.signer
}

// ReloadingKESSigningProviderFactory constructs a complete replacement
// KESSigningProvider.
type ReloadingKESSigningProviderFactory func() (KESSigningProvider, error)

// ReloadingKESSigningProvider delegates KES signing to the currently active
// provider and swaps in a freshly constructed replacement when Reload succeeds.
type ReloadingKESSigningProvider struct {
	mu       sync.RWMutex
	factory  ReloadingKESSigningProviderFactory
	provider KESSigningProvider
}

// NewReloadingKESSigningProvider creates a reloadable KES signing provider from
// a caller-provided factory.
func NewReloadingKESSigningProvider(factory ReloadingKESSigningProviderFactory) (*ReloadingKESSigningProvider, error) {
	s := &ReloadingKESSigningProvider{
		factory: factory,
	}
	if err := s.Reload(); err != nil {
		return nil, err
	}
	return s, nil
}

// NewReloadingKESSigner creates a reloadable in-process KES signer from key and
// operational-certificate files.
func NewReloadingKESSigner(kesKeyPath, opCertPath string, params NetworkParams) (*ReloadingKESSigningProvider, error) {
	return NewReloadingKESSignerWithClock(kesKeyPath, opCertPath, params, time.Now)
}

// NewReloadingKESSignerWithClock creates a reloadable in-process KES signer with
// an injected clock.
func NewReloadingKESSignerWithClock(kesKeyPath, opCertPath string, params NetworkParams, now func() time.Time) (*ReloadingKESSigningProvider, error) {
	return NewReloadingKESSigningProvider(func() (KESSigningProvider, error) {
		return NewKESSignerWithClock(kesKeyPath, opCertPath, params, now)
	})
}

// NewReloadingExternalKESSigner creates a reloadable external-process KES signer
// wrapper.
func NewReloadingExternalKESSigner(command, opCertPath string, params NetworkParams, timeout time.Duration) (*ReloadingKESSigningProvider, error) {
	return NewReloadingExternalKESSignerWithClock(command, opCertPath, params, timeout, time.Now)
}

// NewReloadingExternalKESSignerWithClock creates a reloadable external-process
// KES signer wrapper with an injected clock.
func NewReloadingExternalKESSignerWithClock(command, opCertPath string, params NetworkParams, timeout time.Duration, now func() time.Time) (*ReloadingKESSigningProvider, error) {
	return NewReloadingExternalKESSignerFromConfig(ExternalKESSignerConfig{
		Command:                    command,
		OperationalCertificatePath: opCertPath,
		Network:                    params,
		Timeout:                    timeout,
		Now:                        now,
	})
}

// NewReloadingExternalKESSignerFromConfig creates a reloadable external-process
// KES signer wrapper from config.
func NewReloadingExternalKESSignerFromConfig(cfg ExternalKESSignerConfig) (*ReloadingKESSigningProvider, error) {
	return NewReloadingKESSigningProvider(func() (KESSigningProvider, error) {
		return NewExternalKESSignerFromConfig(cfg)
	})
}

// Sign delegates to the currently active provider.
func (s *ReloadingKESSigningProvider) Sign(payload []byte) (SignedKESPayload, error) {
	provider := s.ActiveProvider()
	if provider == nil || isNilInterface(provider) {
		return SignedKESPayload{}, ErrSignerRequired
	}
	return provider.Sign(payload)
}

// SignAt delegates to the currently active provider.
func (s *ReloadingKESSigningProvider) SignAt(period uint64, payload []byte) (SignedKESPayload, error) {
	provider := s.ActiveProvider()
	if provider == nil || isNilInterface(provider) {
		return SignedKESPayload{}, ErrSignerRequired
	}
	return provider.SignAt(period, payload)
}

// CurrentPeriod delegates to the currently active provider.
func (s *ReloadingKESSigningProvider) CurrentPeriod() (uint64, error) {
	provider := s.ActiveProvider()
	if provider == nil || isNilInterface(provider) {
		return 0, ErrSignerRequired
	}
	return provider.CurrentPeriod()
}

// OperationalCertificate delegates to the currently active provider,
// returning the zero value when no provider is active.
func (s *ReloadingKESSigningProvider) OperationalCertificate() KESSigningCertificate {
	provider := s.ActiveProvider()
	if provider == nil || isNilInterface(provider) {
		return KESSigningCertificate{}
	}
	return provider.OperationalCertificate()
}

// Reload constructs and validates a replacement KES signing provider, then
// swaps it in. The active provider is left unchanged when construction fails.
func (s *ReloadingKESSigningProvider) Reload() error {
	if s == nil {
		return ErrSignerRequired
	}
	if s.factory == nil {
		return errors.New("dmq reloading KES signing provider factory is required")
	}
	next, err := s.factory()
	if err != nil {
		return err
	}
	if isNilInterface(next) {
		return errors.New("dmq reloading KES signing provider factory returned nil provider")
	}
	s.mu.Lock()
	s.provider = next
	s.mu.Unlock()
	return nil
}

// ActiveProvider returns the currently active KES signing provider.
func (s *ReloadingKESSigningProvider) ActiveProvider() KESSigningProvider {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.provider
}

func isNilInterface(v any) bool {
	if v == nil {
		return true
	}
	value := reflect.ValueOf(v)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	case reflect.Invalid,
		reflect.Bool,
		reflect.Int,
		reflect.Int8,
		reflect.Int16,
		reflect.Int32,
		reflect.Int64,
		reflect.Uint,
		reflect.Uint8,
		reflect.Uint16,
		reflect.Uint32,
		reflect.Uint64,
		reflect.Uintptr,
		reflect.Float32,
		reflect.Float64,
		reflect.Complex64,
		reflect.Complex128,
		reflect.Array,
		reflect.String,
		reflect.Struct,
		reflect.UnsafePointer:
		return false
	default:
		return false
	}
}
