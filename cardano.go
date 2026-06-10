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
	"encoding/json"
	"errors"
	"fmt"
	"math/bits"
	"os"
	"time"
)

const (
	// CardanoSlotsPerKESPeriod is the slots-per-KES-period genesis parameter
	// shared by Cardano mainnet, preprod, and preview. Custom networks may
	// differ; use NetworkParams.SlotsPerKESPeriod as the source of truth.
	CardanoSlotsPerKESPeriod = 129600

	// CardanoMainnetShelleyStartSlot is the absolute slot at the Shelley hard fork.
	CardanoMainnetShelleyStartSlot = 4492800
	// CardanoPreprodShelleyStartSlot is the absolute slot at the Shelley hard fork.
	CardanoPreprodShelleyStartSlot = 86400
)

var (
	cardanoMainnetShelleyStart = time.Date(2020, 7, 29, 21, 44, 51, 0, time.UTC)
	cardanoPreprodShelleyStart = time.Date(2022, 6, 21, 0, 0, 0, 0, time.UTC)
)

// NetworkParams contains the timing parameters needed to derive absolute KES
// periods and epochs. Start is the wall-clock time for AbsoluteStartSlot.
type NetworkParams struct {
	Start             time.Time
	AbsoluteStartSlot uint64
	SlotLength        time.Duration
	EpochLength       uint64
	SlotsPerKESPeriod uint64
	MaxKESEvolutions  uint64
}

// NetworkParamsForMagic returns Shelley timing parameters for well-known
// Cardano networks.
func NetworkParamsForMagic(magic uint32) (NetworkParams, error) {
	switch magic {
	case 764824073: // mainnet
		return NetworkParams{
			Start:             cardanoMainnetShelleyStart,
			AbsoluteStartSlot: CardanoMainnetShelleyStartSlot,
			SlotLength:        time.Second,
			EpochLength:       432000,
			SlotsPerKESPeriod: CardanoSlotsPerKESPeriod,
			MaxKESEvolutions:  62,
		}, nil
	case 1: // preprod
		return NetworkParams{
			Start:             cardanoPreprodShelleyStart,
			AbsoluteStartSlot: CardanoPreprodShelleyStartSlot,
			SlotLength:        time.Second,
			EpochLength:       432000,
			SlotsPerKESPeriod: CardanoSlotsPerKESPeriod,
			MaxKESEvolutions:  62,
		}, nil
	case 2: // preview
		return NetworkParams{
			Start:             time.Date(2022, 10, 25, 0, 0, 0, 0, time.UTC),
			SlotLength:        time.Second,
			EpochLength:       86400,
			SlotsPerKESPeriod: CardanoSlotsPerKESPeriod,
			MaxKESEvolutions:  62,
		}, nil
	}
	return NetworkParams{}, fmt.Errorf("unknown network magic %d (mainnet=764824073, preprod=1, preview=2)", magic)
}

// NetworkParamsFromShelleyGenesis builds NetworkParams from a Shelley genesis
// JSON file, for networks not covered by NetworkParamsForMagic.
func NetworkParamsFromShelleyGenesis(path string) (NetworkParams, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return NetworkParams{}, fmt.Errorf("read Shelley genesis %q: %w", path, err)
	}
	var genesis struct {
		SystemStart       string   `json:"systemStart"`
		SlotLength        *float64 `json:"slotLength"`
		EpochLength       uint64   `json:"epochLength"`
		SlotsPerKESPeriod uint64   `json:"slotsPerKESPeriod"`
		MaxKESEvolutions  uint64   `json:"maxKESEvolutions"`
		NetworkMagic      uint32   `json:"networkMagic"`
		AbsoluteStartSlot *uint64  `json:"absoluteStartSlot"`
	}
	if err := json.Unmarshal(raw, &genesis); err != nil {
		return NetworkParams{}, fmt.Errorf("parse Shelley genesis %q: %w", path, err)
	}
	if genesis.SystemStart == "" {
		return NetworkParams{}, fmt.Errorf("shelley genesis %q missing systemStart", path)
	}
	start, err := time.Parse(time.RFC3339, genesis.SystemStart)
	if err != nil {
		return NetworkParams{}, fmt.Errorf("parse Shelley genesis systemStart %q: %w", genesis.SystemStart, err)
	}
	if genesis.SlotsPerKESPeriod == 0 {
		return NetworkParams{}, fmt.Errorf("shelley genesis %q missing slotsPerKESPeriod", path)
	}
	slotLength := time.Second
	if genesis.SlotLength != nil {
		if *genesis.SlotLength <= 0 {
			return NetworkParams{}, fmt.Errorf("shelley genesis %q has invalid slotLength %v", path, *genesis.SlotLength)
		}
		slotLength = time.Duration(*genesis.SlotLength * float64(time.Second))
		if slotLength <= 0 {
			return NetworkParams{}, fmt.Errorf("shelley genesis %q has invalid slotLength %v", path, *genesis.SlotLength)
		}
	}
	if genesis.EpochLength == 0 {
		return NetworkParams{}, fmt.Errorf("shelley genesis %q missing epochLength", path)
	}
	absoluteStartSlot := uint64(0)
	if genesis.AbsoluteStartSlot != nil {
		absoluteStartSlot = *genesis.AbsoluteStartSlot
	} else if genesis.NetworkMagic == 764824073 {
		start = cardanoMainnetShelleyStart
		absoluteStartSlot = CardanoMainnetShelleyStartSlot
	}
	return NetworkParams{
		Start:             start,
		AbsoluteStartSlot: absoluteStartSlot,
		SlotLength:        slotLength,
		EpochLength:       genesis.EpochLength,
		SlotsPerKESPeriod: genesis.SlotsPerKESPeriod,
		MaxKESEvolutions:  genesis.MaxKESEvolutions,
	}, nil
}

// CurrentKESPeriod returns the absolute KES period at the given time for a
// well-known Cardano network identified by its network magic.
func CurrentKESPeriod(magic uint32, now time.Time) (uint64, error) {
	p, err := NetworkParamsForMagic(magic)
	if err != nil {
		return 0, err
	}
	return CurrentKESPeriodFor(p, now)
}

// CurrentKESPeriodFor returns the absolute KES period at the given time for
// the supplied network parameters.
func CurrentKESPeriodFor(p NetworkParams, now time.Time) (uint64, error) {
	if p.SlotsPerKESPeriod == 0 {
		return 0, errors.New("slotsPerKESPeriod must be > 0")
	}
	slot, err := currentAbsoluteSlotFor(p, now)
	if err != nil {
		return 0, err
	}
	return slot / p.SlotsPerKESPeriod, nil
}

// CurrentEpochFor returns the epoch number at the given time, counted from
// the network parameters' start time.
func CurrentEpochFor(p NetworkParams, now time.Time) (uint64, error) {
	if p.EpochLength == 0 {
		return 0, errors.New("epochLength must be > 0")
	}
	slot, err := CurrentSlotFor(p, now)
	if err != nil {
		return 0, err
	}
	return slot / p.EpochLength, nil
}

// CurrentSlotFor returns the slot at the given time, relative to the network
// parameters' start time. Add NetworkParams.AbsoluteStartSlot for the
// absolute chain slot.
func CurrentSlotFor(p NetworkParams, now time.Time) (uint64, error) {
	slotLength := p.SlotLength
	if slotLength <= 0 {
		slotLength = time.Second
	}
	if now.Before(p.Start) {
		return 0, fmt.Errorf("clock %s is before network start %s", now, p.Start)
	}
	slotDuration := now.Sub(p.Start) / slotLength
	if slotDuration < 0 {
		return 0, fmt.Errorf("clock %s is before network start %s", now, p.Start)
	}
	return uint64(slotDuration), nil
}

func currentAbsoluteSlotFor(p NetworkParams, now time.Time) (uint64, error) {
	slot, err := CurrentSlotFor(p, now)
	if err != nil {
		return 0, err
	}
	if slot > ^uint64(0)-p.AbsoluteStartSlot {
		return 0, fmt.Errorf("slot overflow: absolute start slot %d plus relative slot %d", p.AbsoluteStartSlot, slot)
	}
	return p.AbsoluteStartSlot + slot, nil
}

// KESPeriodStart returns the wall-clock time at which the given absolute KES
// period begins. It returns the zero time when the period is before the
// network start or the computation overflows.
func KESPeriodStart(p NetworkParams, period uint64) time.Time {
	slotLength := p.SlotLength
	if slotLength <= 0 {
		slotLength = time.Second
	}
	slotsHi, slots := bits.Mul64(period, p.SlotsPerKESPeriod)
	if slotsHi != 0 {
		return time.Time{}
	}
	if slots < p.AbsoluteStartSlot {
		return time.Time{}
	}
	slots -= p.AbsoluteStartSlot
	nanosHi, nanos := bits.Mul64(slots, uint64(slotLength))
	if nanosHi != 0 || nanos > uint64(1<<63-1) {
		return time.Time{}
	}
	return p.Start.Add(time.Duration(nanos)) //nolint:gosec // Bounds checked above against time.Duration max.
}
