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

// Package dmq provides an embeddable implementation of the CIP-0137
// Distributed Message Queue for Go applications.
//
// The package manages topic-scoped queues, local fanout subscriptions,
// deterministic message ID checks, TTL policy, duplicate suppression, optional
// gOuroboros message authentication, and lifecycle hooks. Use Manager when a
// process needs explicit multi-topic control, or TopicNode when it wants a
// single-topic node that can register the topic, load discovery peers, start
// node-to-node networking, and shut down as one unit.
//
// dmq aliases the gOuroboros DMQ wire types so callers can publish local
// message bodies through a Signer or submit already signed CIP-0137 messages
// directly. It includes Cardano network timing helpers, file-backed and
// external-process KES signing helpers, topology and ledger peer discovery, and
// gOuroboros protocol adapters for local message submission, local message
// notification, and node-to-node message submission.
package dmq
