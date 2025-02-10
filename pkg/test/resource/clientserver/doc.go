// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 The Falco Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package clientserver provides the implementation of a clientServer test resource. A clientServer sets up a client and
// a server, and enables their communication by tuning the underlying network infrastructure. The user can specify udp4,
// udp6, tcp4, tcp6 or unix as transport protocol. For connection-oriented transport protocols, the client is
// automatically connected to the server. The resource enables field binding to both client and server information.
package clientserver
