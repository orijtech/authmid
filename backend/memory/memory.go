// Copyright 2017 orijtech, Inc. All Rights Reserved.
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

package memory

import (
	"errors"
	"sync"
)

type Memory struct {
	m  map[string]string
	mu sync.Mutex
}

func (m *Memory) Close() error {
	return nil
}

func (m *Memory) UpsertSecret(apiKey, apiSecret string) error {
	m.mu.Lock()
	m.m[apiKey] = apiSecret
	m.mu.Unlock()

	return nil
}

func (m *Memory) DeleteAPIKey(apiKey string) error {
	m.mu.Lock()
	delete(m.m, apiKey)
	m.mu.Unlock()

	return nil
}

func NewWithMap(m map[string]string) (*Memory, error) {
	return &Memory{m: m}, nil
}

var errNoSuchSecret = errors.New("no such secret")

func (m *Memory) LookupSecret(apiKey string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	secret, ok := m.m[apiKey]
	if !ok {
		return nil, errNoSuchSecret
	}
	return []byte(secret), nil
}
