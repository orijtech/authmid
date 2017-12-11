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

package redis

import (
	"errors"
	"strings"
	"sync"

	"github.com/odeke-em/redtable"

	"github.com/orijtech/authmid"
)

type redisConnector struct {
	closeOnce  sync.Once
	c          *redtable.Client
	hTableName string
}

func New(hashTableName, dbURL string) (authmid.Backend, error) {
	if strings.TrimSpace(hashTableName) == "" {
		return nil, authmid.ErrEmptyTableName
	}
	c, err := redtable.New(dbURL)
	if err != nil {
		return nil, err
	}
	return &redisConnector{c: c, hTableName: hashTableName}, nil
}

var _ authmid.Backend = (*redisConnector)(nil)

func (rc *redisConnector) LookupSecret(apiKey string) ([]byte, error) {
	value, err := rc.c.HGet(rc.hTableName, apiKey)
	if err != nil {
		return nil, err
	}

	var secret []byte
	switch typedV := value.(type) {
	case []byte:
		secret = typedV
	case string:
		secret = []byte(typedV)
	}
	if secret == nil {
		return nil, authmid.ErrNoSuchAPIKey
	}
	return secret, nil
}

func (rc *redisConnector) UpsertSecret(apiKey, apiSecret string) error {
	_, err := rc.c.HSet(rc.hTableName, apiKey, apiSecret)
	return err
}

func (rc *redisConnector) DeleteAPIKey(apiKey string) error {
	n, err := rc.c.HDel(rc.hTableName, apiKey)
	if err != nil {
		return err
	}
	return errOnNoRowsAffected(n)
}

var errNoEntriesMatched = errors.New("no entries matched")

func errOnNoRowsAffected(n interface{}) error {
	var nr int64
	switch typedValue := n.(type) {
	case int64:
		nr = typedValue
	case int:
		nr = int64(typedValue)
	case uint:
		nr = int64(typedValue)
	case uint64:
		nr = int64(typedValue)
	default:
		return nil
	}
	if nr <= 0 {
		return errNoEntriesMatched
	}
	return nil
}

var errAlreadyClosed = errors.New("already closed")

func (rc *redisConnector) Close() error {
	var err error = errAlreadyClosed
	rc.closeOnce.Do(func() {
		err = rc.c.Close()
	})
	return err
}
