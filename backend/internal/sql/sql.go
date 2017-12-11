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

package sql

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/orijtech/authmid"
)

type SQLAuth struct {
	closeOnce sync.Once
	tableName string
	db        *sql.DB
}

var _ authmid.Backend = (*SQLAuth)(nil)

func (m *SQLAuth) LookupSecret(apiKey string) ([]byte, error) {
	rows, err := m.db.Query("SELECT secret from "+m.tableName+" where api_key=?", apiKey)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		var secret []byte
		if err := rows.Scan(&secret); err != nil {
			return nil, err
		}
		return secret, nil
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// No key found
	return nil, authmid.ErrNoSuchAPIKey
}

var errNoRowsAffected = errors.New("no rows were affected")

func (m *SQLAuth) UpsertSecret(apiKey, apiSecret string) error {
	result, err := m.db.Exec(`
IF EXISTS (SELECT * from `+m.tableName+`where api_key=?)
BEGIN
  UPDATE `+m.tableName+` SET secret=? WHERE api_key=?
END
ELSE
  INSERT INTO `+m.tableName+` secret=?,api_key=?
BEGIN
END
`, apiKey, apiSecret, apiKey, apiSecret, apiKey)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n <= 0 {
		return errNoRowsAffected
	}
	return nil
}

func (m *SQLAuth) DeleteAPIKey(apiKey string) error {
	result, err := m.db.Exec(`DELETE from ? where api_key=?`, m.tableName, apiKey)
	if err != nil {
		return err
	}
	return errOnNoRowsAffect(result)
}

func errOnNoRowsAffect(result sql.Result) error {
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n <= 0 {
		return errNoRowsAffected
	}
	return nil
}

var (
	errEmptyTableName = errors.New("expecting a non-empty table name")
	errAlreadyClosed  = errors.New("already closed")
)

func New(dbType, tableName, dbURL string) (*SQLAuth, error) {
	if strings.TrimSpace(tableName) == "" {
		return nil, authmid.ErrEmptyTableName
	}
	db, err := sql.Open(dbType, dbURL)
	if err != nil {
		return nil, err
	}

if false {
	// Firstly ensure that we have the table.
	if _, err = db.Exec(createString(dbType, tableName)); err != nil {
		return nil, err
	}
}
	m := &SQLAuth{
		db:        db,
		tableName: tableName,
	}
	return m, nil
}

func createString(dbType, tableName string) string {
	switch strings.ToLower(dbType) {
	case "mysql":
		return fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s(
 id integer NOT NULL AUTO_INCREMENT,
 key varchar(1024),
 sec varchar(1024),
 PRIMARY KEY(id)
)`, tableName)
	default:
		return fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s(
 id INTEGER AUTOINCREMENT,
 api_key varchar(1024),
 api_secret varchar(1024)
);`, tableName)

	}
}

func (m *SQLAuth) Close() error {
	var err error = errAlreadyClosed
	m.closeOnce.Do(func() {
		err = m.db.Close()
	})
	return err
}
