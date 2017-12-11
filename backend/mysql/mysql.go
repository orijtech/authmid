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

package mysql

import (
	"github.com/orijtech/authmid"
	"github.com/orijtech/authmid/backend/internal/sql"

	// Register the MySQL driver
	_ "github.com/go-sql-driver/mysql"
)

func New(tableName, dbURL string) (authmid.Backend, error) {
	return sql.New("mysql", tableName, dbURL)
}
