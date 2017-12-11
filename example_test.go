// Copyright 2017 orijtech. All Rights Reserved.
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

package authmid_test

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/orijtech/authmid"
	"github.com/orijtech/authmid/backend/redis"
)

func Example_middleware() {
	srv := httptest.NewServer(authmid.Middleware(&sampleAuthChecker{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := ioutil.ReadAll(r.Body)
		fmt.Fprintf(w, "Well authenticated, and here is your body: %s", body)
	})))
	defer srv.Close()

	// The client will then authenticate like this
	req := makeReq("POST", []byte(`{"name": "foo", "age": 99}`), authKey1)
	req.URL, _ = url.Parse(srv.URL)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()
	blob, _ := ioutil.ReadAll(res.Body)
	fmt.Printf("response: %s\n", blob)
}

func Example_inPlainServer() {
	http.Handle("/", authmid.Middleware(&sampleAuthChecker{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Authenticated pong!")
	})))
}

func Example_backendForAuthentication() {
	backend, err := redis.New("keys", "redis://localhost:6379")
	if err != nil {
		log.Fatal(err)
	}

	ac := &apiChecker{
		backend: backend,
		next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "Authenticated pong!")
		}),
		hdrKey: "DEMO-ACCESS-APIKEY",
	}
	http.Handle("/ping", ac)

	http.HandleFunc("/reg", func(w http.ResponseWriter, r *http.Request) {
		qv := r.URL.Query()
		key, secret := qv.Get("key"), qv.Get("secret")
		if err := backend.UpsertSecret(key, secret); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	})

	addr := ":8777"
	log.Printf("Serving on: %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal(err)
	}
}

type apiChecker struct {
	backend authmid.Backend
	next    http.Handler
	hdrKey  string
}

func (ac *apiChecker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	apiKey := r.Header.Get(ac.hdrKey)
	if strings.TrimSpace(apiKey) == "" {
		http.Error(w, "expecting a non-blank API Key", http.StatusBadRequest)
		return
	}
	secret, err := ac.backend.LookupSecret(apiKey)
	if err != nil {
		log.Printf("looking up secret: err: %v", err)
		http.Error(w, "failed to lookup the secret", http.StatusBadRequest)
		return
	}
	log.Printf("secret: %s\n", secret)
	ac.next.ServeHTTP(w, r)
}
