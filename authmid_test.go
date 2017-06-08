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
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/orijtech/authmid"
)

func TestChecker(t *testing.T) {
	tests := [...]struct {
		Authenticator authmid.Authenticator
		wantErr       bool

		req, comparisonReq *http.Request
	}{
		0: {
			req:           makeReq("POST", []byte(`{"name": "foo", "age": 99}`), authKey1),
			Authenticator: &sampleAuthChecker{},
			comparisonReq: makeReq("POST", []byte(`{"name": "foo", "age": 99}`), authKey1),
		},
		1: {
			req:           makeReq("GET", nil, authKey2),
			Authenticator: &sampleAuthChecker{},
			comparisonReq: makeReq("GET", nil, authKey2),
		},
		2: {
			req:           makeReq("GET", []byte(`{"name": "fiddler"}`), authKey1, "TEST-ACCESS-TIMESTAMP"),
			Authenticator: &sampleAuthChecker{},
			wantErr:       true, // "TEST-ACCESS-TIMESTAMP" was popped
		},
		3: {
			req:           makeReq("POST", nil, authKey1, "TEST-ACCESS-TIMESTAMP"),
			Authenticator: &sampleAuthChecker{},
			wantErr:       true, // "TEST-ACCESS-TIMESTAMP" was popped
		},

		// Test with a custom method
		4: {
			req:           makeReq("FOMO", nil, authKey1),
			Authenticator: &sampleAuthChecker{},
			comparisonReq: makeReq("FOMO", nil, authKey1),
		},
	}

	for i, tt := range tests {
		checkFn := authmid.Checker(tt.Authenticator)
		err := checkFn(tt.req)
		gotErr := err != nil
		if gotErr != tt.wantErr {
			t.Errorf("#%d: gotErr=%v wantErr=%v; err:(%v)", i, gotErr, tt.wantErr, err)
		}

		// Now ensure that the dump of both requests is the same
		gotDump, wantDump := dumpReqOut(tt.req), dumpReqOut(tt.comparisonReq)
		if !tt.wantErr && !bytes.Equal(gotDump, wantDump) {
			t.Errorf("#%d:\ngot: %q\nwant:%q\n", i, gotDump, wantDump)
		}
	}
}

type sampleAuthChecker struct{}

var _ authmid.Authenticator = (*sampleAuthChecker)(nil)

func (ca *sampleAuthChecker) HeaderValues(hdr http.Header) (values, warnings []string, err error) {
	keys := []struct {
		key      string
		optional bool
	}{
		// {key: "TEST-VERSION", optional: true},
		{key: "TEST-ACCESS-TIMESTAMP"},
	}
	var errsList []string
	for _, st := range keys {
		value, err := headerValueOrErr(hdr, st.key)
		if err == nil {
			values = append(values, value)
			continue
		}
		if st.optional {
			warnings = append(warnings, err.Error())
		} else {
			errsList = append(errsList, err.Error())
		}
	}
	if len(errsList) > 0 {
		return nil, warnings, errors.New(strings.Join(errsList, "\n"))
	}
	return values, warnings, nil
}

func (ca *sampleAuthChecker) LookupAPIKey(hdr http.Header) (string, error) {
	return headerValueOrErr(hdr, "TEST-ACCESS-KEY")
}

var (
	apiKey1 = "b9b60b63-e37b-4b45-9397-2c20433f4d53"
	apiKey2 = "78e34d4c-7f6e-4c57-995d-224cd0296fd0"

	bAPISecret1 = []byte("a41ce573-b848-40b2-9618-565f44133992")
	bAPISecret2 = []byte("65d6829c-f9f9-45c5-9f9f-9646c0f129dc")

	errUnknownAPIKey = errors.New("unknown API key")
)

func (ca *sampleAuthChecker) LookupSecret(apiKey string) ([]byte, error) {
	switch apiKey {
	case apiKey1:
		return bAPISecret1, nil
	case apiKey2:
		return bAPISecret2, nil
	default:
		return nil, errUnknownAPIKey
	}
}

func (ca *sampleAuthChecker) Signature(hdr http.Header) (string, error) {
	return headerValueOrErr(hdr, "TEST-ACCESS-SIGN")
}

func headerValueOrErr(hdr http.Header, key string) (string, error) {
	if value := hdr.Get(key); value != "" {
		return value, nil
	}
	return "", fmt.Errorf("missing %q key", key)
}

func makeReq(method string, body []byte, aKey *authKey, hdrKeysToPop ...string) *http.Request {
	var prc io.ReadCloser
	if len(body) > 0 {
		var pwc io.WriteCloser
		prc, pwc = io.Pipe()
		go func() {
			defer pwc.Close()
			pwc.Write(body)
		}()
	}

	u, _ := url.Parse("https://orijtech.com/")
	req := &http.Request{
		Method: method,
		Header: make(http.Header),
		Body:   prc,
		URL:    u,
	}
	aKey.signAndSetHeaders(req)

	for _, hdrKey := range hdrKeysToPop {
		req.Header.Del(hdrKey)
	}
	return req
}

func dumpReqOut(req *http.Request) []byte {
	defer func() {
		// Catch and ignore any panics
		_ = recover()
	}()
	dump, _ := httputil.DumpRequestOut(req, true)
	return dump
}

var (
	authKey1 = &authKey{
		key:    apiKey1,
		secret: string(bAPISecret1),
	}

	authKey2 = &authKey{
		key:    apiKey2,
		secret: string(bAPISecret2),
	}
)

type authKey struct {
	secret, key string
}

func (aKey *authKey) signAndSetHeaders(req *http.Request) {
	// Expecting headers:
	// * TEST-ACCESS-KEY
	// * TEST-ACCESS-SIGN:
	//    + HMAC(timestamp + method + requestPath + body)
	// * TEST-ACCESS-TIMESTAMP: Number of seconds since Unix Epoch of the request
	timestamp := time.Now().Unix()
	req.Header.Set("TEST-VERSION", "2017-06-07")
	req.Header.Set("TEST-ACCESS-TIMESTAMP", fmt.Sprintf("%d", timestamp))
	req.Header.Set("TEST-ACCESS-KEY", aKey.key)
	req.Header.Set("TEST-ACCESS-SIGN", aKey.hmacSignature(req, timestamp))
}

func (aKey *authKey) hmacSignature(req *http.Request, timestampUnix int64) string {
	var body []byte
	if req.Body != nil {
		body, _ = ioutil.ReadAll(req.Body)
		// And we have to reconstruct the body now
		prc, pwc := io.Pipe()
		go func() {
			defer pwc.Close()
			pwc.Write(body)
		}()
		req.Body = prc
	}

	mac := hmac.New(sha256.New, []byte(aKey.secret))
	urlPath := req.URL.Path
	if q := req.URL.Query(); len(q) > 0 {
		urlPath += "?" + q.Encode()
	}
	sig := fmt.Sprintf("%d%s%s%s", timestampUnix, req.Method, urlPath, body)
	mac.Write([]byte(sig))
	return fmt.Sprintf("%x", mac.Sum(nil))
}
