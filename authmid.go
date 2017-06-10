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

package authmid

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
)

type Authenticator interface {
	LookupSecret(apiKey string) ([]byte, error)
	HeaderValues(hdr http.Header) (values, warnings []string, err error)
	LookupAPIKey(hdr http.Header) (string, error)
	Signature(hdr http.Header) (string, error)
}

var (
	ErrSignatureMismatch = errors.New("invalid/mismatched signatures")
)

func Middleware(vf Authenticator, next http.Handler) http.Handler {
	return &auther{verify: Checker(vf), next: next}
}

type auther struct {
	verify func(*http.Request) error
	next   http.Handler
}

var _ http.Handler = (*auther)(nil)

func (a *auther) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := a.verify(r)
	if err == nil {
		// We can proceed, verification was successful.
		a.next.ServeHTTP(w, r)
		return
	}

	// Otherwise we've encountered an error
	switch typ := err.(type) {
	case CodedError:
		http.Error(w, typ.Error(), typ.Code())
	default:
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

var errNilHeader = errors.New("expecting a non-nil header")

type ExcludeMethodAndPather interface {
	ExcludeMethodAndPath() bool
}

func Checker(vf Authenticator) func(*http.Request) error {
	return func(req *http.Request) error {
		if req == nil || len(req.Header) == 0 {
			return errNilHeader
		}
		wantSignature, err := vf.Signature(req.Header)
		if err != nil {
			return err
		}
		apiKey, err := vf.LookupAPIKey(req.Header)
		if err != nil {
			return err
		}
		apiSecret, err := vf.LookupSecret(apiKey)
		if err != nil {
			return err
		}
		rreq, body, err := slurpThenRecoverBody(req)
		if err != nil {
			return err
		}
		mac := hmac.New(sha256.New, apiSecret)
		inputs := []string{string(body)}
		if ex, ok := vf.(ExcludeMethodAndPather); !ok || !ex.ExcludeMethodAndPath() {
			urlPath := rreq.URL.Path
			if q := req.URL.Query(); len(q) > 0 {
				urlPath += "?" + q.Encode()
			}
			// Otherwise prepend req.Method and urlPath
			inputs = append([]string{req.Method, urlPath}, inputs...)
		}
		headerValues, warnings, err := vf.HeaderValues(req.Header)
		if err != nil {
			return err
		}
		if len(warnings) > 0 {
			// TODO: Figure out if to send this component in the
			// response writer and when should the write be performed?
		}
		sigInput := append(headerValues, inputs...)
		_, _ = io.WriteString(mac, strings.Join(sigInput, ""))
		gotSignature := fmt.Sprintf("%x", mac.Sum(nil))
		if gotSignature != wantSignature {
			return ErrSignatureMismatch
		}
		return nil
	}
}

type CodedError interface {
	Error() string
	Code() int
}

func slurpThenRecoverBody(req *http.Request) (*http.Request, []byte, error) {
	if req.Body == nil {
		return req, nil, nil
	}

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return req, nil, err
	}
	// Close the original body
	_ = req.Body.Close()
	prc, pwc := io.Pipe()
	go func() {
		defer pwc.Close()
		pwc.Write(body)
	}()
	req.Body = prc
	return req, body, nil
}
