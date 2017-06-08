# authmid
Authentication middleware for signed requests, useful for webhook authentication verifying identities

## Usage
Create your custom authenticator that conforms to interface Authenticator
so that you can custom lookup the secret, and headers and pass that into
Middleware to wrap the next handler. For example, simply:
```go
func main() {
	http.Handle("/", authmid.Middleware(&sampleAuthChecker{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Authenticated pong!")
	})))

	// Then run the server to receive traffic.
}
```

Or for a more comprehensive end to end working example:

```go
func main() {
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
```
