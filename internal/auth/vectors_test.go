package auth

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/icholy/digest"
)

func mustReq(t *testing.T, method, u, body string) *http.Request {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, u, r)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func sign(t *testing.T, c *Config, req *http.Request) {
	t.Helper()
	s, err := NewManager().Signer(c, Env{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Sign(context.Background(), req); err != nil {
		t.Fatal(err)
	}
}

// Hawk specification example (hueniverse/hawk README).
func TestHawkVector(t *testing.T) {
	c := &Config{Type: "hawk", Hawk: &HawkConfig{
		ID: "dh37fgj492je", Key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
		Timestamp: 1353832234, Nonce: "j4h3g2", Ext: "some-app-ext-data",
	}}
	req := mustReq(t, "GET", "http://example.com:8000/resource/1?b=1&a=2", "")
	sign(t, c, req)
	want := `Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", ext="some-app-ext-data", mac="6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE="`
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("hawk header\n got %s\nwant %s", got, want)
	}

	// Payload example from the same README.
	c.Hawk.Payload = true
	req = mustReq(t, "POST", "http://example.com:8000/resource/1?b=1&a=2", "Thank you for flying Hawk")
	req.Header.Set("Content-Type", "text/plain")
	sign(t, c, req)
	got := req.Header.Get("Authorization")
	if !strings.Contains(got, `hash="Yi9LfIIFRtBEPt74PVmbTF/xVAwPn7ub15ePICfgnuY="`) {
		t.Fatalf("hawk payload hash: %s", got)
	}
	if !strings.Contains(got, `mac="aSe1DERmZuRl3pI36/9BdZmnErTw3sNzOOAUlfeKjVw="`) {
		t.Fatalf("hawk payload mac: %s", got)
	}
	// The body is still readable after signing.
	b, _ := io.ReadAll(req.Body)
	if string(b) != "Thank you for flying Hawk" {
		t.Fatalf("body consumed: %q", b)
	}
}

func oauth1Sig(t *testing.T, h string) string {
	t.Helper()
	for _, p := range strings.Split(strings.TrimPrefix(h, "OAuth "), ", ") {
		if v, ok := strings.CutPrefix(p, `oauth_signature="`); ok {
			s, err := url.PathUnescape(strings.TrimSuffix(v, `"`))
			if err != nil {
				t.Fatal(err)
			}
			return s
		}
	}
	t.Fatalf("no signature in %s", h)
	return ""
}

func TestOAuth1Vectors(t *testing.T) {
	// OAuth Core 1.0 Appendix A.5 (photos.example.net).
	c := &Config{Type: "oauth1", OAuth1: &OAuth1Config{
		ConsumerKey: "dpf43f3p2l4k3l03", ConsumerSecret: "kd94hf93k423kf44",
		Token: "nnch734d00sl2jdk", TokenSecret: "pfkkdhi9sl3r4s00",
		Nonce: "kllo9940pd9333jh", Timestamp: 1191242096, Realm: "http://photos.example.net/",
	}}
	req := mustReq(t, "GET", "http://photos.example.net/photos?file=vacation.jpg&size=original", "")
	sign(t, c, req)
	if got := oauth1Sig(t, req.Header.Get("Authorization")); got != "tR3+Ty81lMeYAr/Fid0kMTYa/WM=" {
		t.Fatalf("oauth core 1.0 vector: got %s", got)
	}
	if !strings.HasPrefix(req.Header.Get("Authorization"), `OAuth realm="http%3A%2F%2Fphotos.example.net%2F", `) {
		t.Fatalf("realm: %s", req.Header.Get("Authorization"))
	}

	// Twitter "Creating a signature" example: form body parameters are
	// part of the base string.
	c = &Config{Type: "oauth1", OAuth1: &OAuth1Config{
		ConsumerKey:    "xvz1evFS4wEEPTGEFPHBog",
		ConsumerSecret: "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw",
		Token:          "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb",
		TokenSecret:    "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE",
		Nonce:          "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg",
		Timestamp:      1318622958,
	}}
	body := "status=Hello%20Ladies%20%2B%20Gentlemen%2C%20a%20signed%20OAuth%20request%21"
	req = mustReq(t, "POST", "https://api.twitter.com/1.1/statuses/update.json?include_entities=true", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	sign(t, c, req)
	if got := oauth1Sig(t, req.Header.Get("Authorization")); got != "hCtSmYh+iHYCEqBWrE7C7hYmtUk=" {
		t.Fatalf("twitter vector: got %s", got)
	}
	b, _ := io.ReadAll(req.Body)
	if string(b) != body {
		t.Fatalf("body consumed: %q", b)
	}

	// RFC 5849 §3.4.1.1 base string example.
	u, _ := url.Parse("http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b")
	params := [][2]string{}
	for k, vs := range u.Query() {
		for _, v := range vs {
			params = append(params, [2]string{k, v})
		}
	}
	for k, v := range map[string]string{"c2": "", "a3": "2 q", "oauth_consumer_key": "9djdj82h48djs9d2", "oauth_token": "kkk9d7dh3k39sjv7",
		"oauth_signature_method": "HMAC-SHA1", "oauth_timestamp": "137131201", "oauth_nonce": "7d8f3e4a"} {
		params = append(params, [2]string{k, v})
	}
	want := "POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk9d7dh3k39sjv7"
	if got := OAuth1BaseString("POST", u, params); got != want {
		t.Fatalf("rfc5849 base string\n got %s\nwant %s", got, want)
	}

	// Query placement and PLAINTEXT.
	c = &Config{Type: "oauth1", OAuth1: &OAuth1Config{ConsumerKey: "ck", ConsumerSecret: "cs&x", SignatureMethod: "PLAINTEXT", InQuery: true}}
	req = mustReq(t, "GET", "http://h/p?x=1", "")
	sign(t, c, req)
	if req.URL.Query().Get("oauth_signature") != "cs%26x&" || req.Header.Get("Authorization") != "" {
		t.Fatalf("plaintext in query: %s", req.URL.RawQuery)
	}
}

// AWS SigV4 test suite "get-vanilla".
func TestSigV4Vanilla(t *testing.T) {
	c := &Config{Type: "aws_sigv4", AWS: &AWSConfig{
		AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		Region: "us-east-1", Service: "service", Timestamp: "20150830T123600Z",
	}}
	req := mustReq(t, "GET", "https://example.amazonaws.com/", "")
	sign(t, c, req)
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("sigv4\n got %s\nwant %s", got, want)
	}
}

// SigV4 with a body, query and session token, checked against an
// independent implementation of the algorithm.
func TestSigV4Independent(t *testing.T) {
	cfg := &AWSConfig{AccessKeyID: "AKID", SecretAccessKey: "SECRET", SessionToken: "TOKEN",
		Region: "eu-west-1", Service: "execute-api", Timestamp: "2024-01-02T03:04:05Z"}
	body := `{"hello":"world"}`
	req := mustReq(t, "POST", "https://api.example.com/v1/items?b=2&a=1", body)
	req.Header.Set("Content-Type", "application/json")
	sign(t, &Config{Type: "aws_sigv4", AWS: cfg}, req)

	amzDate := "20240102T030405Z"
	if req.Header.Get("X-Amz-Date") != amzDate || req.Header.Get("X-Amz-Security-Token") != "TOKEN" {
		t.Fatalf("headers: %v", req.Header)
	}
	ph := sha256.Sum256([]byte(body))
	signed := strings.Split(strings.SplitN(strings.SplitN(req.Header.Get("Authorization"), "SignedHeaders=", 2)[1], ",", 2)[0], ";")
	var canonHeaders strings.Builder
	for _, h := range signed {
		v := req.Header.Get(h)
		switch h {
		case "host":
			v = req.URL.Host
		case "content-length":
			v = fmt.Sprint(req.ContentLength)
		}
		canonHeaders.WriteString(h + ":" + strings.TrimSpace(v) + "\n")
	}
	if !sort.StringsAreSorted(signed) {
		t.Fatalf("signed headers not sorted: %v", signed)
	}
	canon := strings.Join([]string{"POST", "/v1/items", "a=1&b=2", canonHeaders.String(), strings.Join(signed, ";"), hex.EncodeToString(ph[:])}, "\n")
	ch := sha256.Sum256([]byte(canon))
	scope := "20240102/eu-west-1/execute-api/aws4_request"
	sts := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(ch[:])
	mac := func(k []byte, d string) []byte { m := hmac.New(sha256.New, k); m.Write([]byte(d)); return m.Sum(nil) }
	k := mac([]byte("AWS4SECRET"), "20240102")
	k = mac(k, "eu-west-1")
	k = mac(k, "execute-api")
	k = mac(k, "aws4_request")
	sig := hex.EncodeToString(mac(k, sts))
	if !strings.HasSuffix(req.Header.Get("Authorization"), "Signature="+sig) {
		t.Fatalf("independent signature mismatch\n got %s\nwant %s", req.Header.Get("Authorization"), sig)
	}

	// Without GetBody the payload is UNSIGNED-PAYLOAD and the body is untouched.
	req = mustReq(t, "PUT", "https://bucket.s3.amazonaws.com/key", "")
	req.Body = io.NopCloser(strings.NewReader("streamed"))
	req.GetBody = nil
	sign(t, &Config{Type: "aws_sigv4", AWS: &AWSConfig{AccessKeyID: "a", SecretAccessKey: "b", Region: "us-east-1", Service: "s3"}}, req)
	if req.Header.Get("X-Amz-Content-Sha256") != "UNSIGNED-PAYLOAD" {
		t.Fatalf("expected UNSIGNED-PAYLOAD, got %q", req.Header.Get("X-Amz-Content-Sha256"))
	}
	b, _ := io.ReadAll(req.Body)
	if string(b) != "streamed" {
		t.Fatalf("body: %q", b)
	}
}

// Akamai EdgeGrid reference test vectors (AkamaiOPEN-edgegrid testdata).
func TestEdgeGridVectors(t *testing.T) {
	base := EdgeGridConfig{
		ClientToken:   "akab-client-token-xxx-xxxxxxxxxxxxxxxx",
		AccessToken:   "akab-access-token-xxx-xxxxxxxxxxxxxxxx",
		ClientSecret:  "SOMESECRET",
		MaxBody:       2048,
		HeadersToSign: []string{"X-Test1", "X-Test2", "X-Test3"},
		Nonce:         "nonce-xx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
		Timestamp:     "20140321T19:34:21+0000",
	}
	host := "https://akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net"
	cases := []struct {
		name, method, path, body string
		headers                  map[string]string
		sig                      string
	}{
		{"simple GET", "GET", "/", "", nil, "tL+y4hxyHxgWVD30X3pWnGKHcPzmrIF+LThiAOhMxYU="},
		{"GET with querystring", "GET", "/testapi/v1/t1?p1=1&p2=2", "", nil, "hKDH1UlnQySSHjvIcZpDMbQHihTQ0XyVAKZaApabdeA="},
		{"POST inside limit", "POST", "/testapi/v1/t3", "datadatadatadatadatadatadatadata", nil, "hXm4iCxtpN22m4cbZb4lVLW5rhX8Ca82vCFqXzSTPe4="},
		{"simple header signing with GET", "GET", "/testapi/v1/t4", "", map[string]string{"X-Test1": "test-simple-header"}, "8F9AybcRw+PLxnvT+H0JRkjROrrUgsxJTnRXMzqvcwY="},
	}
	secrets := []string{"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx="}
	for _, tc := range cases {
		var got []string
		ok := false
		for _, sec := range secrets {
			cfg := base
			cfg.ClientSecret = sec
			req := mustReq(t, tc.method, host+tc.path, tc.body)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			sign(t, &Config{Type: "akamai_edgegrid", EdgeGrid: &cfg}, req)
			h := req.Header.Get("Authorization")
			got = append(got, h)
			wantPrefix := "EG1-HMAC-SHA256 client_token=akab-client-token-xxx-xxxxxxxxxxxxxxxx;access_token=akab-access-token-xxx-xxxxxxxxxxxxxxxx;timestamp=20140321T19:34:21+0000;nonce=nonce-xx-xxxx-xxxx-xxxx-xxxxxxxxxxxx;signature="
			if !strings.HasPrefix(h, wantPrefix) {
				t.Fatalf("%s: header %s", tc.name, h)
			}
			if strings.HasSuffix(h, "signature="+tc.sig) {
				ok = true
			}
		}
		if !ok {
			t.Errorf("%s: no secret produced signature %s; got %v", tc.name, tc.sig, got)
		}
	}
}

// RFC 7616 §3.9.1 examples (MD5 and SHA-256) and a full challenge round trip.
func TestDigestVectors(t *testing.T) {
	chal := &digest.Challenge{
		Realm: "http-auth@example.org", Nonce: "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
		Opaque: "FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS", QOP: []string{"auth", "auth-int"},
	}
	for alg, want := range map[string]string{
		"MD5":     "8ca523f5e9506fed4657c9700eebdbec",
		"SHA-256": "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1",
	} {
		ch := *chal
		ch.Algorithm = alg
		cred, err := digest.Digest(&ch, digest.Options{Method: "GET", URI: "/dir/index.html", Username: "Mufasa",
			Password: "Circle of Life", Cnonce: "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ", Count: 1})
		if err != nil {
			t.Fatal(err)
		}
		if cred.Response != want {
			t.Fatalf("%s: got %s want %s", alg, cred.Response, want)
		}
	}

	// Round trip: the server verifies the response independently (MD5, qop=auth).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, "Digest ") {
			w.Header().Set("WWW-Authenticate", `Digest realm="`+chal.Realm+`", qop="auth", algorithm=MD5, nonce="`+chal.Nonce+`", opaque="`+chal.Opaque+`"`)
			w.WriteHeader(401)
			return
		}
		p := parseDigest(h)
		md := func(s string) string { s2 := md5.Sum([]byte(s)); return hex.EncodeToString(s2[:]) }
		ha1 := md("Mufasa:" + chal.Realm + ":Circle of Life")
		ha2 := md(r.Method + ":" + p["uri"])
		want := md(ha1 + ":" + chal.Nonce + ":" + p["nc"] + ":" + p["cnonce"] + ":auth:" + ha2)
		if p["response"] != want || p["username"] != "Mufasa" || p["uri"] != r.URL.RequestURI() {
			w.WriteHeader(403)
			return
		}
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "ok:%s", body)
	}))
	defer srv.Close()
	rt, err := NewManager().Transport(http.DefaultTransport, &Config{Type: "digest", Username: "Mufasa", Password: "Circle of Life"}, Env{})
	if err != nil {
		t.Fatal(err)
	}
	cl := &http.Client{Transport: rt}
	resp, err := cl.Post(srv.URL+"/dir/index.html?x=1", "text/plain", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(b) != "ok:payload" {
		t.Fatalf("digest round trip: %d %s", resp.StatusCode, b)
	}
}

func parseDigest(h string) map[string]string {
	out := map[string]string{}
	for _, p := range strings.Split(strings.TrimPrefix(h, "Digest "), ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(p), "=")
		out[k] = strings.Trim(v, `"`)
	}
	return out
}
