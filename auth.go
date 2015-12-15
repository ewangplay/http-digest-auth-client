package httpDigestAuth

import (
	"fmt"
	"io/ioutil"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
)

// DigestAuthClient tracks the state of authentication
type DigestAuthClient struct {
	Realm     string
	Qop       string
	Method    string
	Nonce     string
	Opaque    string
	Algorithm string
	HA1       string
	HA2       string
	Cnonce    string
	Path      string
	Nc        int16
	Username  string
	Password  string
}

func NewDigestAuthClient(realm string, username string, password string) (*DigestAuthClient, error) {
    client := &DigestAuthClient{}
    client.Realm = realm
    client.Username = username
    client.Password = password
    return client, nil
}

func (d *DigestAuthClient) digestChecksum() {
	switch d.Algorithm {
	case "MD5":
		// A1
		h := md5.New()
		A1 := fmt.Sprintf("%s:%s:%s", d.Username, d.Realm, d.Password)
		io.WriteString(h, A1)
		d.HA1 = fmt.Sprintf("%x", h.Sum(nil))

		// A2
		h = md5.New()
		A2 := fmt.Sprintf("%s:%s", d.Method, d.Path)
		io.WriteString(h, A2)
		d.HA2 = fmt.Sprintf("%x", h.Sum(nil))
	case "MD5-sess":
	default:
		//token
	}
}

// applyAuth adds proper auth header to the passed request
func (d *DigestAuthClient) applyAuth(req *http.Request) {
	d.Nc += 0x1
	d.Cnonce = randomKey()
	d.Method = req.Method
	d.Path = req.URL.RequestURI()
	d.digestChecksum()
	response := h(strings.Join([]string{d.HA1, d.Nonce, fmt.Sprintf("%08x", d.Nc),
		d.Cnonce, d.Qop, d.HA2}, ":"))
	AuthHeader := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", cnonce="%s", nc=%08x, qop=%s, response="%s", algorithm=%s`,
		d.Username, d.Realm, d.Nonce, d.Path, d.Cnonce, d.Nc, d.Qop, response, d.Algorithm)
	if d.Opaque != "" {
		AuthHeader = fmt.Sprintf(`%s, opaque="%s"`, AuthHeader, d.Opaque)
	}
	fmt.Printf("%v\n", AuthHeader)
	req.Header.Set("Authorization", AuthHeader)
}

// Auth authenticates against a given URI
func (d *DigestAuthClient) Auth(client *http.Client, req *http.Request) (resp_body []byte, err error) {

	resp, err := client.Do(req)
	if err != nil {
		return
	}

	if resp.StatusCode == 401 {

		authn := digestAuthParams(resp)
		resp.Body.Close()

		algorithm := authn["algorithm"]
		d.Method = req.Method
		d.Path = req.URL.RequestURI()
		d.Realm = authn["realm"]
		d.Qop = authn["qop"]
		d.Nonce = authn["nonce"]
		d.Opaque = authn["opaque"]
		if algorithm == "" {
			d.Algorithm = "MD5"
		} else {
			d.Algorithm = authn["algorithm"]
		}
		d.Nc = 0x0

		d.applyAuth(req)
		resp, err = client.Do(req)
		if err != nil {
			return
		}

		if resp.StatusCode == 200 {
			goto SUCC

		} else {
			err = fmt.Errorf("response status code was %v", resp.StatusCode)
			return
		}

	} else if resp.StatusCode == 200 {
		goto SUCC

	} else {
		err = fmt.Errorf("response status code was %v", resp.StatusCode)
		return
	}

SUCC:
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("read http body error: %v\n", err)
		return
	}
	resp.Body.Close()

	return body, nil
}

/*
Parse Authorization header from the http.Request. Returns a map of
auth parameters or nil if the header is not a valid parsable Digest
auth header.
*/
func digestAuthParams(r *http.Response) map[string]string {
	s := strings.SplitN(r.Header.Get("Www-Authenticate"), " ", 2)
	if len(s) != 2 || s[0] != "Digest" {
		return nil
	}

	result := map[string]string{}
	for _, kv := range strings.Split(s[1], ",") {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		result[strings.Trim(parts[0], "\" ")] = strings.Trim(parts[1], "\" ")
	}
	return result
}

func randomKey() string {
	k := make([]byte, 12)
	for bytes := 0; bytes < len(k); {
		n, err := rand.Read(k[bytes:])
		if err != nil {
			panic("rand.Read() failed")
		}
		bytes += n
	}
	return base64.StdEncoding.EncodeToString(k)
}

/*
H function for MD5 algorithm (returns a lower-case hex MD5 digest)
*/
func h(data string) string {
	digest := md5.New()
	digest.Write([]byte(data))
	return fmt.Sprintf("%x", digest.Sum(nil))
}
