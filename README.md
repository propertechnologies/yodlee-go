# yodlee-go
swagger-go generated yodlee client library for golang with an example of how to use it

```
package main

import (
	"encoding/pem"
	"log"
	"net/http"
	"os"
	"time"

	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"

	"github.com/go-openapi/strfmt"

	"golang.org/x/oauth2/jws"

	yodlee "github.com/propertechnologies/yodlee-go/client"
	"github.com/propertechnologies/yodlee-go/client/accounts"

	httptransport "github.com/go-openapi/runtime/client"
)

type YodleeRoundTripper struct {
	r http.RoundTripper
}

// Api-Version header must be manually added to all requests
func (rt YodleeRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	r.Header.Add("Api-Version", "1.1")
	return rt.r.RoundTrip(r)
}

func main() {
	// This string MUST have newline characters before and after "-----BEGIN PRIVATE KEY------" 
  // or it won't parse. If you see \n characters in the printf, you didn't export the vars correctly.
	os.Getenv("YODLEE_SANDBOX_PRIVATE_KEY")
	log.Printf("key = \n%s", k)
	key := []byte(k)

	claims := &jws.ClaimSet{
		Iss: os.Getenv("YODLEE_SANDBOX_ISSUER_ID"),
		Iat: time.Now().Unix(),
		Exp: time.Now().Unix() + 1800,
		Sub: "<USER_ID>",
	}
	headers := &jws.Header{
		Algorithm: "RS512",
		Typ:       "JWT",
	}
	var err error
	privPem, _ := pem.Decode(key)

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS8PrivateKey(privPem.Bytes); err != nil {
		panic(err)
	}

	var privateKey *rsa.PrivateKey
	var ok bool
	privateKey, ok = parsedKey.(*rsa.PrivateKey)
	if !ok {
		panic("Failed to parse key")
	}
  // We need to create a custom signer, the default one uses sha256, yodlee uses sha512
	sg := func(data []byte) (sig []byte, err error) {
		h := sha512.New()
		h.Write(data)
		return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA512, h.Sum(nil))
	}
	ss, err := jws.EncodeWithSigner(headers, claims, sg)
	if err != nil {
		panic(err)
	}
  // This endpoint will change depending on environment
	t := httptransport.New("sandbox.api.yodlee.com", "/ysl", []string{"https"})
	var yRoundTripper http.RoundTripper = YodleeRoundTripper{r: http.DefaultTransport}
	t.Transport = yRoundTripper
	t.DefaultAuthentication = httptransport.BearerToken(ss)
	c := yodlee.New(t, strfmt.Default)

	resp, err := c.Accounts.GetAllAccounts(accounts.NewGetAllAccountsParams())
	if err != nil {
		panic(err)
	}
	log.Printf("accounts = %+v\n", resp.Payload)
	log.Printf("error = %s\n", resp.Error())
}
```
