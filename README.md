# stackpath-urlauth
Golang library to sign Stackpath CDN URLs.  This prevents tampering and allows for automatic expiration of URLs.

Details on the Stackpath 'Secure Tokens' feature are available on the [Stackpath Support](https://support.securecdn.stackpath.com/hc/en-us/articles/115001618928-How-to-Setup-a-Secure-Token) site.

## Example
```go
import ("github.com/muxinc/stackpath-urlauth/urlauth")

inputURL := "https://www.example.com/foo?client_id=abc123&foo=bar"
secret := "supersecret"
expirationTime := startTime.Add(time.Hour * 6)
signedURL, err := urlauth.SignURL(inputURL, secret, expirationTime)
```
