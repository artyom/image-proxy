// Command image-proxy implements proxy fetching images on http:// urls.
//
// It's intended to run behind a https-enabled CDN and can be used to fetch
// images over non-https urls to avoid "mixed content" warnings on a https page.
//
// API accepts mandatory argument "u" which must be a full url to image
// resource. If url has https schema, image-proxy issues redirect to this url,
// if url is plain http, it requests that resource, verifies that its
// Content-Type is indeed image and proxies resource directly to client, also
// adding Cache-Control headers so that CDN can cache such request.
//
// Non-empty -secret flag enables HMAC verification of provided input: key is
// derived as a sha1 hash of provided secret; each request then must have
// additional "h" argument which must be a sha1-based HMAC signature of "u"
// argument value encoded as base64 url-friendly unpadded encoding (RFC 4648).
//
// Example code generating signed url:
//
//	proxy := `https://cdn.example.com/` // CDN serving over HTTPS
//	imageURL := `http://example.com/image.jpg` // plain HTTP site
//	secret := `foobar`
//	key := sha1.Sum([]byte(secret))
//	mac := hmac.New(sha1.New, key[:])
//	mac.Write([]byte(imageURL))
//	vals := make(url.Values)
//	vals.Set("u", imageURL)
//	vals.Set("h", base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
//	finalURL := proxy + "?" + vals.Encode()
package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/artyom/autoflags"
	"github.com/artyom/useragent"
)

func main() {
	args := runArgs{
		Addr: "localhost:8080",
	}
	autoflags.Parse(&args)
	if err := run(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type runArgs struct {
	Addr   string `flag:"addr,address to listen"`
	Secret string `flag:"secret,used to verify HMAC signature"`
}

func run(args runArgs) error {
	var key []byte
	if args.Secret != "" {
		b := sha1.Sum([]byte(args.Secret))
		key = b[:]
	}
	server := &http.Server{
		Addr:           args.Addr,
		Handler:        handler(key),
		ReadTimeout:    5 * time.Second,
		IdleTimeout:    30 * time.Second,
		WriteTimeout:   2 * time.Minute,
		MaxHeaderBytes: 1 << 16,
	}
	return server.ListenAndServe()
}

func handler(key []byte) http.Handler {
	client := &http.Client{
		Transport: useragent.Set(http.DefaultTransport, userAgent),
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		vals, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		s := vals.Get("u")
		if s == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		if key != nil {
			messageMAC, err := base64.RawURLEncoding.DecodeString(vals.Get("h"))
			if err != nil || !checkMAC([]byte(s), messageMAC, key) {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}
		}
		u, err := url.Parse(s)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		switch u.Scheme {
		case "https":
			http.Redirect(w, r, u.String(), http.StatusMovedPermanently)
			return
		case "http":
		default:
			http.Error(w, http.StatusText(http.StatusUnprocessableEntity), http.StatusUnprocessableEntity)
			return
		}
		req, err := http.NewRequest(http.MethodGet, u.String(), nil)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		req = req.WithContext(r.Context())
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusOK:
		case http.StatusGone,
			http.StatusNotFound,
			http.StatusTooManyRequests,
			http.StatusUnavailableForLegalReasons:
			http.Error(w, http.StatusText(resp.StatusCode), resp.StatusCode)
			return
		default:
			http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
			return
		}
		const cType = `Content-Type`
		if !strings.HasPrefix(strings.ToLower(resp.Header.Get(cType)), "image/") {
			http.Error(w, http.StatusText(http.StatusNotAcceptable), http.StatusNotAcceptable)
			return
		}
		w.Header().Set(cType, resp.Header.Get(cType))
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "max-age=31536000, public")
		if i := r.ContentLength; i > 0 {
			w.Header().Set("Content-Length", strconv.FormatInt(i, 10))
		}
		io.Copy(w, resp.Body)
	})
}

func checkMAC(message, messageMAC, key []byte) bool {
	mac := hmac.New(sha1.New, key) // TODO: use free list
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}

const userAgent = `ImageProxy: github.com/artyom/image-proxy`
