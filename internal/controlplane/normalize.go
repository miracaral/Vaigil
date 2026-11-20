package controlplane

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"
)

// maxDecodeDepth is how many encoding layers we peel off. Each layer
// multiplies the work, so the limit is a trade-off; data encoded more
// times than this is not seen (see TestFourLayersExceedTheLimit).
const maxDecodeDepth = 3

// Runs of characters that could be base64 (standard or URL-safe) or hex.
// "=" is left out: it is base64 padding, but in a URL it also separates
// a key from its value. "/" is base64 but also a path separator, so we
// try runs both with and without it.
var (
	encodedRun     = regexp.MustCompile(`[A-Za-z0-9+/_-]{8,}`)
	encodedRunNoSl = regexp.MustCompile(`[A-Za-z0-9+_-]{8,}`)
)

var decoders = []func(string) ([]byte, error){
	base64.RawStdEncoding.DecodeString,
	base64.RawURLEncoding.DecodeString,
	hex.DecodeString,
}

// decodings returns s plus every string reachable from it by up to
// maxDecodeDepth rounds of URL, base64 and hex decoding.
func decodings(s string) []string {
	all := []string{s}
	seen := map[string]bool{s: true}
	layer := []string{s}
	for depth := 0; depth < maxDecodeDepth; depth++ {
		var next []string
		for _, v := range layer {
			for _, d := range decodeOnce(v) {
				if !seen[d] {
					seen[d] = true
					next = append(next, d)
				}
			}
		}
		all = append(all, next...)
		layer = next
	}
	return all
}

// decodeOnce peels one layer: the whole string URL-decoded, and every
// encoded-looking run inside it decoded as base64 or hex.
func decodeOnce(s string) []string {
	var out []string
	if u, err := url.QueryUnescape(s); err == nil && u != s {
		out = append(out, u)
	}
	runs := append(encodedRun.FindAllString(s, -1), encodedRunNoSl.FindAllString(s, -1)...)
	for _, run := range runs {
		for _, decode := range decoders {
			if b, err := decode(run); err == nil {
				out = append(out, string(b))
			}
		}
	}
	return out
}
