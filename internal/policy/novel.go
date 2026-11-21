package policy

import (
	"fmt"
	"net/url"
	"strings"
	"unicode"
)

// tainted-egress-novel-data turns the question around. Instead of looking
// for pieces of the secret in what leaves (a denylist that lost to
// short-pieces, path-split and value-first-split), it allows only content
// from trusted sources: the user's task and the allowlist. Anything else
// in the content (WHAT) of an egress call to a destination the user did
// not name is new data, and is denied, however short.
// See docs/adr/0001-allowlist-egress-over-fragment-matching.md.

// QueryParts returns each query key, each query value and the #fragment of
// u as separate strings. If the query does not parse, it is returned raw.
func QueryParts(u *url.URL) []string {
	out := []string{u.Fragment}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return append(out, u.RawQuery)
	}
	for k, vs := range q {
		out = append(out, k)
		out = append(out, vs...)
	}
	return out
}

// what returns the content parts of an egress call: subject and body of
// an email; path segments, query keys and values and fragment of a URL.
// Scheme and host are WHERE, judged by the domain rules.
func what(r Request) []string {
	switch r.Tool {
	case "send_email":
		return []string{r.Subject, r.Body}
	case "web_fetch":
		u, err := url.Parse(r.URL)
		if err != nil {
			return []string{r.URL}
		}
		return append(strings.Split(u.Path, "/"), QueryParts(u)...)
	}
	return nil
}

func isWordRune(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }

// novelData reports whether the call carries content that is not made of
// trusted words and trusted punctuation. Callers check the context is
// tainted and the destination was not named by the user.
func novelData(r Request) (Decision, bool) {
	trusted := strings.Join(append([]string{r.UserTask}, r.AllowedDomains...), " ")
	words := map[string]bool{}
	for _, w := range strings.FieldsFunc(strings.ToLower(trusted), func(c rune) bool { return !isWordRune(c) }) {
		words[w] = true
	}
	for _, part := range what(r) {
		for _, w := range strings.FieldsFunc(strings.ToLower(part), func(c rune) bool { return !isWordRune(c) }) {
			if !words[w] {
				return novel(w), true
			}
		}
		// Punctuation can carry bits too ("-_-_"), so it must also come
		// from the trusted text.
		for _, c := range part {
			if !isWordRune(c) && !unicode.IsSpace(c) && !strings.ContainsRune(trusted, c) {
				return novel(string(c)), true
			}
		}
	}
	return Decision{}, false
}

func novel(s string) Decision {
	if len(s) > 12 {
		s = s[:12] + "..."
	}
	return Decision{Deny, "tainted-egress-novel-data",
		fmt.Sprintf("context holds untrusted data and the call carries content the user never gave (%q)", s)}
}
