package guardian

import (
	"net/url"
	"regexp"
	"strings"
)

var sensitiveQueryKeys = map[string]struct{}{
	"access_token": {}, "api_key": {}, "apikey": {}, "api-key": {}, "authorization": {},
	"auth": {}, "authsig": {}, "client_secret": {}, "code": {}, "id_token": {}, "jwt": {},
	"key": {}, "pass": {}, "passwd": {}, "password": {}, "pwd": {}, "refresh_token": {},
	"secret": {}, "session": {}, "sessionid": {}, "sid": {}, "sig": {}, "signature": {},
	"token": {}, "x-amz-signature": {}, "x-amz-credential": {},
}

// sensitiveQueryRE is the fallback when the query can't be parsed (a bad
// escape makes url.ParseQuery fail, which used to leave it unredacted).
var sensitiveQueryRE = regexp.MustCompile(`(?i)([?&;](?:access_token|api_key|apikey|api-key|authorization|auth|authsig|client_secret|code|id_token|jwt|key|pass|passwd|password|pwd|refresh_token|secret|session|sessionid|sid|sig|signature|token|x-amz-signature|x-amz-credential)=)[^&;#]*`)

// redactRequestURI replaces common credential-bearing query values before a
// request is persisted or streamed in the block log. The path and safe query
// parameters remain available for troubleshooting.
func redactRequestURI(raw string) string {
	u, err := url.ParseRequestURI(raw)
	if err != nil {
		return sensitiveQueryRE.ReplaceAllString(raw, "${1}REDACTED")
	}
	if u.RawQuery == "" {
		return raw
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return sensitiveQueryRE.ReplaceAllString(raw, "${1}REDACTED")
	}
	changed := false
	for key := range query {
		if _, ok := sensitiveQueryKeys[strings.ToLower(key)]; ok {
			query[key] = []string{"REDACTED"}
			changed = true
		}
	}
	if !changed {
		return raw
	}
	u.RawQuery = query.Encode()
	return u.String()
}
