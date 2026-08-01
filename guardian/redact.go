package guardian

import (
	"net/url"
	"strings"
)

var sensitiveQueryKeys = map[string]struct{}{
	"access_token": {}, "api_key": {}, "apikey": {}, "authorization": {},
	"code": {}, "id_token": {}, "passwd": {}, "password": {}, "secret": {},
	"token": {},
}

// redactRequestURI replaces common credential-bearing query values before a
// request is persisted or streamed in the block log. The path and safe query
// parameters remain available for troubleshooting.
func redactRequestURI(raw string) string {
	u, err := url.ParseRequestURI(raw)
	if err != nil || u.RawQuery == "" {
		return raw
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return raw
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
