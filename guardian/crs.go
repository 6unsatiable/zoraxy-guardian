package guardian

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"

	plugin "example.com/guardian/mod/zoraxy_plugin"
)

// WAFEngine runs the OWASP Core Rule Set (via Coraza) over every request's
// URI, query arguments and headers. Request bodies are not available to a
// Zoraxy sniff handler, so body inspection is off.
type WAFEngine struct {
	Enabled bool `json:"enabled"`
	// ParanoiaLevel 1-4: higher catches more and false-positives more.
	ParanoiaLevel int `json:"paranoia_level"`
	// AnomalyThreshold is CRS's inbound anomaly score that blocks (5 =
	// one critical match).
	AnomalyThreshold int `json:"anomaly_threshold"`
	// Exclusions turn off CRS rules for a host and/or path prefix, the
	// usual way to fix a false positive.
	Exclusions []WAFExclusion `json:"exclusions"`
}

// WAFExclusion removes RuleIDs ("942100" or a range "942000-942999") for
// requests to Hosts (globs, empty = all) whose path starts with PathPrefix
// (empty = any path).
type WAFExclusion struct {
	Hosts      []string `json:"hosts,omitempty"`
	PathPrefix string   `json:"path_prefix,omitempty"`
	RuleIDs    []string `json:"rule_ids"`
}

var ruleIDPattern = regexp.MustCompile(`^\d{1,7}(-\d{1,7})?$`)

// crsAllowedContentTypes is CRS's default list plus the types the proxied
// apps actually send (WebRTC SDP offers, binary uploads, ndjson streams).
const crsAllowedContentTypes = `|application/x-www-form-urlencoded| |multipart/form-data| |multipart/related| |text/xml| |application/xml| |application/soap+xml| |application/json| |application/cloudevents+json| |application/cloudevents-batch+json| |application/sdp| |application/octet-stream| |text/plain| |application/x-ndjson| |application/grpc-web+proto| |application/x-protobuf|`

func crsDirectives(cfg WAFEngine) string {
	pl := cfg.ParanoiaLevel
	if pl < 1 || pl > 4 {
		pl = 1
	}
	threshold := cfg.AnomalyThreshold
	if threshold < 1 {
		threshold = 5
	}
	var b strings.Builder
	// @coraza.conf-recommended is skipped: it uses directives newer than
	// this Coraza and only configures body handling, which is off.
	b.WriteString("SecRuleEngine On\nSecRequestBodyAccess Off\nSecResponseBodyAccess Off\nSecAuditEngine Off\n")
	b.WriteString("Include @crs-setup.conf.example\n")
	fmt.Fprintf(&b, "SecAction \"id:900000,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=%d\"\n", pl)
	fmt.Fprintf(&b, "SecAction \"id:900110,phase:1,pass,nolog,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=4\"\n", threshold)
	b.WriteString("SecAction \"id:900200,phase:1,pass,nolog,setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE PROPFIND MKCOL COPY MOVE'\"\n")
	fmt.Fprintf(&b, "SecAction \"id:900220,phase:1,pass,nolog,setvar:'tx.allowed_request_content_type=%s'\"\n", crsAllowedContentTypes)
	// Exclusions run in phase 1 before any CRS rule, removing the listed
	// rules for the rest of the transaction.
	for i, ex := range cfg.Exclusions {
		var ctl []string
		for _, id := range ex.RuleIDs {
			if ruleIDPattern.MatchString(id) {
				ctl = append(ctl, "ctl:ruleRemoveById="+id)
			}
		}
		if len(ctl) == 0 {
			continue
		}
		id := 1000 + i*2
		var conds []string
		if len(ex.Hosts) > 0 {
			var alts []string
			for _, h := range ex.Hosts {
				alts = append(alts, hostGlobRegex(h))
			}
			conds = append(conds, fmt.Sprintf(`SERVER_NAME "@rx ^(?:%s)$"`, strings.Join(alts, "|")))
		}
		if ex.PathPrefix != "" {
			conds = append(conds, fmt.Sprintf(`REQUEST_FILENAME "@beginsWith %s"`, strings.ReplaceAll(ex.PathPrefix, `"`, "")))
		}
		if len(conds) == 0 {
			conds = []string{`REQUEST_LINE "@unconditionalMatch"`}
		}
		for j, c := range conds {
			actions := fmt.Sprintf("id:%d,phase:1,pass,nolog", id)
			if j > 0 {
				actions = "t:none"
			}
			if j < len(conds)-1 {
				actions += ",chain"
			} else {
				actions += "," + strings.Join(ctl, ",")
			}
			fmt.Fprintf(&b, "SecRule %s \"%s\"\n", c, actions)
		}
	}
	b.WriteString("Include @owasp_crs/REQUEST-*.conf\n")
	return b.String()
}

// hostGlobRegex turns a host glob (*.example.com) into a lowercase regex.
func hostGlobRegex(g string) string {
	return strings.ReplaceAll(regexp.QuoteMeta(strings.ToLower(g)), `\*`, `[^.]*`)
}

func newCRS(cfg WAFEngine) (coraza.WAF, error) {
	return coraza.NewWAF(coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithDirectives(crsDirectives(cfg)))
}

// crsCheck runs the request through CRS and returns a block reason such as
// "crs-942100 SQL Injection Attack Detected via libinjection", or "".
func crsCheck(waf coraza.WAF, req *plugin.DynamicSniffForwardRequest, ip string) string {
	if waf == nil {
		return ""
	}
	tx := waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		_ = tx.Close()
	}()
	tx.ProcessConnection(ip, 0, "", 443)
	uri := req.RequestURI
	if uri == "" {
		uri = req.URL
	}
	proto := req.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	tx.ProcessURI(uri, req.Method, proto)
	tx.SetServerName(strings.ToLower(hostOnly(req.Host)))
	tx.AddRequestHeader("Host", req.Host)
	keys := make([]string, 0, len(req.Header))
	for k := range req.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strings.EqualFold(k, "Host") {
			continue
		}
		for _, v := range req.Header[k] {
			tx.AddRequestHeader(k, v)
		}
	}
	it := tx.ProcessRequestHeaders()
	if it == nil {
		var err error
		it, err = tx.ProcessRequestBody()
		if err != nil {
			return ""
		}
	}
	if it == nil {
		return ""
	}
	return crsReason(it, tx.MatchedRules())
}

// crsReason names the highest-severity matched detection rule (not the
// 949 anomaly-evaluation rule that did the actual blocking).
func crsReason(it *types.Interruption, matched []types.MatchedRule) string {
	best := -1
	bestSev := 99
	for i, m := range matched {
		id := m.Rule().ID()
		if id < 910000 || id >= 949000 || m.Message() == "" {
			continue
		}
		if sev := int(m.Rule().Severity()); sev < bestSev {
			best, bestSev = i, sev
		}
	}
	if best < 0 {
		return "crs-" + strconv.Itoa(it.RuleID)
	}
	msg := matched[best].Message()
	if len(msg) > 80 {
		msg = msg[:80]
	}
	return fmt.Sprintf("crs-%d %s", matched[best].Rule().ID(), msg)
}

func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

func validateWAFEngine(cfg WAFEngine) error {
	if cfg.ParanoiaLevel < 0 || cfg.ParanoiaLevel > 4 {
		return fmt.Errorf("WAF paranoia level must be 1-4")
	}
	for i, ex := range cfg.Exclusions {
		if len(ex.RuleIDs) == 0 {
			return fmt.Errorf("WAF exclusion %d has no rule IDs", i+1)
		}
		for _, id := range ex.RuleIDs {
			if !ruleIDPattern.MatchString(id) {
				return fmt.Errorf("WAF exclusion %d: bad rule ID %q", i+1, id)
			}
		}
		if ex.PathPrefix != "" && !strings.HasPrefix(ex.PathPrefix, "/") {
			return fmt.Errorf("WAF exclusion %d: path prefix must start with /", i+1)
		}
	}
	return nil
}

// WAFEngineStatus is reported by /api/status.
type WAFEngineStatus struct {
	Loaded bool   `json:"loaded"`
	Error  string `json:"error,omitempty"`
}

func (s *Store) WAFEngineStatus() WAFEngineStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return WAFEngineStatus{Loaded: s.crs != nil, Error: s.crsErr}
}
