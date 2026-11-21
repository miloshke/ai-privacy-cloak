// Package detect finds secrets and PII in free-form text: credential
// patterns (AWS/GitHub/Stripe/Google/Slack/npm/SendGrid/Twilio/Anthropic/
// OpenAI keys, PEM private key blocks, JWTs, generic high-entropy strings)
// plus PII (email, phone, IPv4, credit card numbers, IBANs, SSNs, US bank
// routing numbers). It has no ML dependency on purpose - regex +
// entropy/checksum scoring covers the sharpest pain point (credentials
// leaking from repo files into agent context) at effectively zero latency.
package detect

import (
	"math"
	"regexp"
	"sort"
	"strings"
)

type Kind string

const (
	KindAWSAccessKey    Kind = "AWS_ACCESS_KEY"
	KindGitHubToken     Kind = "GITHUB_TOKEN"
	KindStripeKey       Kind = "STRIPE_KEY"
	KindJWT             Kind = "JWT"
	KindGenericAPIKey   Kind = "GENERIC_API_KEY"
	KindHighEntropy     Kind = "HIGH_ENTROPY_SECRET"
	KindEmail           Kind = "EMAIL"
	KindPhone           Kind = "PHONE"
	KindIPv4            Kind = "IPV4"
	KindCreditCard      Kind = "CREDIT_CARD"
	KindIBAN            Kind = "IBAN"
	KindPrivateKey      Kind = "PRIVATE_KEY"
	KindGoogleAPIKey    Kind = "GOOGLE_API_KEY"
	KindSlackToken      Kind = "SLACK_TOKEN"
	KindNpmToken        Kind = "NPM_TOKEN"
	KindSendGridKey     Kind = "SENDGRID_KEY"
	KindTwilioKey       Kind = "TWILIO_KEY"
	KindAnthropicKey    Kind = "ANTHROPIC_API_KEY"
	KindOpenAIKey       Kind = "OPENAI_API_KEY"
	KindSSN             Kind = "SSN"
	KindUSRoutingNumber Kind = "US_ROUTING_NUMBER"
)

// Rule matches one secret/PII shape. MinEntropy, when non-zero, additionally
// requires the matched text's Shannon entropy to clear the threshold before
// it counts as a hit - this is what lets KindHighEntropy catch opaque
// tokens without flagging ordinary long words or identifiers. Validate,
// when set, is a second, stronger gate than entropy: a checksum the value
// must satisfy (Luhn for card numbers, mod-97 for IBANs), which rejects
// almost all accidental matches (order IDs, tracking numbers) that merely
// look the right shape. MaxLength, when non-zero, rejects the *entire*
// match if it's longer than that - this is deliberately not the same as
// bounding the regex's own repetition count: a bounded quantifier still
// lets FindAll fragment one long run into many shorter matches that
// collectively cover almost all of it (verified: a base64 image blob did
// exactly that). Matching the full unbounded run first and then
// discarding it whole if it's implausibly long is what actually prevents
// a large binary blob from being treated as a pile of smaller secrets.
type Rule struct {
	Kind       Kind
	Pattern    *regexp.Regexp
	MinEntropy float64
	MaxLength  int
	Validate   func(raw string) bool
}

type Match struct {
	Kind  Kind
	Start int
	End   int
	Value string
}

var defaultRules = []Rule{
	{Kind: KindAWSAccessKey, Pattern: regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{Kind: KindGitHubToken, Pattern: regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`)},
	{Kind: KindStripeKey, Pattern: regexp.MustCompile(`\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b`)},
	{Kind: KindJWT, Pattern: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`)},
	{Kind: KindGenericAPIKey, Pattern: regexp.MustCompile(`(?i)(?:api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*['"]?([A-Za-z0-9_\-/+=]{16,})['"]?`)},
	{Kind: KindEmail, Pattern: regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)},
	// Requires an actual delimiter (parens, dashes/dots/spaces, or a
	// leading country code) between groups - a bare run of 10+ digits
	// (UUIDs, order IDs, timestamps) must not match, since that's a much
	// more common shape in repo content than an undelimited phone number.
	{Kind: KindPhone, Pattern: regexp.MustCompile(`\(\d{3}\)[-.\s]?\d{3}[-.\s]?\d{4}\b|\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b|\+\d{1,3}[-.\s]?\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b`)},
	{Kind: KindIPv4, Pattern: regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)},
	// 13-19 digits (the valid card-number length range), optionally
	// space/dash grouped like real cards are. Luhn is what actually does
	// the filtering here - without it this would fire on any long digit
	// run (order IDs, phone numbers, timestamps).
	{Kind: KindCreditCard, Pattern: regexp.MustCompile(`\b\d(?:[ -]?\d){12,18}\b`), Validate: luhnValid},
	// ISO 13616: 2-letter country code + 2 check digits + up to 30
	// alphanumeric BBAN chars. The mod-97 checksum (Validate) is what
	// actually confirms it's an IBAN and not just an uppercase code-looking
	// string of the right length.
	{Kind: KindIBAN, Pattern: regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b`), Validate: ibanValid},
	// Bounded by a literal header/footer, so this is essentially
	// zero-false-positive - and SSH/TLS private keys accidentally sitting
	// in a repo are one of the most damaging things a coding agent could
	// read and paste into context.
	{Kind: KindPrivateKey, Pattern: regexp.MustCompile(`-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----(?s:.*?)-----END (?:[A-Z]+ )?PRIVATE KEY-----`)},
	{Kind: KindGoogleAPIKey, Pattern: regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35,}\b`)},
	{Kind: KindSlackToken, Pattern: regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`)},
	{Kind: KindNpmToken, Pattern: regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36,}\b`)},
	{Kind: KindSendGridKey, Pattern: regexp.MustCompile(`\bSG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b`)},
	{Kind: KindTwilioKey, Pattern: regexp.MustCompile(`\bAC[0-9a-fA-F]{32}\b`)},
	// Anthropic's rule must stay ahead of OpenAI's in this list: OpenAI's
	// pattern below is broad enough to also match "sk-ant-..." keys, and
	// the dedupe pass in Scan keeps whichever same-span match was added
	// first when two rules tie on position and length.
	{Kind: KindAnthropicKey, Pattern: regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_\-]{20,}\b`)},
	{Kind: KindOpenAIKey, Pattern: regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b`)},
	// Requires dashes, same reasoning as KindPhone: a bare 9-digit run is
	// far more likely to be a tracking/order ID than an SSN written out
	// in full, so only the delimited NNN-NN-NNNN form counts.
	{Kind: KindSSN, Pattern: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`), Validate: ssnPlausible},
	// Bank routing numbers are conventionally written as a bare 9-digit
	// run with no separators, so unlike SSN/phone there's no delimiter to
	// require - the ABA checksum (Validate) is what filters out ordinary
	// 9-digit numbers that just happen to be the right length.
	{Kind: KindUSRoutingNumber, Pattern: regexp.MustCompile(`\b\d{9}\b`), Validate: routingNumberValid},
	// Pattern itself is intentionally unbounded ({24,}, no upper limit) -
	// MaxLength rejects the whole match afterward if it's too long,
	// rather than bounding the regex's own repetition count. Those are
	// not equivalent: a bounded quantifier ({24,256}) still lets FindAll
	// fragment one long run into many shorter matches that collectively
	// cover almost all of it (verified: a 100KB base64 image blob
	// fragmented into ~590-1900 matches covering 80-99.998% of it
	// depending on exactly how the bound interacted with where "+"/"/"
	// happened to fall - fixing the symptom, not the cause). Matching
	// the full run first and discarding that entire match post-hoc is
	// what actually prevents a large binary blob (base64 image, PDF,
	// any attachment) from being treated as a pile of smaller secrets:
	// FindAll consumes the whole oversized run in one match attempt
	// (greedy + \b only permits ending at the run's true end), that one
	// match gets thrown away for being too long, and scanning resumes
	// after it - zero matches from the blob, not a fragmented mess of them.
	{Kind: KindHighEntropy, Pattern: regexp.MustCompile(`\b[A-Za-z0-9+/_\-]{24,}\b`), MinEntropy: 4.0, MaxLength: 256},
}

// ssnPlausible rejects area/group/serial combinations the Social
// Security Administration has never issued (area 000/666/9xx, group 00,
// serial 0000). Unlike Luhn or mod-97, there's no real checksum for an
// SSN - this is a plausibility filter, not proof the number is real or
// in use.
func ssnPlausible(raw string) bool {
	digits := onlyDigits(raw)
	if len(digits) != 9 {
		return false
	}
	area, group, serial := digits[0:3], digits[3:5], digits[5:9]
	if area == "000" || area == "666" || area[0] == '9' {
		return false
	}
	if group == "00" || serial == "0000" {
		return false
	}
	return true
}

// routingNumberValid implements the ABA routing number checksum:
// 3*(d1+d4+d7) + 7*(d2+d5+d8) + 1*(d3+d6+d9) must be divisible by 10.
func routingNumberValid(raw string) bool {
	digits := onlyDigits(raw)
	if len(digits) != 9 {
		return false
	}
	d := make([]int, 9)
	for i, c := range digits {
		d[i] = int(c - '0')
	}
	sum := 3*(d[0]+d[3]+d[6]) + 7*(d[1]+d[4]+d[7]) + 1*(d[2]+d[5]+d[8])
	return sum%10 == 0
}

// luhnValid implements the Luhn checksum used by all major card networks.
func luhnValid(raw string) bool {
	digits := onlyDigits(raw)
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		n := int(digits[i] - '0')
		if double {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		double = !double
	}
	return sum%10 == 0
}

// ibanValid implements the ISO 7064 MOD97-10 checksum: move the first 4
// characters to the end, convert letters to numbers (A=10 ... Z=35), and
// the whole thing must be congruent to 1 mod 97. Computed digit-by-digit
// so it never needs a big-integer type.
func ibanValid(raw string) bool {
	s := strings.ToUpper(strings.ReplaceAll(raw, " ", ""))
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	rearranged := s[4:] + s[:4]
	rem := 0
	for _, ch := range rearranged {
		switch {
		case ch >= '0' && ch <= '9':
			rem = (rem*10 + int(ch-'0')) % 97
		case ch >= 'A' && ch <= 'Z':
			n := int(ch-'A') + 10 // A=10 ... Z=35
			rem = (rem*10 + n/10) % 97
			rem = (rem*10 + n%10) % 97
		default:
			return false
		}
	}
	return rem == 1
}

func onlyDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

type Detector struct {
	rules []Rule
}

func New() *Detector {
	return &Detector{rules: defaultRules}
}

// Scan returns every match in text, sorted by position, with overlapping
// matches from less-specific rules (e.g. HIGH_ENTROPY_SECRET inside an
// already-matched GENERIC_API_KEY) collapsed into the earliest/longest one.
func (d *Detector) Scan(text string) []Match {
	var matches []Match
	for _, r := range d.rules {
		for _, loc := range r.Pattern.FindAllStringIndex(text, -1) {
			value := text[loc[0]:loc[1]]
			if r.MaxLength > 0 && len(value) > r.MaxLength {
				continue
			}
			if r.MinEntropy > 0 && shannonEntropy(value) < r.MinEntropy {
				continue
			}
			if r.Validate != nil && !r.Validate(value) {
				continue
			}
			matches = append(matches, Match{Kind: r.Kind, Start: loc[0], End: loc[1], Value: value})
		}
	}
	return dedupeOverlaps(matches)
}

// shannonEntropy returns the entropy of s in bits per character.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := make(map[rune]int)
	for _, r := range s {
		counts[r]++
	}
	var entropy float64
	n := float64(len(s))
	for _, c := range counts {
		p := float64(c) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// dedupeOverlaps resolves overlapping matches by letting specific kinds
// (a Stripe key, a Slack token, ...) win over the generic catch-alls
// (GENERIC_API_KEY, HIGH_ENTROPY_SECRET) whenever they cover the same
// text - even when the generic match starts earlier and is longer. That
// happens constantly in practice: "SLACK_TOKEN=xoxb-..." matches
// GENERIC_API_KEY starting at "TOKEN", fully enclosing the more useful
// SLACK_TOKEN match that starts at "xoxb". Within the same tier, prefer
// the longer (more specific) span, then the earlier one.
func dedupeOverlaps(matches []Match) []Match {
	if len(matches) < 2 {
		return matches
	}

	candidates := make([]Match, len(matches))
	copy(candidates, matches)
	sort.SliceStable(candidates, func(i, j int) bool {
		gi, gj := isGeneric(candidates[i].Kind), isGeneric(candidates[j].Kind)
		if gi != gj {
			return !gi // specific kinds are tried first
		}
		li := candidates[i].End - candidates[i].Start
		lj := candidates[j].End - candidates[j].Start
		if li != lj {
			return li > lj
		}
		return candidates[i].Start < candidates[j].Start
	})

	var kept []Match
	for _, m := range candidates {
		overlapsKept := false
		for _, k := range kept {
			if m.Start < k.End && k.Start < m.End {
				overlapsKept = true
				break
			}
		}
		if !overlapsKept {
			kept = append(kept, m)
		}
	}

	sort.Slice(kept, func(i, j int) bool { return kept[i].Start < kept[j].Start })
	return kept
}

func isGeneric(k Kind) bool {
	return k == KindGenericAPIKey || k == KindHighEntropy
}
