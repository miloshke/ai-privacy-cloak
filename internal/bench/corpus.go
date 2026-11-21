// Package bench exercises the detector against realistic repo-content
// snippets - the kind of thing a coding agent actually reads and pastes
// into context - to measure catch rate, false positives, and latency.
package bench

import (
	"strings"

	"cloak/internal/detect"
)

// Case is one planted-secret (or deliberately clean) sample. WantKinds
// lists every Kind that must be found somewhere in Text for the case to
// pass. ExpectClean cases assert the opposite: nothing should fire, and
// anything that does is reported as a false positive rather than a pass/fail.
type Case struct {
	Name        string
	Description string
	Text        string
	WantKinds   []detect.Kind
	ExpectClean bool
}

func Corpus() []Case {
	return []Case{
		{
			Name:        "env_file",
			Description: ".env file content an agent would cat into context",
			Text: "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n" +
				"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY123\n" +
				"DATABASE_URL=postgres://admin:S3cretPassword123@db.internal.example.com:5432/app\n",
			WantKinds: []detect.Kind{detect.KindAWSAccessKey},
		},
		{
			Name:        "github_curl",
			Description: "a GitHub PAT pasted into a curl command",
			Text:        `curl -H "Authorization: Bearer ghp_abcdefghij0123456789abcdefghij012345" https://api.github.com/user`,
			WantKinds:   []detect.Kind{detect.KindGitHubToken},
		},
		{
			Name:        "stripe_secret_key",
			Description: "a Stripe secret key assigned in code, no generic api-key wording nearby",
			Text:        `self.secret_key = "sk_live_51H8abcdEFGHijklMNOPqrstUVWX"`,
			WantKinds:   []detect.Kind{detect.KindStripeKey},
		},
		{
			Name:        "jwt_in_log_line",
			Description: "a bearer JWT captured in an application log line",
			Text: `2026-01-10T08:22:11Z level=info msg="auth header" value="Authorization: Bearer ` +
				`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"`,
			WantKinds: []detect.Kind{detect.KindJWT},
		},
		{
			Name:        "hardcoded_password",
			Description: "a plaintext password literal in a connection call",
			Text:        `db.connect(host="db.internal", user="admin", password="Sup3rSecretPassw0rd123")`,
			WantKinds:   []detect.Kind{detect.KindGenericAPIKey},
		},
		{
			Name:        "support_ticket_pii",
			Description: "customer PII in a pasted support ticket",
			Text:        `Ticket #4821 - customer jane.doe@example.com reported login issues, callback number (415) 555-0148.`,
			WantKinds:   []detect.Kind{detect.KindEmail, detect.KindPhone},
		},
		{
			Name:        "internal_ip",
			Description: "an internal host address in a deploy script",
			Text:        `ssh deploy@10.0.4.17 -p 2222   # staging box, do not expose publicly`,
			WantKinds:   []detect.Kind{detect.KindIPv4},
		},
		{
			Name:        "webhook_secret_no_keyword_adjacency",
			Description: "an opaque high-entropy secret where the keyword isn't directly adjacent to the value",
			Text:        `We validate the signature using whsec_8f3ac9d2e4b7a1c6f0d8e2b4a7c9f1e3 pulled from the dashboard.`,
			WantKinds:   []detect.Kind{detect.KindHighEntropy},
		},
		{
			Name:        "credit_card_in_support_ticket",
			Description: "a card number pasted into a support/refund request",
			Text:        `Please refund to the card on file: 4111 1111 1111 1111, thanks.`,
			WantKinds:   []detect.Kind{detect.KindCreditCard},
		},
		{
			Name:        "iban_in_invoice",
			Description: "an IBAN pasted into an invoice/payment instruction",
			Text:        `Please wire the invoice amount to IBAN DE89370400440532013000 at Deutsche Bank.`,
			WantKinds:   []detect.Kind{detect.KindIBAN},
		},
		{
			Name:        "ssh_key_in_repo",
			Description: "an SSH private key accidentally left in a repo file",
			Text: "# deploy_key.pem\n" +
				"-----BEGIN OPENSSH PRIVATE KEY-----\n" +
				"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUx\n" +
				"OQAAACBfakefakefakefakefakefakefakefakefakefakefakefakefakefakefake\n" +
				"-----END OPENSSH PRIVATE KEY-----\n",
			WantKinds: []detect.Kind{detect.KindPrivateKey},
		},
		{
			Name:        "ci_secrets_dotenv",
			Description: "provider API keys in a CI secrets file - also the regression case for generic KEY=value shadowing a specific provider kind",
			Text: "ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789\n" +
				"OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF\n" +
				"SLACK_TOKEN=xoxb-1234567890-abcdefghijklmnopqrstuvwx\n",
			WantKinds: []detect.Kind{detect.KindAnthropicKey, detect.KindOpenAIKey, detect.KindSlackToken},
		},
		{
			Name:        "routing_number_in_wire_instructions",
			Description: "a bank routing number pasted into wire-transfer instructions",
			Text:        `Wire instructions: routing number 021000021 (JPMorgan Chase NY), account number on file.`,
			WantKinds:   []detect.Kind{detect.KindUSRoutingNumber},
		},
		{
			Name:        "ssn_in_hr_document",
			Description: "an SSN pasted into an HR/payroll record",
			Text:        `Employee record: SSN 219-09-9999, start date 2026-01-05.`,
			WantKinds:   []detect.Kind{detect.KindSSN},
		},
		{
			Name:        "git_commit_sha",
			Description: "false-positive trap: a git commit hash looks structurally similar to a hex secret",
			Text:        `Fixed the race condition in commit 4f21a9c8e3b6d5f0917c2a8b4e6d1f3a9c7b5e02 on main.`,
			ExpectClean: true,
		},
		{
			Name:        "uuid_request_id",
			Description: "false-positive trap: a UUID in a log line",
			Text:        `request_id=550e8400-e29b-41d4-a716-446655440000 status=200 duration_ms=42`,
			ExpectClean: true,
		},
		{
			Name:        "order_reference_number",
			Description: "false-positive trap: a 16-digit order reference that happens to be card-number-shaped but fails the Luhn check",
			Text:        `Your order reference is 1234567890123456 - keep this for tracking.`,
			ExpectClean: true,
		},
		{
			Name:        "sequential_nine_digit_id",
			Description: "false-positive trap: a sequential 9-digit ID that's the right length for a routing number but fails the ABA checksum",
			Text:        `Internal customer ID 123456789 was merged into the new system.`,
			ExpectClean: true,
		},
		{
			Name:        "iso_date_not_ssn",
			Description: "false-positive trap: an ISO date's digit-dash shape (4-2-2) must not be mistaken for an SSN's (3-2-4)",
			Text:        `See the report dated 2026-10-18, revision 4.`,
			ExpectClean: true,
		},
		{
			Name:        "large_base64_attachment",
			Description: "false-positive trap: a large base64-encoded attachment (image/PDF/etc) is exactly as high-entropy as a real secret and must not be swept up at all, fragmented or otherwise",
			Text:        "data: " + strings.Repeat("QWxhZGRpbjpvcGVuIHNlc2FtZQ", 40) + " end of attachment",
			ExpectClean: true,
		},
		{
			Name:        "ordinary_go_code",
			Description: "benign code with no secrets at all",
			Text: "func main() {\n" +
				"\tfmt.Println(\"hello, world\")\n" +
				"\tdata := map[string]string{\"status\": \"ok\"}\n" +
				"\t_ = data\n" +
				"}\n",
			ExpectClean: true,
		},
		{
			Name:        "ordinary_prose",
			Description: "benign README-style prose with no secrets",
			Text:        `To get started, clone the repository, install dependencies with your package manager of choice, and run the test suite before opening a pull request.`,
			ExpectClean: true,
		},
	}
}
