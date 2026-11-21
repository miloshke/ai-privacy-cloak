package detect

import (
	"strings"
	"testing"
)

func TestScanFindsKnownSecretShapes(t *testing.T) {
	d := New()
	text := `AWS key: AKIAABCDEFGHIJKLMNOP, contact jane@example.com, token ghp_abcdefghij0123456789abcdefghij012345`

	matches := d.Scan(text)
	if len(matches) == 0 {
		t.Fatal("expected at least one match, got none")
	}

	var kinds []Kind
	for _, m := range matches {
		kinds = append(kinds, m.Kind)
	}

	for _, want := range []Kind{KindAWSAccessKey, KindEmail, KindGitHubToken} {
		found := false
		for _, k := range kinds {
			if k == want {
				found = true
			}
		}
		if !found {
			t.Errorf("expected a %s match, got kinds %v", want, kinds)
		}
	}
}

func TestScanIgnoresOrdinaryText(t *testing.T) {
	d := New()
	matches := d.Scan("please refactor the handler and add a unit test")
	if len(matches) != 0 {
		t.Errorf("expected no matches in ordinary text, got %v", matches)
	}
}

func TestLuhnValidAcceptsPublishedTestCardNumbers(t *testing.T) {
	// These are the standard published test numbers card networks document
	// for integration testing - not real cards.
	for _, card := range []string{
		"4111111111111111", // Visa
		"5555555555554444", // Mastercard
		"378282246310005",  // Amex
	} {
		if !luhnValid(card) {
			t.Errorf("expected %s to be Luhn-valid", card)
		}
	}
}

func TestLuhnValidRejectsRandomDigitRuns(t *testing.T) {
	for _, s := range []string{
		"4111111111111112", // last digit of a valid test card, flipped
		"1234567890123456",
	} {
		if luhnValid(s) {
			t.Errorf("expected %s to fail the Luhn check", s)
		}
	}
}

func TestScanFindsCreditCardInSupportText(t *testing.T) {
	d := New()
	text := "Please refund to the card on file: 4111 1111 1111 1111, thanks."
	if !hasKind(d.Scan(text), KindCreditCard) {
		t.Errorf("expected a CREDIT_CARD match in %q", text)
	}
}

func TestIbanValidAcceptsTextbookExamples(t *testing.T) {
	for _, iban := range []string{
		"GB82WEST12345698765432",      // UK, from the IBAN Wikipedia example
		"DE89370400440532013000",      // Germany
		"FR1420041010050500013M02606", // France (BBAN includes a letter)
	} {
		if !ibanValid(iban) {
			t.Errorf("expected %s to be a valid IBAN checksum", iban)
		}
	}
}

func TestIbanValidRejectsAlteredChecksum(t *testing.T) {
	if ibanValid("GB82WEST12345698765433") {
		t.Error("expected altering the last digit to break the checksum")
	}
}

func TestScanFindsIBANInInvoiceText(t *testing.T) {
	d := New()
	text := "Please wire the invoice amount to IBAN DE89370400440532013000 at Deutsche Bank."
	if !hasKind(d.Scan(text), KindIBAN) {
		t.Errorf("expected an IBAN match in %q", text)
	}
}

func hasKind(matches []Match, k Kind) bool {
	for _, m := range matches {
		if m.Kind == k {
			return true
		}
	}
	return false
}

func TestScanFindsPrivateKeyBlock(t *testing.T) {
	d := New()
	text := "Here's the deploy key:\n" +
		"-----BEGIN OPENSSH PRIVATE KEY-----\n" +
		"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUx\n" +
		"OQAAACBfakefakefakefakefakefakefakefakefakefakefakefakefakefakefake\n" +
		"-----END OPENSSH PRIVATE KEY-----\n" +
		"That's all."
	if !hasKind(d.Scan(text), KindPrivateKey) {
		t.Errorf("expected a PRIVATE_KEY match in %q", text)
	}
}

func TestScanFindsProviderAPIKeys(t *testing.T) {
	cases := []struct {
		name string
		text string
		want Kind
	}{
		{"google", "the maps key is AIzaSyD-FAKEFAKEFAKEFAKEFAKEFAKEFAKE1234", KindGoogleAPIKey},
		{"slack", "export SLACK_TOKEN=xoxb-1234567890-abcdefghijklmnopqrstuvwx", KindSlackToken},
		{"npm", "//registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz0123456789", KindNpmToken},
		{"sendgrid", "SENDGRID_API_KEY=SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz0123456789", KindSendGridKey},
		{"twilio", "TWILIO_ACCOUNT_SID=AC1234567890abcdef1234567890abcdef", KindTwilioKey},
		{"anthropic", "ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789", KindAnthropicKey},
		{"openai", "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF", KindOpenAIKey},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !hasKind(New().Scan(c.text), c.want) {
				t.Errorf("expected a %s match in %q", c.want, c.text)
			}
		})
	}
}

func TestScanDisambiguatesAnthropicFromOpenAIKeyPrefix(t *testing.T) {
	d := New()
	matches := d.Scan("key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789")
	if hasKind(matches, KindOpenAIKey) {
		t.Errorf("expected an sk-ant- key to be classified as Anthropic, not OpenAI: %v", matches)
	}
	if !hasKind(matches, KindAnthropicKey) {
		t.Errorf("expected an ANTHROPIC_API_KEY match, got %v", matches)
	}
}

func TestRoutingNumberValidAcceptsPublishedInstitutionalNumbers(t *testing.T) {
	// 021000021 is JPMorgan Chase's own publicly published NY routing
	// number - an institutional identifier, not anyone's private data.
	if !routingNumberValid("021000021") {
		t.Error("expected 021000021 to pass the ABA checksum")
	}
}

func TestRoutingNumberValidRejectsAlteredChecksum(t *testing.T) {
	if routingNumberValid("021000022") {
		t.Error("expected altering the last digit to break the ABA checksum")
	}
}

func TestScanFindsRoutingNumberInWireInstructions(t *testing.T) {
	d := New()
	text := "Wire instructions: routing number 021000021, account number on file."
	if !hasKind(d.Scan(text), KindUSRoutingNumber) {
		t.Errorf("expected a US_ROUTING_NUMBER match in %q", text)
	}
}

func TestSsnPlausibleRejectsNeverIssuedRanges(t *testing.T) {
	for _, ssn := range []string{"000-12-3456", "666-12-3456", "912-12-3456", "123-00-4567", "123-45-0000"} {
		if ssnPlausible(ssn) {
			t.Errorf("expected %s to be rejected as an never-issued SSN range", ssn)
		}
	}
}

func TestScanFindsSSNInHRDocument(t *testing.T) {
	d := New()
	// 219-09-9999 is the "Woolworth wallet" SSN - a famous fake widely
	// reused after a 1938 wallet promotion, not anyone's real number.
	text := "Employee record: SSN 219-09-9999, start date 2026-01-05."
	if !hasKind(d.Scan(text), KindSSN) {
		t.Errorf("expected an SSN match in %q", text)
	}
}

func TestSsnDoesNotFalsePositiveOnPhoneOrDate(t *testing.T) {
	d := New()
	matches := d.Scan("call us at 415-555-0148 or see the report dated 2026-10-18")
	if hasKind(matches, KindSSN) {
		t.Errorf("expected no SSN false positive, got %v", matches)
	}
}

// A real base64-encoded attachment (image, PDF, any binary content) is
// exactly as "high entropy" as a real secret by this metric, and used
// to match in its entirety - a 100KB image became one multi-KB match
// (later, after a naive length bound was tried, ~590-1900 fragmented
// matches covering nearly all of it instead). Rule.MaxLength fixes this
// by matching the full run first and discarding the whole match if it's
// implausibly long, rather than bounding the regex's own repetition.
func TestScanRejectsOversizedHighEntropyBlobEntirely(t *testing.T) {
	d := New()
	blob := strings.Repeat("QWxhZGRpbjpvcGVuIHNlc2FtZQ", 20) // 520 chars, well past MaxLength
	matches := d.Scan(blob)
	for _, m := range matches {
		if m.Kind == KindHighEntropy {
			t.Errorf("expected an oversized run to be rejected entirely, got a %d-char HIGH_ENTROPY_SECRET match", m.End-m.Start)
		}
	}
}

func TestScanStillCatchesHighEntropySecretUnderTheLengthBound(t *testing.T) {
	d := New()
	secret := "whsec_8f3ac9d2e4b7a1c6f0d8e2b4a7c9f1e3" // well under MaxLength
	if !hasKind(d.Scan("the webhook secret is "+secret), KindHighEntropy) {
		t.Errorf("expected a normal-sized opaque secret to still be caught")
	}
}
