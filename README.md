# cloak

A local proxy that sits between AI coding agents (Claude Code, Cursor, aider, Codex CLI, ...) and the model provider's API, redacting secrets and PII before they leave your machine — and restoring them transparently in the response.

> **Status:** early scaffold / MVP in progress. Not production-ready. Name is a placeholder.

**Is this plug-and-play, or does it need configuration?** A few one-time terminal
commands, then it's invisible. There's no config file to write and cloak has no
API keys or accounts of its own - `cloak install` detects your shell and writes
one environment variable your agent already knows how to read
(`ANTHROPIC_BASE_URL`, or the equivalent for your provider), `cloak serve` (or
`cloak service install` for something that survives reboots) starts it, and
from then on you just use Claude Code / Cursor / aider exactly as before. The
only ongoing interaction is `cloak toggle`/`enable`/`disable` if you ever want
to turn redaction off without losing your agent's connection. See the full
steps below.

## Usage

Nothing is published yet - build from source. Requires Go 1.23+.

### 1. Build

```sh
go build -o cloak ./cmd/cloak
```

Use a real build, not `go run`, for anything in step 3 onward - `go run` compiles to a throwaway temp binary, and `cloak service install` needs a stable path to relaunch on login.

### 2. Point your agent at cloak

cloak proxies one provider's API at a time: `anthropic` (default), `openai`, or `gemini`. This writes the right environment variable into your shell profile:

```sh
./cloak install              # preview only - dry run, writes nothing
./cloak install -yes         # writes ANTHROPIC_BASE_URL=http://127.0.0.1:8787 to e.g. ~/.zshrc
```

For a different provider:

```sh
./cloak install -provider openai -yes   # writes OPENAI_BASE_URL
./cloak install -provider gemini -yes   # writes GOOGLE_GEMINI_BASE_URL - confirm your agent actually honors this one, it's less universal than the other two
```

Then restart your shell (or `source ~/.zshrc`) so new terminal sessions pick up the variable.

### 3. Run it

Pick foreground (simplest, stops when the terminal closes) or background (survives reboots):

```sh
./cloak serve                            # foreground, anthropic, listens on 127.0.0.1:8787
./cloak serve -provider openai
```

```sh
./cloak service install -provider anthropic   # background: launchd (macOS) / systemd --user (Linux) / login Run key (Windows)
./cloak service status
./cloak service uninstall
```

Either way, once it's running, just use Claude Code / Cursor / aider as normal - requests are redacted on the way out and restored on the way back in, with no change to your workflow.

### 4. Toggle protection without restarting anything

```sh
./cloak protection-status   # is it currently redacting?
./cloak disable             # traffic still flows, just unredacted - the agent never loses connectivity
./cloak enable
./cloak toggle               # flips whichever state it's currently in
```

### 5. Optional: menu-bar / system-tray toggle

```sh
go build -o cloak-tray ./cmd/cloak-tray
./cloak-tray                 # shows a tray icon, polls status every 3s, click to toggle
```

`cloak-tray` doesn't start or stop `cloak serve` - it's a thin GUI client on the same control API as step 4, so it only does anything useful while cloak is already running.

### 6. Optional: packaged installers

```sh
./scripts/package-macos.sh      # -> dist/macos/cloak-tray.app, dist/macos/cloak-VERSION.dmg
brew install makensis           # once, for the Windows installer
./scripts/package-windows.sh    # -> dist/windows/cloak-setup-VERSION.exe
```

macOS: unsigned by default, but `package-macos.sh` now signs + notarizes a real build when `CLOAK_SIGN_IDENTITY` and `CLOAK_NOTARY_PROFILE` are set (one-time Keychain setup, documented at the top of the script) - opens with no Gatekeeper warning at all once that's in place.

Windows: still unsigned, no code-signing certificate owned yet - SmartScreen will warn on first run. Traditional certs run ~$200-500/yr and usually need business verification; Microsoft's newer Trusted Signing (Azure-based, pay-per-use) is worth checking as a cheaper option, but verify current pricing/eligibility directly since it's changed before. Not wired into `package-windows.sh` yet because there's no certificate to sign with.

### Checking it's actually working

```sh
./cloak bench                          # leak-corpus benchmark: catch-rate + latency
./cloak protection-status              # confirm redaction is on
```

The most direct check: point `-upstream` at something that just echoes back whatever it receives (a raw `nc -l <port>` listener works for a quick look, no setup) and send real traffic through cloak - you're reading the actual bytes that left the process, not trusting a log.

### Tracing what's been redacted

Off by default - cloak writes nothing to disk unless you ask it to. Pass `-audit-log <path>` to `serve` or `service install` to get a local, append-only JSON-lines record of every redaction:

```sh
./cloak serve -audit-log ~/.cloak/audit.jsonl
tail -f ~/.cloak/audit.jsonl
```

Each line is `{"time", "session_id", "kind", "placeholder"}` - when, which conversation, and *what kind* of thing (`AWS_ACCESS_KEY`, `EMAIL`, ...). It never contains the real value that triggered it or the placeholder's mapping back to that value - verified by a test that asserts the planted secret never appears anywhere in the log file. The file is created `0600` (owner-only) **on macOS/Linux** - on Windows, `chmod`-style mode bits don't map onto a real ACL (confirmed via the Windows CI job: the file comes back `0666` regardless of what's requested), so privacy there currently rests on the user profile directory's own default ACL inheritance rather than an explicit owner-only lock. Narrow in practice (a standard single-user Windows machine already restricts the profile directory to that user), but worth knowing before relying on this on a shared Windows box.

### Uninstalling

```sh
./cloak service uninstall     # if you ran it as a background service
```

Then remove the `export ANTHROPIC_BASE_URL=...` (or `OPENAI_BASE_URL`/`GOOGLE_GEMINI_BASE_URL`) line `cloak install` added to your shell profile - it's clearly marked with a `# added by cloak install` comment above it.

## The problem

Coding agents read your repo to do their job: they `cat` `.env` files, `grep` config, open old CSVs, paste log output into their own context. All of that gets sent as plaintext to whichever model provider you're using (Anthropic, OpenAI, ...). That means your AWS keys, Stripe secrets, customer records, and internal hostnames are routinely leaving your machine as a side effect of normal agent use — not because anyone asked for it.

Existing "LLM privacy proxy" tools (see below) solve the generic version of this for *chat* traffic: names, emails, SSNs. None of them are tuned for the specific shape of the problem coding agents create — credential-shaped strings, `.env`-style key/value pairs, file content and diffs — or integrated into a coding-agent-first workflow.

## How it works

```
Claude Code / Cursor / aider
        │  ANTHROPIC_BASE_URL or OPENAI_BASE_URL=http://localhost:8787
        ▼
┌───────────────────────────────┐
│            cloak               │
│                                 │
│  1. Scrub transport metadata   │
│  2. Scan request body for      │
│     secrets/PII (regex +       │
│     entropy, no ML)            │
│  3. Swap matches for           │
│     placeholders               │
│     ("AKIA..." -> "{{AWS_     │
│     ACCESS_KEY_1}}")           │
│  4. Store the mapping in an    │
│     in-memory, per-session     │
│     vault (never on disk)      │
└───────────────────────────────┘
        │  fully anonymized request
        ▼
   Anthropic / OpenAI / ...
        │  response (may echo a placeholder back)
        ▼
┌───────────────────────────────┐
│            cloak               │
│  5. Restore placeholders using │
│     the session vault          │
│  6. Evict the session after an │
│     idle timeout                │
└───────────────────────────────┘
        │  clean output, originals restored
        ▼
   Your terminal
```

Session identity is derived from a hash of the system prompt + first message, which most agent CLIs resend unchanged on every turn — so the same conversation reuses the same vault across turns without any explicit session header.

One cloak process speaks one provider's wire protocol at a time (`-provider anthropic|openai`, default anthropic) - request/response shapes differ enough between providers that guessing would be fragile. Run a second instance on another port if you need both at once. Provider-specific logic (session-ID derivation, SSE stream framing) lives behind a small `Provider` interface (`internal/proxy/provider.go`); redaction itself is protocol-agnostic and shared.

## Why this, why now

Full context and competitive analysis from the planning session that produced this scaffold:

- **The generic "redact PII before it hits an LLM" idea is already built**, including by well-funded players: [Dataiku's Kiji Privacy Proxy](https://www.dataiku.com/company/news/dataiku-launches-kiji-privacy-proxy) (Apache 2.0, launched Apr 2026, desktop + server), the indie [PrivAiTe](https://pypi.org/project/privaite/) project (reversible redaction incl. tool-call args and multimodal content), and LiteLLM's built-in Presidio guardrail for anyone already running that gateway.
- **A related but distinct space** — credential-injection proxies that keep an agent from ever holding a real API key for *its own tool calls* (Secret Broker, Phantom Secrets, Agent Vault, AgentSecrets) — solves a different problem: that's about agents calling *other* APIs safely, not about secrets already sitting in your repo leaking into the *model provider's* context window.
- **The open wedge:** nobody is tuning this pattern specifically for coding-agent traffic — credential-shaped detection (not just classic PII), onboarding through the coding-agent community, and distribution via a visceral demo ("your agent just read your `.env` file into Claude's context") rather than a compliance pitch.

Win condition here is tight execution and the right audience, not an empty market — treat the Dataiku/PrivAiTe benchmarks as the bar to beat on catch-rate and latency, not ignore.

## MVP scope

- [x] Reverse proxy for the Anthropic Messages API, the OpenAI Chat Completions API, and Google's Gemini `generateContent`/`streamGenerateContent` API (JSON + streaming for all three), redact-on-request / restore-on-response working end to end. Selected via `-provider anthropic|openai|gemini`; each has its own session-ID derivation and SSE-restore logic behind the `Provider` interface. Caveat worth knowing: `ANTHROPIC_BASE_URL`/`OPENAI_BASE_URL` are near-universally honored by coding agents, but Gemini's equivalent (`GOOGLE_GEMINI_BASE_URL`, which Google's own Gemini CLI documents) is less consistently exposed by third-party agents - check your specific tool.
- [x] Regex + Shannon-entropy/checksum detection, no ML dependency:
  - Credentials: AWS access keys, GitHub PATs, Stripe keys, Google API keys, Slack tokens, npm tokens, SendGrid keys, Twilio account SIDs, Anthropic/OpenAI API keys, JWTs, PEM private key blocks (SSH/TLS), generic `key=`/`secret=`/`token=`/`password=` literals, and a generic high-entropy catch-all.
  - PII: email, phone, IPv4, credit card numbers (Luhn-validated), IBANs (mod-97 checksum validated), SSNs (plausibility-filtered against SSA's never-issued ranges - no real checksum exists for an SSN), US bank routing numbers (ABA checksum validated).
  - Overlap resolution prefers specific kinds (e.g. `SLACK_TOKEN`) over the generic catch-alls even when the generic match starts earlier and is longer - `TOKEN=xoxb-...` reports as Slack, not just "some API key" (`internal/detect/detect.go`, `dedupeOverlaps`).
- [x] In-memory, TTL-evicted session vault — nothing ever touches disk.
- [x] `cloak install` — detects zsh/bash/fish, previews the change by default, writes it (idempotently) with `-yes`.
- [x] Leak-corpus benchmark (`cloak bench` / `go test ./internal/bench`): 21 realistic cases (planted credentials, PEM keys, card/IBAN/SSN/routing numbers, PII, and false-positive traps like UUIDs, git SHAs, a Luhn-invalid order number, a non-ABA-checksum sequential ID, and an ISO date that must not be mistaken for an SSN) — currently 21/21 passing, worst-case p95 latency ~120µs, two to three orders of magnitude under the <15ms budget.
- [x] Token-level incremental streaming restore for both providers — placeholders are restored and flushed as soon as they're complete, not batched. A trailing fragment that could be the start of an unterminated `{{...}}` tag is held back until it closes or the stream ends (shared `placeholderBuffer` in `internal/proxy/stream.go`). Covered by a unit test on the buffer and, for each provider, an integration test that splits a placeholder across two real SSE chunks through the full HTTP handler.
- [x] Tool-call argument streaming redaction (Anthropic's `input_json_delta`, OpenAI's `tool_calls[].function.arguments`) — this isn't just coverage, it was a live correctness bug: a coding agent routinely echoes previously-redacted file content back through a tool call (read a file, edit it, write it back), and without this, the agent would've written the literal `{{...}}` placeholder text into the file instead of the real secret. Fixed for both providers, each with its own split-across-chunks integration test proving the restored value survives a tool call's streamed arguments intact.
- [x] `cloak service install|uninstall|status` — registers cloak to run automatically in the background via each OS's native mechanism (launchd agent on macOS, systemd `--user` service on Linux, a login Run-key entry on Windows), so protection survives reboots without a dedicated terminal tab. Needs a real `go build` binary, not `go run` - `go run`'s binary is temporary, and installing a service pointing at one would silently break once it's cleaned up; `service install` detects and refuses that case. Verified end-to-end on macOS: real launchd agent installed, proxy confirmed listening and forwarding a request to the live Anthropic API (401, as expected with no key - proving the round trip), then fully uninstalled with no residue (no plist, not loaded, no stray process). Linux/Windows paths are implemented and cross-compile cleanly but are not yet exercised on those OSes.
- [x] Runtime on/off toggle (`cloak toggle` / `cloak enable` / `cloak disable` / `cloak protection-status`) — flips a redact-vs-passthrough flag on an already-running cloak via a tiny loopback-only control API (`/__cloak__/status|enable|disable|toggle`), rather than starting/stopping the process. That distinction matters: env vars only take effect for new agent sessions, so stopping the process while `ANTHROPIC_BASE_URL`/`OPENAI_BASE_URL` is still set would break the agent's connectivity instead of just removing protection. When disabled, traffic is a true byte-for-byte passthrough (`servePassthrough` in `internal/proxy/proxy.go`) - not "redaction ran and found nothing", nothing touches the bytes at all, with incremental flushing so a passed-through SSE stream still arrives live. Mutating actions require POST (GET is rejected with 405); status is a plain GET. Verified live: started a real background instance, drove it through disable → confirmed the upstream received a secret byte-for-byte unredacted → toggle → enable → confirmed redaction resumed, all over the real network path to Anthropic's API, then torn down cleanly. This is also the exact mechanism a future menu-bar/tray toggle app would call - a GUI there is now just a thin client on top of this.
- [x] `cloak-tray` — a menu-bar/system-tray app (`cmd/cloak-tray`, using `fyne.io/systray` - the project's first external dependency, scoped to this one command) that polls `/__cloak__/status` every 3s and lets you click to toggle. It's a thin GUI client on the control API from the toggle feature above - it doesn't manage `cloak serve`'s process at all. Verified for real on macOS: built, launched against a live test instance, survived a CLI-driven toggle with no conflicts, exited cleanly. Cross-compiles for Linux and Windows too (`systray`'s non-macOS backends are pure Go - only macOS needs CGo, which Xcode provides here); not run on either of those OSes.
- [x] Packaging: `scripts/package-macos.sh` builds a real `cloak-tray.app` + `.dmg` via `hdiutil` - verified end-to-end: mounted the built dmg, confirmed the `Info.plist` validates (`plutil -lint`) and the bundled binary is a genuine arm64 Mach-O executable. It also now signs + notarizes when `CLOAK_SIGN_IDENTITY`/`CLOAK_NOTARY_PROFILE` are set (an Apple Developer Program membership is owned for this project), codesigning the nested binaries before the bundle, then the dmg, then submitting to `notarytool` and stapling the ticket - opens with no Gatekeeper warning at all once that's in place. Unsigned remains the default (no env vars set) for anyone building locally without that membership. `scripts/package-windows.sh` cross-builds `cloak.exe` (console subsystem, it's a CLI) and `cloak-tray.exe` (`-ldflags -H=windowsgui`, so no console window flashes behind the tray icon) and wraps them in a real NSIS installer via Homebrew's `makensis` - verified the two `.exe` files are well-formed PE32+ binaries with the right subsystem each, and that `makensis` builds the installer without error, but **none of it has been run on an actual Windows machine**, and it's still unsigned: no Windows code-signing certificate has been acquired yet (see the Usage section above for options), so SmartScreen will warn on first run until that's a separate cost/account decision someone makes.

**Other private data considered, not yet added:** crypto wallet addresses (only worth it for fintech/crypto-adjacent users). Explicitly deferred rather than planned: physical addresses, full names, dates of birth — these need real NER to catch reliably without a flood of false positives, and that ML dependency is exactly what this project is betting against; re-litigate only if the credential-shaped bet stops being enough.

Explicitly out of scope for MVP: a team dashboard/control plane.

## Hardening pass

A deliberate "what haven't we actually checked" pass, since every feature above had been tested for the happy path but not stress-tested. Found and fixed real bugs, not just added coverage:

- **Gzip response corruption (real bug, fixed).** Forwarding a client's own `Accept-Encoding` header disables Go's `net/http.Transport` automatic gzip-request-and-transparently-decompress behavior (it only activates when the outgoing request has no `Accept-Encoding` of its own). Reproduced concretely with a controlled test: without the fix, a compressed upstream response arrived as raw gzip bytes, meaning **a redacted secret would never get restored** - the client would receive the literal `{{...}}` placeholder instead of the real value once it decompressed on its own end. Fixed by stripping the header before forwarding, so `Transport` negotiates and decompresses for us; verified the fix with the same reproduction, in both normal and passthrough (disabled) mode.
- **Silent stream truncation (real bug, fixed).** None of the three providers' `StreamRestore` checked `scanner.Err()` after the SSE parsing loop - if a single line ever exceeded the 1MB buffer cap (plausible for large embedded content, e.g. base64 image data or a big file write via a tool call), the stream just stopped with no log, no client-visible error. Raised the cap to 10MB and added `logScannerError` so this is now at least surfaced, not swallowed - proven with a test that force-triggers an oversized line and asserts it gets logged without hanging the handler.
- **Unbounded request body memory (real gap, fixed).** The redaction path (unlike passthrough, which streams bytes through without ever buffering them) read the entire request body into memory with no cap - a very large pasted file could balloon memory unboundedly. Capped at 64MB via `http.MaxBytesReader`, returning a clean 413 instead.
- **No graceful shutdown (real gap, fixed).** `cloak serve` used to call `http.ListenAndServe` directly with no signal handling, so a `SIGTERM` from launchd/systemd (exactly what `cloak service install` sets up) would hard-kill in-flight requests. Now traps `SIGINT`/`SIGTERM` and calls `server.Shutdown` with a 10s drain window. Verified live: sent a real `SIGTERM` to a running instance and confirmed it logged the signal and exited cleanly rather than just vanishing.
- **Concurrency.** `go test -race` passes, including a 200-goroutine stress test hammering the handler and the toggle endpoint simultaneously - no data races found.
- **Session ID collision (fixed).** `DeriveSessionID` hashes the system prompt + first message, which is the most stable, most-available content on a conversation's first turn - but on its own that means two **genuinely unrelated** conversations with identical opening text (plausible: same project's system prompt + a short first message like "fix the bug") would hash to the same session and **share one vault bucket**. Fixed by binding session identity to the underlying TCP connection in addition to content: `http.Server.ConnContext` (wired in `cmd/cloak`) tags every connection with a unique id via `proxy.ConnContext`, and `combineSessionID` (`internal/proxy/proxy.go`) hashes that together with the content-derived id before it ever touches the vault (`internal/proxy/connid.go`). This closes the common "two separate terminal tabs" case entirely without changing the `Provider` interface at all - the mixing happens once, centrally, after `Provider.DeriveSessionID` returns. Verified with a test that reproduces the exact leak scenario (session B's upstream echoes back session A's placeholder tag verbatim) and confirms it fails without the fix and passes with it (`TestServeHTTPDoesNotCollideAcrossConnectionsWithIdenticalContent`, `internal/proxy/connid_test.go`). Residual case, by the same honesty standard as everywhere else in this README: a reconnect mid-conversation (e.g. after a keep-alive idle timeout) gets a new connection id, so that turn starts a fresh vault bucket instead of reusing the previous one - a minor loss of placeholder continuity across that reconnect, never a collision.
- **Verified end-to-end against a real agent CLI (closed - was the single biggest remaining validation gap).** Ran headless Claude Code (`claude -p`, model `claude-haiku-4-5`) through a live `cloak serve` instance against the real Anthropic API, not curl or a fake upstream. Two runs: (1) asked it to read a planted `.env` file (a fake AWS-shaped key, a fake Stripe key, an email) and print the contents back - the audit log confirms `HIGH_ENTROPY_SECRET`/`STRIPE_KEY`/`EMAIL` were actually redacted on the outgoing request, and the printed output showed the real original values, correctly restored. (2) asked it to read that file and write the Stripe key into a new file via the `Write` tool - the exact "agent echoes redacted content back through a tool call" scenario called out above as a real correctness bug class - and the written file contained the real secret, not a literal `{{...}}` tag. No errors, no mangled `tool_use.id`, nothing left over in `cloak`'s own log. (The planted AWS-shaped key didn't match the exact `AKIA`+16-char format and fell through to the generic high-entropy rule instead of the specific `AWS_ACCESS_KEY` rule - an artifact of the fake test value, not a detection gap; it was still caught and redacted.)

## Bugs found via real usage

- **Structural IDs mangled into invalid placeholders (critical, fixed).** `redactJSON` walked *every* string anywhere in the body with no concept of "this is protocol metadata, not content." A real Anthropic `tool_use.id` or OpenAI `tool_call.id` routinely clears the `HIGH_ENTROPY_SECRET` threshold (confirmed: `msg_01XFDUDYJgAACzvnptvVoYEL` and `call_FthC9qRpvrtC2QS8Kv82rI5Q` both match it), so it would get swapped for a `{{HIGH_ENTROPY_SECRET_N}}` placeholder - whose curly braces violate Anthropic's `^[a-zA-Z0-9_-]+$` validation on that field, making the API reject the entire request with a 400. **This broke tool use outright** - not a detection gap, an active break of the core workflow, caught from a real `API Error: 400 ... tool_use.id: String should match pattern` while actually using the tool. Fixed by adding `structuralKeys` (`id`, `tool_use_id`, `tool_call_id`, `type`, `role`, `model`, `object`, `finish_reason`/`finishReason`, `stop_reason`) that `redactJSON` always skips, regardless of what the value looks like - verified with a reproduction that fails without the fix and passes with it, for both Anthropic's and OpenAI's field-naming conventions, while confirming a real secret in the same request (inside `tool_result`/tool-message content, which *is* real content) still gets redacted correctly.
  - Residual tradeoff, same honesty standard as the session-ID finding above: this skips any field with one of those exact names *anywhere* in the tree, including inside tool-call arguments - so a secret nested under a key literally named `id` or `type` inside arbitrary tool JSON wouldn't be caught. Narrow and unusual; breaking every tool call outright is the far more common and far more severe failure this trades away.
  - This is now the strongest reason to prioritize the "not yet checked" item above: this exact bug could only be found by real usage, not by any of the test/fake-upstream coverage already in place, because it depends on the *exact* field names and ID shapes a real provider uses.
- **Follow-up: "how do I verify it's actually not sending sensitive data?"** Fair question after the above - demonstrated two complementary answers rather than just asserting trust. (1) Pointed `-upstream` at a raw `nc -l` listener and sent a real secret through: watched the literal bytes arrive at the other end with only `{{AWS_ACCESS_KEY_1}}` in them, no code to trust, just the wire. (2) Built the opt-in `-audit-log` flag (`internal/audit/`) for ongoing tracing without re-running a live demo each time - a local JSON-lines record of every redaction (timestamp, session, kind) that's been verified, by test, to never contain the real value or the placeholder-to-value mapping. Off by default, so it doesn't weaken the "nothing touches disk" promise unless explicitly asked for.
- **`-audit-log` failed on its own README example (real bug, fixed within minutes of shipping).** `audit.Open` created the file but never its parent directory - `~/.cloak/audit.jsonl`, the exact example in this README, doesn't work on a machine where `~/.cloak` has never existed, which is every machine on first use. Every existing test for this package happened to write directly into `t.TempDir()`, which already exists, so none of them exercised this at all. Fixed by having `Open` call `os.MkdirAll` on the parent first (`0700`, owner-only, matching the file's own `0600`); added a test using a nested non-existent subdirectory specifically because the existing tests couldn't have caught this, then confirmed it fails without the fix (a build error, since removing the directory-creation code left an unused import - strong enough proof it's load-bearing) and passes with it. Re-ran the user's exact original command end to end afterward to confirm.
- **Stale running process silently absorbed every fix above (process-management, not code).** None of the fixes landed in practice for a while, because a long-running `cloak serve` process predated all of them - overwriting the binary on disk doesn't affect an already-running process, which keeps executing old code from memory until it's actually killed and relaunched. Compounded by `cloak service install`'s own `KeepAlive: true`: killing the stale process without rebuilding first just gets it relaunched by launchd, unchanged. The fix each time was mundane but necessary: `lsof -i :8787` / `ps` to find what's actually running and since when, rebuild, `cloak service install` again (which reloads the launchd agent), then verify via `/__cloak__/status` and a fresh `ps` - not just "I edited the file, you're good now."
- **31 redactions from "one prompt" (expected, not a bug, but worth explaining).** Looked alarming until accounting for how these APIs actually work: Claude Code resends the *entire* conversation history on every turn, and this exact project's build session - run through its own cloak instance the whole time - had accumulated a long transcript full of deliberately-planted fake secrets, emails, and IPs from testing. One short visible prompt is never "one short prompt" from the proxy's perspective once the full history is in play.
- **That question was still worth chasing, because `HIGH_ENTROPY_SECRET` is the most false-positive-prone rule - and it turned up two more real bugs.** (1) A real base64-encoded attachment (image, PDF, any binary content) is exactly as "high entropy" as a real secret by this metric, and matched *in its entirety* - a 100KB image became one multi-KB match, got swapped for a placeholder, and the **whole 100KB string sat in the in-memory vault** keyed by it. Fixing this took two attempts: bounding the regex's own repetition count (`{24,256}`) didn't work, because Go's `\b` is defined relative to `\w` ([0-9A-Za-z_]) rather than this pattern's own character class, and base64's `+`/`/` characters (non-`\w`) created internal word-boundary breaks roughly every 16 characters - so the bound just fragmented one giant match into ~590-1900 smaller ones that still collectively covered 80-99.998% of the blob, depending on exactly where those breaks landed. The actual fix: a new `Rule.MaxLength` that matches the full *unbounded* run first and discards the whole match if it's longer than 256 chars, instead of ever trying to bound or fragment it - verified at multiple sizes up to 100KB, confirmed to still catch real secrets up to the 256-char bound, and confirmed (by temporarily disabling the check) that the test actually exercises it. (2) Anthropic's extended-thinking block `signature` field - a cryptographic signature over the thinking content, short enough that the length bound alone wouldn't have excluded it - needed its own `structuralKeys` entry, same bug class as `tool_use.id`, found by the same kind of audit.

## Layout

```
cmd/cloak/            CLI entrypoint (serve, install, service, toggle/enable/disable/protection-status, bench)
cmd/cloak-tray/        menu-bar/system-tray GUI, a thin client on the toggle control API
internal/detect/      secret/PII pattern matching (regex + entropy/checksum)
internal/vault/       in-memory placeholder <-> original value store
internal/proxy/       reverse proxy, request redaction, SSE stream restore, provider abstraction, runtime toggle
internal/config/      flag/env resolution
internal/install/     shell-profile detection and idempotent rc-file wiring
internal/bench/       leak-corpus benchmark (planted secrets + false-positive traps)
internal/service/     background auto-start registration (launchd/systemd/Run-key), per-OS build-tagged files
internal/audit/       opt-in local JSON-lines log of redaction metadata (never values), off by default
scripts/              macOS (.app/.dmg) and Windows (.exe/NSIS installer) packaging
```

## Developing

See **Usage** above for actually running cloak. During development, `go run ./cmd/cloak <command>` works for everything except `service install` (needs a stable binary path - see Usage step 1).

```sh
go test ./...                 # full suite
go test -race ./...           # same, with the race detector
go run ./cmd/cloak bench      # leak-corpus catch-rate + latency report
```

`go test ./...` covers the detector's pattern matching, the leak corpus (as a regression gate), shell-profile wiring, the `go run`-binary safety check, the enable/disable/toggle control API (including that disabled mode is a true unmodified passthrough), gzip-compressed upstream responses, oversized-request/oversized-SSE-line handling, and a full request→redact→upstream→stream→restore round trip against a fake upstream.

## Go-to-market (for later, not MVP)

Free and open source ([MIT](LICENSE)) for the local binary, forever — a tool that reads your secrets can't be a vendor's SaaS. Launch via Show HN and the Claude Code / Cursor communities with a concrete demo rather than a compliance pitch. Monetize later via a team control plane (audit log of what got redacted across a team's agent usage, policy enforcement, SSO) sold to the eng lead once individual devs on a team are already using the free CLI.
