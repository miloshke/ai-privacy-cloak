package proxy

import (
	"bufio"
	"io"
	"log"
	"strings"
)

// maxSSELineSize bounds a single scanned SSE line (bufio.Scanner's token
// size, not the whole stream). 10MB comfortably covers a large embedded
// chunk - base64 image data in a multimodal response, or a sizeable file
// write streamed through a single tool-call argument delta - while still
// bounding per-request memory use. Every Provider's StreamRestore shares
// this limit and logs via logScannerError if a stream ever exceeds it,
// rather than truncating the client's response with no trace of why.
const maxSSELineSize = 10 * 1024 * 1024

func newSSEScanner(body io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), maxSSELineSize)
	return scanner
}

// logScannerError reports why an SSE stream's scan loop ended early -
// bufio.Scanner otherwise fails silently (Scan just returns false), which
// would otherwise look identical to a normal, complete stream ending.
func logScannerError(provider string, err error) {
	if err != nil {
		log.Printf("cloak: %s stream ended early: %v", provider, err)
	}
}

// placeholderBuffer accumulates streamed text and releases everything
// except a trailing fragment that could still be the start of an
// unterminated "{{...}}" placeholder tag. Shared by every Provider's
// StreamRestore implementation - a placeholder can straddle an arbitrary
// chunk boundary regardless of which wire protocol is framing the stream.
type placeholderBuffer struct {
	pending strings.Builder
}

// feed appends chunk and returns the portion now safe to restore and
// forward, keeping back any unsafe trailing fragment for the next call.
func (b *placeholderBuffer) feed(chunk string) string {
	b.pending.WriteString(chunk)
	buf := b.pending.String()
	safe := safeFlushPoint(buf)
	flush := buf[:safe]
	b.pending.Reset()
	b.pending.WriteString(buf[safe:])
	return flush
}

// drain returns and clears whatever is left - used when the stream ends,
// since nothing can arrive after that to complete a dangling tag.
func (b *placeholderBuffer) drain() string {
	rest := b.pending.String()
	b.pending.Reset()
	return rest
}

// safeFlushPoint returns the length of buf up to which text is guaranteed
// not to contain the start of an unterminated "{{" tag. Everything before
// the last "{{" is safe by construction: if an earlier "{{" were also
// unterminated, this same check would already have held it back on a
// previous call.
func safeFlushPoint(buf string) int {
	if idx := strings.LastIndex(buf, "{{"); idx != -1 && !strings.Contains(buf[idx:], "}}") {
		return idx
	}
	return len(buf)
}
