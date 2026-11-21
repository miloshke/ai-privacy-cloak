package proxy

import (
	"context"
	"net"
	"sync/atomic"
)

type connIDKey struct{}

var connCounter atomic.Uint64

// ConnContext should be installed as http.Server.ConnContext (see
// cmd/cloak's runServe). It assigns each underlying TCP connection a
// unique, process-local identifier and threads it through to every
// request made over that connection, independent of the request's own
// content.
//
// Provider.DeriveSessionID hashes content that's stable across turns of
// one conversation (system prompt + first message) but not unique across
// conversations - two unrelated terminal tabs whose opening text happens
// to match byte-for-byte would otherwise share one vault bucket and could
// restore each other's secrets. Mixing in the TCP connection identity
// (see combineSessionID in proxy.go) closes that gap: distinct
// connections never collide, no matter what content they carry. A
// reused keep-alive connection correctly keeps mapping to the same id
// across turns, which is exactly the property the content hash alone was
// trying to provide.
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, connIDKey{}, connCounter.Add(1))
}

// connID extracts the identifier ConnContext attached, or 0 if none was
// set - e.g. a request built directly in a test without going through a
// real listener. Combining 0 with content still keys deterministically,
// so such requests continue to match each other exactly as they did
// before this fix.
func connID(ctx context.Context) uint64 {
	id, _ := ctx.Value(connIDKey{}).(uint64)
	return id
}
