package proxy

import "testing"

func TestPlaceholderBufferHoldsBackSplitTag(t *testing.T) {
	b := &placeholderBuffer{}

	// Simulate a placeholder tag arriving split across three tiny SSE
	// deltas, the exact scenario that broke naive "forward each chunk
	// as it arrives" streaming.
	out1 := b.feed("the key is {{AWS_ACCESS")
	out2 := b.feed("_KEY_1}} do not log it")
	out3 := b.drain()

	if out1 != "the key is " {
		t.Errorf("expected the first flush to stop right before the tag, got %q", out1)
	}
	if out2 != "{{AWS_ACCESS_KEY_1}} do not log it" {
		t.Errorf("expected the completed tag plus trailing text once the tag closes, got %q", out2)
	}
	if out3 != "" {
		t.Errorf("expected nothing left to drain, got %q", out3)
	}
}

func TestPlaceholderBufferDrainsDanglingTagAtBlockEnd(t *testing.T) {
	b := &placeholderBuffer{}

	out1 := b.feed("truncated secret {{AWS_ACC")
	out2 := b.drain() // block ends before the tag ever closes

	if out1 != "truncated secret " {
		t.Errorf("expected the dangling tag to be held back, got %q", out1)
	}
	if out2 != "{{AWS_ACC" {
		t.Errorf("expected drain to return the unterminated fragment as-is, got %q", out2)
	}
}

func TestPlaceholderBufferFlushesMultipleCompleteTagsInOneChunk(t *testing.T) {
	b := &placeholderBuffer{}

	out := b.feed("{{EMAIL_1}} called {{PHONE_1}} about the invoice")
	if out != "{{EMAIL_1}} called {{PHONE_1}} about the invoice" {
		t.Errorf("expected both complete tags to flush immediately, got %q", out)
	}
}
