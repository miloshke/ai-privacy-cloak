package service

import "testing"

func TestIsTempBuildBinary(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/var/folders/xy/abc/T/go-build123456/b001/exe/cloak", true},
		{"/tmp/go-build987654/b001/exe/cloak", true},
		{`C:\Users\dev\AppData\Local\Temp\go-build555\b001\exe\cloak.exe`, true},
		{"/usr/local/bin/cloak", false},
		{"/Users/dev/projects/privacy/cloak", false},
	}
	for _, c := range cases {
		if got := IsTempBuildBinary(c.path); got != c.want {
			t.Errorf("IsTempBuildBinary(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}
