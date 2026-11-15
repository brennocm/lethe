package torctl

import (
	"bufio"
	"strings"
	"testing"
)

func FuzzTorctlReply(f *testing.F) {
	f.Add("250-a=1\r\n250+b=\r\nx\r\n.\r\n250 OK\r\n")
	f.Add("650 CIRC 1 BUILT $AAAA~x\r\n")
	f.Add("250 AUTHCHALLENGE SERVERHASH=00 SERVERNONCE=\"a\\\"b\"\r\n")
	f.Fuzz(func(t *testing.T, s string) {
		rep, err := readReply(bufio.NewReader(strings.NewReader(s)))
		if err == nil && len(rep.Lines) == 0 {
			t.Fatal("empty reply without error")
		}
		for _, l := range rep.Lines {
			_ = parseKV(l.Text)
			_ = ParseBridge(l.Text)
			_ = parseNS(strings.Join(l.Data, "\n"))
		}
	})
}
