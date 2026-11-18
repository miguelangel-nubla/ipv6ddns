package ddns

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/go-routeros/routeros/v3/proto"
)

// fakeRouterOS serves the RouterOS API: it logs in anyone, and answers the other commands with
// handle, which returns the rows of the reply or an error for a trap.
type fakeRouterOS struct {
	listener net.Listener
	handle   func(command string, args, queries map[string]string) ([]map[string]string, error)
}

func newFakeRouterOS(t *testing.T, tlsConfig *tls.Config, handle func(command string, args, queries map[string]string) ([]map[string]string, error)) *fakeRouterOS {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig != nil {
		listener = tls.NewListener(listener, tlsConfig)
	}
	f := &fakeRouterOS{listener: listener, handle: handle}
	go f.serve()
	t.Cleanup(func() { listener.Close() })
	return f
}

func (f *fakeRouterOS) address() string {
	return f.listener.Addr().String()
}

func (f *fakeRouterOS) serve() {
	for {
		conn, err := f.listener.Accept()
		if err != nil {
			return
		}
		go f.serveConn(conn)
	}
}

func (f *fakeRouterOS) serveConn(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	w := proto.NewWriter(conn)
	for {
		words, err := readSentence(r)
		if err != nil {
			return
		}
		command, args, queries, tag := words[0], map[string]string{}, map[string]string{}, ""
		for _, word := range words[1:] {
			switch {
			case strings.HasPrefix(word, ".tag="):
				tag = strings.TrimPrefix(word, ".tag=")
			case strings.HasPrefix(word, "="):
				k, v, _ := strings.Cut(word[1:], "=")
				args[k] = v
			case strings.HasPrefix(word, "?"):
				k, v, _ := strings.Cut(word[1:], "=")
				queries[k] = v
			}
		}

		var rows []map[string]string
		if command != "/login" {
			rows, err = f.handle(command, args, queries)
		}
		reply := func(word string, pairs map[string]string) {
			w.BeginSentence()
			w.WriteWord(word)
			if tag != "" {
				w.WriteWord(".tag=" + tag)
			}
			for k, v := range pairs {
				w.WriteWord("=" + k + "=" + v)
			}
			w.EndSentence()
		}
		if err != nil {
			reply("!trap", map[string]string{"message": err.Error()})
		} else {
			for _, row := range rows {
				reply("!re", row)
			}
		}
		reply("!done", nil)
	}
}

// readSentence reads the words of a sentence, up to the empty one that ends it.
func readSentence(r *bufio.Reader) ([]string, error) {
	var words []string
	for {
		length, err := readLength(r)
		if err != nil {
			return nil, err
		}
		if length == 0 {
			if len(words) == 0 {
				return nil, errors.New("empty sentence")
			}
			return words, nil
		}
		word := make([]byte, length)
		if _, err := io.ReadFull(r, word); err != nil {
			return nil, err
		}
		words = append(words, string(word))
	}
}

// readLength decodes the length of a word, as the RouterOS API encodes it.
func readLength(r *bufio.Reader) (int, error) {
	b, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	var extra int
	var length int
	switch {
	case b&0x80 == 0:
		return int(b), nil
	case b&0xC0 == 0x80:
		extra, length = 1, int(b&0x3F)
	case b&0xE0 == 0xC0:
		extra, length = 2, int(b&0x1F)
	case b&0xF0 == 0xE0:
		extra, length = 3, int(b&0x0F)
	default:
		extra = 4
	}
	for range extra {
		c, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		length = length<<8 | int(c)
	}
	return length, nil
}
