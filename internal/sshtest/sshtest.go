// Package sshtest runs an SSH server for tests: it takes a password, and answers the commands it
// is asked to run with a handler.
package sshtest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

type Server struct {
	// The address it listens on.
	Address string
	// The fingerprint of its host key, as ssh-keygen -l shows it: of the first, with several.
	HostKey string
	// The fingerprints of all its host keys.
	HostKeys []string

	mutex    sync.Mutex
	commands []string
	logins   int
	conns    int
}

// Connections returns how many connections it accepted, whether their handshake ended or not.
func (s *Server) Connections() int {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.conns
}

// Logins returns how many times a password was given to it, right or wrong.
func (s *Server) Logins() int {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.logins
}

// Commands returns the commands it was asked to run.
func (s *Server) Commands() []string {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return append([]string(nil), s.commands...)
}

// Start runs a server for user and password until the test ends. handle returns the output of a
// command, and an error to exit with status 1.
func Start(t testing.TB, user, password string, handle func(command string) ([]byte, error)) *Server {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return StartWithHostKeys(t, user, password, handle, signer)
}

// StartWithHostKeys is Start for a server with the host keys given, one of each kind: as a real
// one, it shows a client the one of the kind the client prefers.
func StartWithHostKeys(t testing.TB, user, password string, handle func(command string) ([]byte, error), hostKeys ...ssh.Signer) *Server {
	t.Helper()
	s := &Server{}
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			s.mutex.Lock()
			s.logins++
			s.mutex.Unlock()
			if c.User() == user && string(pass) == password {
				return nil, nil
			}
			return nil, errors.New("wrong password")
		},
	}
	for _, signer := range hostKeys {
		config.AddHostKey(signer)
		s.HostKeys = append(s.HostKeys, ssh.FingerprintSHA256(signer.PublicKey()))
	}
	s.HostKey = s.HostKeys[0]

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })

	s.Address = listener.Addr().String()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			s.mutex.Lock()
			s.conns++
			s.mutex.Unlock()
			go s.serve(conn, config, handle)
		}
	}()
	return s
}

func (s *Server) serve(conn net.Conn, config *ssh.ServerConfig, handle func(string) ([]byte, error)) {
	defer conn.Close()
	_, channels, requests, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(requests)
	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "only sessions")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			return
		}
		go func() {
			defer channel.Close()
			for req := range requests {
				if req.Type != "exec" {
					req.Reply(false, nil)
					continue
				}
				var payload struct{ Command string }
				if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
					req.Reply(false, nil)
					return
				}
				req.Reply(true, nil)
				s.mutex.Lock()
				s.commands = append(s.commands, payload.Command)
				s.mutex.Unlock()

				output, err := handle(payload.Command)
				channel.Write(output)
				status := make([]byte, 4)
				if err != nil {
					binary.BigEndian.PutUint32(status, 1)
					channel.Stderr().Write([]byte(err.Error()))
				}
				channel.SendRequest("exit-status", false, status)
				return
			}
		}()
	}
}
