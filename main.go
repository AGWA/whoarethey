// Copyright (C) 2020-2023 Andrew Ayer
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// Except as contained in this notice, the name(s) of the above copyright
// holders shall not be used in advertising or otherwise to promote the
// sale, use or other dealings in this Software without prior written
// authorization.

package main

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"net/http"
	"os"
	"strings"
)

type DummySigner struct {
	PubKey   ssh.PublicKey
	Comment  string
	Tried    bool
	Accepted bool
}

func (signer *DummySigner) PublicKey() ssh.PublicKey {
	signer.Tried = true
	return signer.PubKey
}
func (signer *DummySigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	signer.Accepted = true
	//if signer.Comment != "" {
	//	log.Printf("Server accepted '%s'.", signer.Comment)
	//}
	return &ssh.Signature{
		Format: signer.PubKey.Type(),
	}, nil
}
func ParseAuthorizedKeys(in []byte) ([]*DummySigner, error) {
	signers := []*DummySigner{}
	for len(in) > 0 {
		pubkey, comment, _, rest, err := ssh.ParseAuthorizedKey(in)
		if err != nil {
			return nil, err
		}
		signers = append(signers, &DummySigner{
			PubKey:  pubkey,
			Comment: comment,
		})
		in = rest
	}
	return signers, nil
}
func MakeAuthMethod(dummySigners []*DummySigner) ssh.AuthMethod {
	signers := make([]ssh.Signer, len(dummySigners))
	for i := range dummySigners {
		signers[i] = dummySigners[i]
	}
	return ssh.PublicKeysCallback(func() ([]ssh.Signer, error) { return signers, nil })
}

func LoadSignersFromFile(filename string) ([]*DummySigner, error) {
	fileBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	signers, err := ParseAuthorizedKeys(fileBytes)
	if err != nil {
		return nil, err
	}
	return signers, nil
}
func LoadSignersFromGitHub(username string) ([]*DummySigner, error) {
	url := "https://github.com/" + username + ".keys"
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Error retrieving %s: %s", url, resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	signers, err := ParseAuthorizedKeys(body)
	if err != nil {
		return nil, err
	}
	return signers, nil
}
func LoadSigners(source string) ([]*DummySigner, error) {
	if strings.HasPrefix(source, "github:") {
		return LoadSignersFromGitHub(strings.TrimPrefix(source, "github:"))
	} else {
		return LoadSignersFromFile(source)
	}
}

func TryKeys(server string, username string, keysSource string) (bool, error) {
	signers, err := LoadSigners(keysSource)
	if err != nil {
		return false, fmt.Errorf("Failed to load public keys: %w", err)
	}

	config := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{MakeAuthMethod(signers)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	_, err = ssh.Dial("tcp", server, config)
	numTried := 0
	numAccepted := 0
	for _, signer := range signers {
		if signer.Tried {
			numTried++
		}
		if signer.Accepted {
			numAccepted++
		}
	}
	if numAccepted > 0 {
		return true, nil
	} else if numTried == len(signers) {
		return false, nil
	} else {
		return false, fmt.Errorf("Error dialing server: %w", err)
	}
}

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "Usage: whoarethey HOST:PORT USERNAME KEYSFILE|github:USERNAME...")
		os.Exit(2)
	}
	server, username, keySources := os.Args[1], os.Args[2], os.Args[3:]

	type result struct {
		keySource string
		accepted  bool
		err       error
	}
	results := make(chan result)
	for _, keySource := range keySources {
		go func(keySource string) {
			accepted, err := TryKeys(server, username, keySource)
			results <- result{
				keySource: keySource,
				accepted:  accepted,
				err:       err,
			}
		}(keySource)
	}

	anyAccepted := false
	anyErrors := false
	for range keySources {
		result := <-results
		if result.accepted {
			fmt.Fprintln(os.Stdout, result.keySource)
			anyAccepted = true
		} else if result.err != nil {
			fmt.Fprintf(os.Stderr, "%s: %s\n", result.keySource, result.err)
			anyErrors = true
		}
	}

	if anyAccepted {
		os.Exit(0)
	} else if anyErrors {
		os.Exit(4)
	} else {
		fmt.Fprintln(os.Stderr, "Server accepted none of the provided keys.")
		os.Exit(1)
	}
}
