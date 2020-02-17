package main

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"net/http"
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
	if signer.Comment != "" {
		log.Printf("Server accepted '%s'.", signer.Comment)
	}
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

func LoadSignersFromFile(keysFileName string) ([]*DummySigner, error) {
	keysFileBytes, err := ioutil.ReadFile(keysFileName)
	if err != nil {
		return nil, err
	}
	signers, err := ParseAuthorizedKeys(keysFileBytes)
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
	body, err := ioutil.ReadAll(resp.Body)
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

func main() {
	if len(os.Args) != 4 {
		log.Fatal("Usage: whoarethey SERVER USERNAME KEYSFILE|github:USERNAME")
	}
	server, username, keysSource := os.Args[1], os.Args[2], os.Args[3]

	signers, err := LoadSigners(keysSource)
	if err != nil {
		log.Fatal("Failed to load public keys: ", err)
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
		fmt.Printf("Server accepted %d of %d keys.\n", numAccepted, numTried)
		os.Exit(0)
	} else if numTried < len(signers) {
		log.Fatal("Error dialing server: ", err)
	} else {
		fmt.Printf("Server accepted no keys.\n")
		os.Exit(10)
	}
}
