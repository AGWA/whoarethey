package main

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"log"
	"os"
)

type DummySigner struct {
	PubKey  ssh.PublicKey
	Comment string
	Used    bool
}

func (signer *DummySigner) PublicKey() ssh.PublicKey {
	return signer.PubKey
}
func (signer *DummySigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	signer.Used = true
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

func main() {
	if len(os.Args) != 4 {
		log.Fatal("Usage: whoarethey SERVER USERNAME KEYSFILE")
	}
	server, username, keysFileName := os.Args[1], os.Args[2], os.Args[3]

	keysFileBytes, err := ioutil.ReadFile(keysFileName)
	if err != nil {
		log.Fatal("Failed to read keys file: ", err)
	}
	signers, err := ParseAuthorizedKeys(keysFileBytes)
	if err != nil {
		log.Fatal("Failed to parse keys file: ", err)
	}

	config := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{MakeAuthMethod(signers)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	_, err = ssh.Dial("tcp", server, config)
	success := false
	for _, signer := range signers {
		if signer.Used {
			fmt.Println(signer.Comment)
			success = true
		}
	}
	if !success {
		log.Fatal("Failed to dial server: ", err)
	}
}
