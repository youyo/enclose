package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"golang.org/x/crypto/acme"
)

type (
	InputOutput struct {
		Domain        string `json:"domain"`
		ClientKey     string `json:"client_key"`
		Authorization string `json:"authorization"`
		Status        string `json:"status"`
	}
)

func SelectChallenge(challenges []*acme.Challenge) (*acme.Challenge, error) {
	for _, challenge := range challenges {
		if challenge.Type == "dns-01" {
			return challenge, nil
		}
	}
	return nil, errors.New("Can not find 'dns-01' challenge.")
}

func handler(ctx context.Context, input InputOutput) (InputOutput, error) {
	block, _ := pem.Decode([]byte(input.ClientKey))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return input, errors.New("failed to decode PEM block")
	}

	clientKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return input, err
	}

	acmeClient := &acme.Client{
		Key:          clientKey,
		DirectoryURL: os.Getenv("LetsEncryptURL"),
	}

	authorizationBytes := []byte(input.Authorization)
	var authorization *acme.Authorization
	if err := json.Unmarshal(authorizationBytes, &authorization); err != nil {
		return input, err
	}

	challenge, err := SelectChallenge(authorization.Challenges)
	if err != nil {
		return input, err
	}

	dnsvalue, err := acmeClient.DNS01ChallengeRecord(challenge.Token)
	if err != nil {
		return input, err
	}

	record := "_acme-challenge." + input.Domain
	txtrecords, err := net.LookupTXT(record)
	if err != nil {
		return input, nil
	}

	for _, txt := range txtrecords {
		if txt == dnsvalue {
			input.Status = "TextRecordMatched"
		}
	}

	return input, nil
}

func main() {
	lambda.Start(handler)
}
