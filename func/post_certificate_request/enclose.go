package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"

	"github.com/aws/aws-lambda-go/events"
	"golang.org/x/crypto/acme"
)

type (
	Enclose struct {
		Request      Request
		Response     Response
		ClientKey    *rsa.PrivateKey
		PrivateKey   string
		FullChainPem string
	}

	Request struct {
		Domain    string `json:"domain"`
		Email     string `json:"email,omitempty"`
		AgreeTos  bool   `json:"agree_tos"`
		ClientKey string `json:"client_key,omitempty"`
	}

	Response struct {
		ClientKey      string `json:"client_key"`
		DnsRecordKey   string `json:"dns_record_key"`
		DnsRecordValue string `json:"dns_record_value"`
		DnsRecordType  string `json:"dns_record_type"`
	}
)

func NewEnclose() *Enclose {
	return new(Enclose)
}

func (r *Response) ToJsonString() (string, error) {
	jsonByte, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	response := string(jsonByte)

	return response, nil
}

func (e *Enclose) LoadRequestBodyFromEvent(event events.APIGatewayProxyRequest) error {
	if err := json.Unmarshal([]byte(event.Body), &e.Request); err != nil {
		return err
	}

	if e.Request.AgreeTos != true {
		return errors.New("must agree tos")
	}

	return nil
}

func (e *Enclose) CreateClientKey() error {
	if e.Request.ClientKey != "" {
		e.Response.ClientKey = e.Request.ClientKey
		block, _ := pem.Decode([]byte(e.Request.ClientKey))
		if block == nil || block.Type != "RSA PRIVATE KEY" {
			return errors.New("failed to decode PEM block")
		}

		clientKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return err
		}

		e.ClientKey = clientKey
		return nil
	}

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	e.ClientKey = clientKey

	clientKeyStr := string(
		pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(clientKey),
			},
		),
	)
	e.Response.ClientKey = clientKeyStr

	return nil
}

func SelectChallenge(challenges []*acme.Challenge) (*acme.Challenge, error) {
	for _, challenge := range challenges {
		if challenge.Type == "dns-01" {
			return challenge, nil
		}
	}
	return nil, errors.New("Can not find 'dns-01' challenge.")
}
