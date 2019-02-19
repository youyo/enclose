package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
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

func handler(ctx context.Context, input InputOutput) error {
	block, _ := pem.Decode([]byte(input.ClientKey))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return errors.New("failed to decode PEM block")
	}

	clientKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	acmeClient := &acme.Client{
		Key:          clientKey,
		DirectoryURL: os.Getenv("LetsEncryptURL"),
	}

	privateKeyBytes, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	privateKey := string(
		pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(privateKeyBytes),
			},
		),
	)

	subj := pkix.Name{CommonName: input.Domain}
	asn1Subj, err := asn1.Marshal(subj.ToRDNSequence())
	if err != nil {
		return err
	}

	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKeyBytes)
	if err != nil {
		return err
	}

	certificates, _, err := acmeClient.CreateCert(ctx, csr, 0, true)
	if err != nil {
		return err
	}

	var fullChainPem string
	for _, certificate := range certificates {
		fullChainPem = fullChainPem + string(
			pem.EncodeToMemory(
				&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: certificate,
				},
			),
		)
	}

	updateItemInput := &dynamodb.UpdateItemInput{
		Key: map[string]*dynamodb.AttributeValue{
			"Domain": {
				S: aws.String(input.Domain),
			},
		},
		AttributeUpdates: map[string]*dynamodb.AttributeValueUpdate{
			"PrivateKey": {
				Value: &dynamodb.AttributeValue{
					S: aws.String(privateKey),
				},
				Action: aws.String("PUT"),
			},
			"FullChainPem": {
				Value: &dynamodb.AttributeValue{
					S: aws.String(fullChainPem),
				},
				Action: aws.String("PUT"),
			},
			"Status": {
				Value: &dynamodb.AttributeValue{
					S: aws.String("Complete"),
				},
				Action: aws.String("PUT"),
			},
		},
		TableName: aws.String(os.Getenv("DYNAMODB_TABLE_NAME")),
	}
	dynamodbClient := dynamodb.New(session.Must(session.NewSession()))
	_, err = dynamodbClient.UpdateItem(updateItemInput)

	return err
}

func main() {
	lambda.Start(handler)
}
