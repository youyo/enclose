package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/k0kubun/pp"
	"golang.org/x/crypto/acme"
)

func handler(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	enclose := NewEnclose()

	if err := enclose.LoadRequestBodyFromEvent(request); err != nil {
		resp := map[string]string{
			"message": fmt.Sprintf("%s", err),
		}
		respJson, _ := json.Marshal(resp)
		return events.APIGatewayProxyResponse{
			Body:       string(respJson),
			StatusCode: 400,
		}, nil
	}

	dynamodbClient := dynamodb.New(session.Must(session.NewSession()))
	input := &dynamodb.GetItemInput{
		Key: map[string]*dynamodb.AttributeValue{
			"Domain": {
				S: aws.String(enclose.Request.Domain),
			},
		},
		TableName: aws.String(os.Getenv("DYNAMODB_TABLE_NAME")),
	}
	if result, err := dynamodbClient.GetItem(input); err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
		}, err
	} else if len(result.Item) != 0 {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
		}, nil
	}

	enclose.Response.DnsRecordKey = "_acme-challenge." + enclose.Request.Domain
	enclose.Response.DnsRecordType = "TXT"

	if err := enclose.CreateClientKey(); err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
		}, err
	}

	acmeClient := &acme.Client{
		Key:          enclose.ClientKey,
		DirectoryURL: os.Getenv("LetsEncryptURL"),
	}

	ctx := context.Background()

	if _, err := acmeClient.Register(ctx, &acme.Account{}, acme.AcceptTOS); err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
		}, err
	}

	authorization, err := acmeClient.Authorize(ctx, enclose.Request.Domain)
	if err != nil {
		pp.Println(err)
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
		}, err
	}

	challenge, err := SelectChallenge(authorization.Challenges)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
		}, err
	}

	enclose.Response.DnsRecordValue, err = acmeClient.DNS01ChallengeRecord(challenge.Token)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
		}, err
	}

	authorizationByte, err := json.Marshal(authorization)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
		}, err
	}
	authorizationJson := string(authorizationByte)

	putItemInput := &dynamodb.PutItemInput{
		Item: map[string]*dynamodb.AttributeValue{
			"ClientKey": {
				S: aws.String(enclose.Response.ClientKey),
			},
			"Authorization": {
				S: aws.String(authorizationJson),
			},
			"Domain": {
				S: aws.String(enclose.Request.Domain),
			},
			"Status": {
				S: aws.String("WaitDnsAuthorization"),
			},
			"Timestamp": {
				N: aws.String(strconv.FormatInt(time.Now().UTC().Unix(), 10)),
			},
			"TTL": {
				N: aws.String(strconv.FormatInt(time.Now().UTC().AddDate(0, 1, 0).Unix(), 10)),
			},
		},
		TableName:                aws.String(os.Getenv("DYNAMODB_TABLE_NAME")),
		ConditionExpression:      aws.String("attribute_not_exists(#Domain)"),
		ExpressionAttributeNames: map[string]*string{"#Domain": aws.String("Domain")},
	}
	if _, err := dynamodbClient.PutItem(putItemInput); err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
		}, err
	}

	response, err := enclose.Response.ToJsonString()
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
		}, err
	}

	return events.APIGatewayProxyResponse{
		Body:       response,
		StatusCode: 201,
	}, nil
}

func main() {
	lambda.Start(handler)
}
