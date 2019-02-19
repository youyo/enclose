package main

import (
	"encoding/json"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
)

type Response struct {
	Domain       string `json:"domain"`
	Status       string `json:"status"`
	PrivateKey   string `json:"private_key,omitempty"`
	FullChainPem string `json:"full_chain_pem,omitempty"`
}

func handler(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	domain := request.PathParameters["domain"]

	dynamodbClient := dynamodb.New(session.Must(session.NewSession()))
	input := &dynamodb.GetItemInput{
		Key: map[string]*dynamodb.AttributeValue{
			"Domain": {
				S: aws.String(domain),
			},
		},
		TableName: aws.String(os.Getenv("DYNAMODB_TABLE_NAME")),
	}
	result, err := dynamodbClient.GetItem(input)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
		}, err
	}

	if len(result.Item) == 0 {
		return events.APIGatewayProxyResponse{
			Body:       "{}",
			StatusCode: 404,
		}, nil
	}

	var response Response
	for key, value := range result.Item {
		switch key {
		case "Domain":
			response.Domain = *value.S
		case "Status":
			response.Status = *value.S
		case "PrivateKey":
			response.PrivateKey = *value.S
		case "FullChainPem":
			response.FullChainPem = *value.S
		}
	}

	jsonByte, err := json.Marshal(response)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
		}, err
	}

	return events.APIGatewayProxyResponse{
		Body:       string(jsonByte),
		StatusCode: 200,
	}, nil
}

func main() {
	lambda.Start(handler)
}
