package main

import (
	"context"
	"encoding/json"
	"log"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sfn"
)

type Data struct {
	Domain        string `json:"domain"`
	ClientKey     string `json:"client_key"`
	Authorization string `json:"authorization"`
	Status        string `json:"status"`
}

func handler(ctx context.Context, e events.DynamoDBEvent) {
	for _, record := range e.Records {
		if record.EventName != "INSERT" {
			continue
		}

		var data Data
		data.Status = "WaitDnsAuthorization"
		for name, value := range record.Change.NewImage {
			switch name {
			case "Domain":
				data.Domain = value.String()
			case "ClientKey":
				data.ClientKey = value.String()
			case "Authorization":
				data.Authorization = value.String()
			}
		}

		inputByte, err := json.Marshal(data)
		if err != nil {
			log.Fatal(err)
		}

		sfnClient := sfn.New(session.Must(session.NewSession()))
		startExecutionInput := &sfn.StartExecutionInput{
			Input:           aws.String(string(inputByte)),
			StateMachineArn: aws.String(os.Getenv("STATE_MACHINE_ARN")),
		}
		if _, err = sfnClient.StartExecution(startExecutionInput); err != nil {
			log.Fatal(err)
		}
	}
}

func main() {
	lambda.Start(handler)
}
