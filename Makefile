.DEFAULT_GOAL := help
ProductId := enclose
Stage := ${STAGE}
Stackname := $(ProductId)-$(Stage)
S3Bucket := $(Stackname)-source
OutputTemplateFile := artifacts/sam-output.yaml

## Create bucket
s3bucket:
	aws s3 mb s3://$(S3Bucket)

## Build
build:
	GOOS=linux GOARCH=amd64 go build \
		 -o ./artifacts/post_certificate_request \
		 ./func/post_certificate_request
	GOOS=linux GOARCH=amd64 go build \
		 -o ./artifacts/get_domain_status \
		 ./func/get_domain_status
	GOOS=linux GOARCH=amd64 go build \
		 -o ./artifacts/handler_streams \
		 ./func/handler_streams
	GOOS=linux GOARCH=amd64 go build \
		 -o ./artifacts/check_text_record \
		 ./func/check_text_record
	GOOS=linux GOARCH=amd64 go build \
		 -o ./artifacts/execute_authorization \
		 ./func/execute_authorization
	GOOS=linux GOARCH=amd64 go build \
		 -o ./artifacts/create_cert \
		 ./func/create_cert

## Package
package:
	aws cloudformation package \
		--template-file template.yaml \
		--s3-bucket $(S3Bucket) \
		--output-template-file $(OutputTemplateFile)

## Deploy
deploy: package
	aws cloudformation deploy \
		--template-file $(OutputTemplateFile) \
		--stack-name $(Stackname) \
		--parameter-overrides "Stage=$(Stage)" \
		--capabilities CAPABILITY_IAM \
		--no-fail-on-empty-changeset

## Run openapi
swagger_server:
	docker container run \
		-d \
		--rm \
		--name swagger \
		-p 8080:8080 \
		-v `pwd`:/usr/share/nginx/html/api \
		-e API_URL=http://localhost:8080/api/swagger.yaml \
		swaggerapi/swagger-ui

## Show help
help:
	@make2help $(MAKEFILE_LIST)

.PHONY: help
.SILENT:
