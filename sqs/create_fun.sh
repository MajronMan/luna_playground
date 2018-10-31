aws lambda create-function \
--region eu-west-1 \
--function-name ProcessSQSRecord \
--zip-file fileb://./ProcessSQSRecord.js.zip \
--role arn:aws:iam::497809487591:role/lambda_with_sqs \
--handler ProcessSQSRecord.handler \
--runtime nodejs6.10 \
--profile majronman
