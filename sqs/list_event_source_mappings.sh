aws lambda list-event-source-mappings \
--region eu-west-1 \
--function-name ProcessSQSRecord \
--event-source arn:aws:sqs:eu-west-1:497809487591:test_queue \
--profile majronman
