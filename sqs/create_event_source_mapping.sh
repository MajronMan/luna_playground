aws lambda create-event-source-mapping \
--region eu-west-1 \
--function-name ProcessSQSRecord \
--event-source arn:aws:sqs:eu-west-1:497809487591:test_queue	 \
--batch-size 1 \
--profile majronman
