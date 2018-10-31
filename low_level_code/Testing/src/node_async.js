const AWS = require('aws-sdk')
const async = require('async')

var lambda = new AWS.Lambda({region: "us-east-1"});

var params = {
  FunctionName: "testFunc",
  Payload: ""
 };

console.time()
async.times(1000, (_, next) => { lambda.invoke(params, next) }, () => {
	console.timeEnd()
})
