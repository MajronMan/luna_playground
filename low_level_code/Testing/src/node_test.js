const AWS = require('aws-sdk')
const async = require('async')

var lambda = new AWS.Lambda({region: "us-east-1"});

var params = {
  FunctionName: "testFunc",
  Payload: ""
 };

function repeatInvoke(n, callback) {
	return (n < 1) ? callback() : lambda.invoke(params, () => repeatInvoke(n-1, callback))
}

console.time()
repeatInvoke(1000, () => console.timeEnd())

// console.time()
// async.times(2, (_, next) => { lambda.invoke(params, next) }, (err, data) => {
// 	console.timeEnd()
// })
