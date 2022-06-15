const fs = require('fs');

let rawdata = fs.readFileSync('./json/TransactionEventRequest.json');
let data = JSON.parse(rawdata);
data.eventType = "Started";
data.timestamp = 12;
console.log(data);