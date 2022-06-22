// const fs = require('fs');

// let rawdata = fs.readFileSync('./json/TransactionEventRequest.json');
// let data = JSON.parse(rawdata);
// data.eventType = "Started";
// data.timestamp = 12;
// console.log(data);

// const username = "ID_0001";
// const BasicAuthPassword = "pa$$word";
// const encode = require('nodejs-base64-encode');

// const jwt = require('jsonwebtoken');
// const dotenv = require('dotenv');

// // var basicAuthToken = encode.encode(username + ':' + password, 'base64');
// // console.log(basicAuthToken);


// dotenv.config();

// let jwtSecretKey = process.env.JWT_SECRET_KEY;
// let data = {
//     username: username,
//     password: password,
// }

// const token = jwt.sign(data, jwtSecretKey);
// console.log(token);

const username = "ID_0001";
const BasicAuthPassword = "pa$$word";
console.log('Basic ' + Buffer.from(username + ':' + BasicAuthPassword).toString('base64'));