const WebSocket = require('ws');
const fs = require('fs');

const username = "ID_0001";
const BasicAuthPassword = "pa$$word";
const URL = "wss://localhost:8080/ocpp";
var reconn = null;

function startWebsocket() {
    var ws = new WebSocket(URL + "" + username, {
        key: fs.readFileSync(`${__dirname}/key/client-key.pem`),
        cert: fs.readFileSync(`${__dirname}/key/client-crt.pem`),

        // To enable security option 2, comment out the ca certificate and change the rejectUnauthorized: false
        ca: [
            fs.readFileSync(`${__dirname}/key/server-ca-crt.pem`)
        ],
        requestCert: true,
        rejectUnauthorized: true,
        perMessageDeflate: false,
        headers: {
            Authorization: 'Basic ' + Buffer.from(username + ':' + BasicAuthPassword).toString('base64'),
        },
    });

    ws.on('open', function() {
        clearInterval(reconn);

        let rawdata = fs.readFileSync('./json/TransactionEventRequest.json');
        let sTrans = JSON.parse(rawdata);
        sTrans.eventType = "Started";
        sTrans.timestamp = Date.now(); // new Date();

        ws.send(JSON.stringify(sTrans));
    });

    ws.on('message', function(msg) {
        console.log("From server: " + msg);
    });

    ws.on('error', function (err) {
        console.log(err.message);
    });

    ws.on('close', function() {
        ws = null;
        reconn = setTimeout(startWebsocket, 5000);
    });
}

startWebsocket();