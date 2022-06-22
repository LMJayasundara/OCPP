const WebSocket = require('ws');
const fs = require('fs');

const username = "ID_0001";
const BasicAuthPassword = "pa$$word";
const URL = "ws://127.0.0.1:5000/ocpp";
var reconn = null;
// var subdirectory = null;

function startWebsocket() {
    subdirectory = "ProtectedData"
    // var ws = new WebSocket(URL + "" + subdirectory, ["ocpp2.0", username, password], {
    var ws = new WebSocket(URL + "" + username, {
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