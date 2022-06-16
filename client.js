const WebSocket = require('ws');
const fs = require('fs');

const username = "ID_0001";
const password = "pa$$word";
const URL = "ws://127.0.0.1:5000/";
var reconn = null;

function startWebsocket() {
    var ws = new WebSocket(URL + "" + username, ["ocpp2.0", username, password], {
        perMessageDeflate: false
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
        console.log(err);
    });

    ws.on('close', function() {
        ws = null;
        reconn = setTimeout(startWebsocket, 5000);
    });
}

startWebsocket();