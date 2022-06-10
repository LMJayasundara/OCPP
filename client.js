const WebSocket = require('ws');
const encode = require('nodejs-base64-encode');

const username = "ID_0001"; // "ID_0002";
const password = "pa$$word";
const URL = "ws://127.0.0.1:5000/"; 
var basicAuthToken = encode.encode(username + ':' + password, 'base64');

const ws = new WebSocket(URL + "" + username, ["ocpp2.0", username, password], {
    perMessageDeflate: false,
    headers: {
        Authorization: `Basic ${basicAuthToken}`,
    },
});

ws.on('open', function() {
    ws.send("Charger_0001");
    // ws.send("Charger_0002");
});

ws.on('message', function(msg) {
    console.log("From server: " + msg);
});