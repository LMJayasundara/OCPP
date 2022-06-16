const WebSocket = require('ws');
const fs = require('fs');

const PORT = 5000;

const wss = new WebSocket.Server({
    port: PORT
});

var passwd = 'pa$$word' // should be get form db

wss.on('connection', function (ws, req) {
    var urlData = req.headers['sec-websocket-protocol'].split(',');
    ws.id = urlData[1];
    ws.passwd = urlData[2]
    console.log("Connected Charger ID: "  + ws.id);

    if (ws.id == urlData[1] && ws.passwd == passwd) {
        console.log("Username / Password matched");

        ws.on('message', function (msg) {
            // console.log("From client: ", msg.toString());
            // ws.send("Hello " + ws.id);
    
            // Broadcast message to all connected clients
            wss.clients.forEach(function (client) {
                if(client.id == urlData[1]){
                    console.log("From client: ", msg.toString());
    
                    let traResRow = fs.readFileSync('./json/TransactionEventResponse.json');
                    let traRes = JSON.parse(traResRow);
                    client.send(JSON.stringify(traRes));
                };
            });
        });

    } else {
        console.log("ERROR Username / Password NOT matched");
    }

    ws.on('close', function () {
        console.log('Client disconnected '+ ws.id);
    });

});

console.log( (new Date()) + " Server is listening on port " + PORT);