const WebSocketServer = require('ws').Server;
const fs = require('fs');
const PORT = 5000;
var passwd = 'pa$$word' // should be get form db

const wss = new WebSocketServer({
    port: PORT,
    verifyClient: function (info, cb) {
        var token = info.req.headers['sec-websocket-protocol'].split(',');
        if (!token)
            cb(false, 401, 'Unauthorized')
        else {
            if (token[2] != passwd) {
                console.log("ERROR Username / Password NOT matched");
                cb(false, 401, 'Unauthorized')
            } else {
                console.log("Username / Password matched");
                cb(true, 200, 'Unauthorized')
            }
        }
    }
});

wss.on('connection', function (ws, req) {
    var urlData = req.headers['sec-websocket-protocol'].split(',');
    ws.id = urlData[1];
    console.log("Connected Charger ID: "  + ws.id);

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

    ws.on('close', function () {
        console.log('Client disconnected '+ ws.id);
    });

});

console.log( (new Date()) + " Server is listening on port " + PORT);