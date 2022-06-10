const WebSocket = require('ws');

const PORT = 5000;

const wss = new WebSocket.Server({
    port: PORT
});

wss.on('connection', function (ws, req) {
    var urlData = req.headers['sec-websocket-protocol'].split(',');
    ws.id = urlData[1];
    console.log("Connected Charger ID: "  + ws.id);

    ws.on('message', function (msg) {
        // console.log("From client: ", msg.toString());
        // ws.send("Hello " + ws.id);

        // Broadcast that message to all connected clients
        wss.clients.forEach(function (client) {
            if(client.id == urlData[1]){
                console.log("From client: ", msg.toString());
                client.send("Hello " + ws.id);
            };
        });
    });

    ws.on('close', function () {
        console.log('Client disconnected '+ ws.id);
    })

});

console.log( (new Date()) + " Server is listening on port " + PORT);