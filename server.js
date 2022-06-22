const WebSocketServer = require('ws').Server;
const fs = require('fs');
const PORT = 5000;
var passwd = 'pa$$word' // should be get form db

const wss = new WebSocketServer({
    port: PORT,
    verifyClient: function (info, cb) {
        console.log(info.req.url);
        if(info.req.url !== "/ocpp"){
            var authentication = Buffer.from(info.req.headers.authorization.replace(/Basic/, '').trim(),'base64').toString('utf-8');
            if (!authentication)
                cb(false, 401, 'Authorization Required');
            else {
                var loginInfo = authentication.trim().split(':');
                if (loginInfo[1] != passwd) {
                    console.log("ERROR Username / Password NOT matched");
                    cb(false, 401, 'Authorization Required');
                } else {
                    console.log("Username / Password matched");
                    info.req.identity = loginInfo[0];
                    cb(true, 200, 'Authorized');
                }
            }
        }
        else{
            cb(false, 401, 'Unauthorized')
        }
        
    },
    rejectUnauthorized: false
});

wss.on('connection', function (ws, request) {
    ws.id = request.identity;
    console.log("Connected Charger ID: "  + ws.id);

    ws.on('message', function (msg) {
        // Broadcast message to all connected clients
        wss.clients.forEach(function (client) {
            if(client.id == request.identity){
                console.log("From client",ws.id,": ", msg.toString());

                let traResRow = fs.readFileSync('./json/TransactionEventResponse.json');
                let traRes = JSON.parse(traResRow);
                client.send(JSON.stringify(traRes));
            };
        });
    });

    ws.on('close', function () {
        console.log('Client disconnected '+ ws.id);
        // console.log(ws);
    });

});

console.log( (new Date()) + " Server is listening on port " + PORT);