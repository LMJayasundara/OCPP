const WebSocketServer = require('ws').Server;
const fs = require('fs');
const https = require('https');

const PORT = 8080;
var passwd = 'pa$$word' // should be get form db
const clients = new Set();

const server = new https.createServer({
    cert: fs.readFileSync(`${__dirname}/key/server-crt.pem`),
    key: fs.readFileSync(`${__dirname}/key/server-key.pem`),
    ca: [
      fs.readFileSync(`${__dirname}/key/client-ca-crt.pem`)
    ],
    requestCert: true,
    rejectUnauthorized: true,
    secureProtocol: 'TLS_method',
    ciphers: 'AES128-GCM-SHA256:AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384',
    ecdhCurve: 'secp521r1:secp384r1',
    honorCipherOrder: true
});

const wss = new WebSocketServer({
    server,
    verifyClient: function (info, cb) {
        var success = !!info.req.client.authorized;
        if(success){
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
    clients.add(request.identity);
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
        clients.delete(ws.id);
        console.log('Client disconnected '+ ws.id);
        console.log(clients);
    });

});

server.listen(PORT, ()=>{
    console.log( (new Date()) + " Server is listening on port " + PORT);
});