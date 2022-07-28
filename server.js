const WebSocketServer = require('ws').Server;
const fs = require('fs');
const https = require('https');

const PORT = 8080;
var passwd = 'pa$$word' // Should be get form db
const clients = new Set();

// Config the https options
const options = {
    cert: fs.readFileSync(`${__dirname}/pki/server/certs/server.cert.pem`),
    key: fs.readFileSync(`${__dirname}/pki/server/private/server.key.pem`),
    ca: [
        fs.readFileSync(`${__dirname}/pki/intermediate/certs/ca-chain.cert.pem`)
    ],
    requestCert: true,
    rejectUnauthorized: true,
    secureProtocol: 'TLS_method', // Allow any TLS protocol version up to TLSv1.3
    ciphers: 'AES128-GCM-SHA256:AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384',
    honorCipherOrder: true // Attempt to use the server's cipher suite preferences instead of the client's.
}

// Create the server
const server = new https.createServer(options);

// Create the websocket
const wss = new WebSocketServer({
    server,
    verifyClient: function (info, cb) {
        // Certificactes auth
        var success = !!info.req.client.authorized;
        console.log("Certificactes Authorized: ", success);
        // Basic auth
        if(success){
            var authentication = Buffer.from(info.req.headers.authorization,'base64').toString('utf-8');
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

// return validate days
const getDaysBetween = (validFrom, validTo) => {
    return Math.round(Math.abs(+validFrom - +validTo) / 8.64e7);
};

const getDaysRemaining = (validFrom, validTo) => {
    const daysRemaining = getDaysBetween(validFrom, validTo);
    if (new Date(validTo).getTime() < new Date().getTime()) {
        return -daysRemaining;
    }
    return daysRemaining;
};

const checkCertificateValidity = (daysRemaining, valid) => {
    let isValid = true;
    try {
        if(daysRemaining <= 0 || !valid) {
            isValid = false;
        }
    } catch(err)  {
        isValid = false;
    }
    return isValid;
};

wss.on('connection', function (ws, request) {
    // Check revoke status of the certificates
    const crt = request.connection.getPeerCertificate();
    const vFrom = crt.valid_from;
    const vTo = crt.valid_to;
    var validTo = new Date(vTo);

    var daysRemaining = getDaysRemaining(new Date(), validTo);
    var valid = request.socket.authorized || false;

    console.log("Days Remaining: ", daysRemaining);
    console.log("Expired: ", !valid);

    // Add client to the list
    clients.add(request.identity);
    ws.id = request.identity;
    console.log("Connected Charger ID: "  + ws.id);

    if(checkCertificateValidity(daysRemaining, valid) == true) {
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
    }
});

server.listen(PORT, ()=>{
    console.log( (new Date()) + " Server is listening on port " + PORT);
});