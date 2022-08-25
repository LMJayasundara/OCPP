const WebSocketServer = require('ws').Server;
const fs = require('fs');
const https = require('https');
const ocsp_server = require('./ocsp_server.js');
const yaml = require('js-yaml');
const spawn = require('child_process').spawn;
const kill = require('tree-kill');
var ocsp = require('ocsp');
var ocspCache = new ocsp.Cache();
var bodyparser = require('body-parser');
var express = require('express');
var app = express();
var api = require('./api.js');
var online = require('./online.js');
app.use(bodyparser.json());

// Define variables
var reocsp = null;
// var wss = null
const PORT = 8080;
const onlineclients = new Set();
const path = require('path');
const pkidir = path.resolve(__dirname + '/pki/').split(path.sep).join("/")+"/";
const DB_FILE_PATH = path.join(pkidir, 'db', 'user.db');
global.config = yaml.load(fs.readFileSync('config/config.yml', 'utf8'));

// Check user authentication
const checkAuth = function(id) {
    return new Promise(function(resolve, reject) {
        fs.readFile(DB_FILE_PATH, 'utf8', function(err, passFile) {
            if (err) {
                console.log(err);
                resolve(false);
            } else {
                const lines = passFile.split('\n');

                lines.forEach(function(line) {
                    if (line.split(':')[0] === id) {
                        resolve(line.split(':')[1]);
                    }
                });
            }
            resolve(false);
        });
    });
};

// Config the server options
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

// Create the express-https server
const server = new https.createServer(options, app);

// Create the websocket
// function initWebSocket() { 
    var wss = new WebSocketServer({
        server,
        rejectUnauthorized: true,
        verifyClient: function (info, cb) {
            // Certificactes auth
            var success = !!info.req.client.authorized;
            console.log("Certificactes Authorized: ", success);
            // Basic auth
            if(success){
                var authentication = Buffer.from(info.req.headers.authorization,'base64').toString('utf-8');
                var loginInfo = authentication.trim().split(':');
                if (!authentication) cb(false, 401, 'Authorization Required');
                else {
                    checkAuth(loginInfo[0]).then(function(hash) {
                        if(hash == false){
                            console.log("ERROR Username NOT matched");
                            cb(false, 401, 'Authorization Required');
                        }
                        else if(hash == loginInfo[1]){
                            console.log("Username and Password matched");
                            info.req.identity = loginInfo[0];
                            info.req.hash = loginInfo[1];
                            cb(true, 200, 'Authorized');
                        }
                        else{
                            console.log("ERROR Password NOT matched");
                            cb(false, 401, 'Authorization Required');
                        }
                    });
                }
            }
            else{
                cb(false, 401, 'Unauthorized')
            }
        }
    });
//     return wss;
// };

// Return validate days
const getDaysBetween = (validFrom, validTo) => {
    return Math.round(Math.abs(+validFrom - +validTo) / 8.64e7);
};

// Return days remaining
const getDaysRemaining = (validFrom, validTo) => {
    const daysRemaining = getDaysBetween(validFrom, validTo);
    if (new Date(validTo).getTime() < new Date().getTime()) {
        return -daysRemaining;
    }
    return daysRemaining;
};

// Check certificate valid status
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

// wss = initWebSocket();

// When client connect
(async function () {
    wss.on('connection', function (ws, req) {

        // Add client id to web socket
        ws.id = req.identity;
        // ws._ws = ws;
        // ws._wss = wss;

        // Get client certificates details
        var cert = req.socket.getPeerCertificate(true);
        var vTo = cert.valid_to;
        var validTo = new Date(vTo);
        var daysRemaining = getDaysRemaining(new Date(), validTo);
        var valid = req.socket.authorized || false;
        console.log("Days Remaining: ", daysRemaining);
        console.log("Expired: ", !valid);

        // Get client cert and issuer certificates
        var rawCert = cert.raw;
        var rawIssuer = cert.issuerCertificate.raw;

        // Use for OCSP stapling (Store the client certificate status in cache)
        ocsp.getOCSPURI(rawCert, function(err, uri) {
            if (err) console.log(err);
            var req = ocsp.request.generate(rawCert, rawIssuer);
            var options = {
                url: uri,
                ocsp: req.data
            };
            ocspCache.request(req.id, options, null);
        });

        // Check status of the certificates
        if(checkCertificateValidity(daysRemaining, valid) == true && !onlineclients.has(req.identity)) { // Check client certificate expired or client already connected
            onlineclients.add(req.identity);

            // Broadcast message to specific connected client
            wss.clients.forEach(function (client) {
                online.onlineAPI(app, client, wss);
                // console.log(ocspCache.cache);
                if(client.id == req.identity){
                    // Check revoke status of the certificates
                    ocsp.check({cert: rawCert, issuer: rawIssuer}, function(err, res) {
                        if(err) {
                            console.log(err.message);
                            client.send('Failed to obtain OCSP response!');
                            client.close();
                        } else {
                            // console.log(wss);
                            console.log(res.type);
                            var status = res.type;

                            if(status == 'good'){

                                // Add client to the online client list
                                onlineclients.add(req.identity);

                                console.log("Connected Charger ID: "  + ws.id);
                                client.send("Connected to the server");

                                // Send and resive data
                                client.on('message', function incoming(message) {
                                    console.log("From client: ", ws.id, ": ", message.toString());
                                    // let traResRow = fs.readFileSync('./json/TransactionEventResponse.json');
                                    // client.send(traResRow)
                                });

                                // Client disconnected event
                                client.on('close', function () {
                                    // Client remove from online client set
                                    onlineclients.delete(ws.id);
                                    console.log('Client disconnected '+ ws.id);
                                    console.log(onlineclients);
                                    client.close();
                                    restartServer();
                                });

                            }else{
                                client.send('Certificate is revoked!');
                            }
                        }                              
                    });
                };
            });
        }
        else{
            ws.send("Client already connected!")
        }

    });
})();

// Start the server
server.listen(PORT, ()=>{
    // init APIs
    api.initAPI(app);
    restartServer();
    console.log( (new Date()) + " Server is listening on port " + PORT);
});

// Server stop routine and events
var stopServer = function() {
    console.log("Received termination signal.");
    console.log("Stopping OCSP server...");
    kill(reocsp.pid, 'SIGKILL', function(err) {
        if(err){
            console.log(err.message);
        }
        else{
            console.log("Server stoped!");
        }
        process.exit();
    });
};

var restartServer = function() {
    // Start the OCSP server
    ocsp_server.startServer().then(function (cbocsp) {
        var ocsprenewint = 3000; // 3 second
        reocsp = cbocsp;
        // Restart the OCSP server every 1 min
        setInterval(() => {
            try {
                kill(cbocsp.pid, 'SIGKILL', function() { // err
                    // if(err){
                    //     console.log(err.message);
                    //     // process.exit();
                    // }
                    // else{
                    // console.log("Restart the ocsp server..");
                    cbocsp = spawn('openssl', [
                        'ocsp',
                        '-port', global.config.ca.ocsp.port,
                        '-text',
                        '-index', 'intermediate/index.txt',
                        '-CA', 'intermediate/certs/ca-chain.cert.pem',
                        '-rkey', 'ocsp/private/ocsp.key.pem',
                        '-rsigner', 'ocsp/certs/ocsp.cert.pem',
                        '-nmin', '1'
                    ], {
                        cwd: __dirname + '/pki/',
                        detached: false,
                        shell: true
                    });
        
                    cbocsp.on('error', function(error) {
                        console.log("OCSP server startup error: " + error);
                        reject(error);
                    });

                    reocsp = cbocsp;
                    // }
                });    
            } catch (error) {
                console.log(error.message);
                restartServer();
            }
        }, ocsprenewint);
    })
    .catch(function(error){
        console.log("Could not start OCSP server: " + error);
    });
}

process.on('SIGINT', stopServer);
process.on('SIGHUP', stopServer);
process.on('SIGQUIT', stopServer);