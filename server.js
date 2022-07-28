const WebSocketServer = require('ws').Server;
const fs = require('fs');
const https = require('https');

const ocsp_server = require('./ocsp_server.js');
const yaml = require('js-yaml');
const spawn = require('child_process').spawn;
const kill = require('tree-kill');
var reocsp = null;
global.config = yaml.load(fs.readFileSync('config/config.yml', 'utf8'));

var ocsp = require('ocsp');
var ocspCache = new ocsp.Cache();

var bodyparser = require('body-parser');
var express = require('express');
var app = express();
var api = require('./api.js');
app.use(bodyparser.json());

const PORT = 8080;
const passwd = 'pa$$word' // Should be get form db
const onlineclients = new Set();

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
const server = new https.createServer(options, app);

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
    // rejectUnauthorized: false
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

wss.on('connection', function (ws, req) {
    ws.id = req.identity;

    var cert = req.socket.getPeerCertificate(true);
    var vTo = cert.valid_to;
    var validTo = new Date(vTo);
    var daysRemaining = getDaysRemaining(new Date(), validTo);
    var valid = req.socket.authorized || false;
    console.log("Days Remaining: ", daysRemaining);
    console.log("Expired: ", !valid);

    var cert = req.socket.getPeerCertificate(true);
    var rawCert = cert.raw;
    var rawIssuer = cert.issuerCertificate.raw;

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
    if(checkCertificateValidity(daysRemaining, valid) == true && !onlineclients.has(req.identity)) {
        ws.on('message', function incoming(message) {
            // Broadcast message to specific connected client
            wss.clients.forEach(function (client) {
                // console.log(ocspCache.cache);
                if(client.id == req.identity){
                    // Check revoke status of the certificates
                    ocsp.check({cert: rawCert, issuer: rawIssuer}, function(err, res) {
                        if(err) {
                            console.log(err.message);
                            client.send('Failed to obtain OCSP response!');
                        } else {
                            console.log(res.type);
                            var status = res.type;
                            if(status == 'good'){
                                // Add client to the list
                                onlineclients.add(req.identity);

                                console.log("Connected Charger ID: "  + ws.id);
                                console.log("From client: ", ws.id, ": ", message.toString());
                                let traResRow = fs.readFileSync('./json/TransactionEventResponse.json');
                                let traRes = JSON.parse(traResRow);
                                client.send(JSON.stringify(traRes));
                            }else{
                                client.send('Certificate is revoked!');
                            }
                        }                              
                    });
                };
            });
        });
    
        ws.on('close', function () {
            onlineclients.delete(ws.id);
            console.log('Client disconnected '+ ws.id);
            console.log(onlineclients);
        });
    }
    else{
        ws.send("Client already connected!")
    }

});

server.listen(PORT, ()=>{
    api.initAPI(app);
    ocsp_server.startServer().then(function (cbocsp) {
        var ocsprenewint = 1000 * 60; // 1min
        reocsp = cbocsp;

        setInterval(() => {
            kill(cbocsp.pid, 'SIGKILL', function(err) {
                if(err){
                    console.log(err.message);
                    process.exit();
                }
                else{
                    console.log("Restart the ocsp server..");
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
                        detached: true,
                        shell: true
                    });
        
                    cbocsp.on('error', function(error) {
                        console.log("OCSP server startup error: " + error);
                        reject(error);
                    });

                    reocsp = cbocsp;
                }
            });

        }, ocsprenewint);

    })
    .catch(function(error){
        console.log("Could not start OCSP server: " + error);
    });

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

process.on('SIGINT', stopServer);
process.on('SIGHUP', stopServer);
process.on('SIGQUIT', stopServer);