const WebSocketServer = require('ws').Server;
const fs = require('fs');
const https = require('https');
const http = require('http');
const ocsp_server = require('./ocsp_server.js');
const yaml = require('js-yaml');
const spawn = require('child_process').spawn;
const kill = require('tree-kill');
var ocsp = require('ocsp');
var ocspCache = new ocsp.Cache();
var bodyparser = require('body-parser');
var express = require('express');
var sapp = express();
var app = express();
var apiDis = require('./apiDis.js');
var apiCon = require('./apiCon.js');
sapp.use(bodyparser.json());
app.use(bodyparser.json());

// Define variables
var reocsp = null;
const SPORT = 8080;
const PORT = 6060;
const onlineclients = new Set();
const path = require('path');
const pkidir = path.resolve(__dirname + '/pki/').split(path.sep).join("/")+"/";
const DB_FILE_PATH = path.join(pkidir, 'db', 'user.db');
global.config = yaml.load(fs.readFileSync('config/config.yml', 'utf8'));

const wsEvents = require('ws-events');

// Config Variables
// 1: Unsecured Transport with Basic Authentication Profile
// 2: TLS with Basic Authentication Profile
// 3: TLS with Client Side Certificates Profile
const SECURITY_PROFILE = 2;

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
const sserver = new https.createServer(options, sapp);
const wss = new WebSocketServer({
    server: sserver,
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

const server = new http.createServer({}, app);
const wsn = new WebSocketServer({
    server: server,
    verifyClient: function (info, cb) {
        var authentication = Buffer.from(info.req.headers.authorization,'base64').toString('utf-8');
        var loginInfo = authentication.trim().split(':');
        if (!authentication)
            cb(false, 401, 'Authorization Required');
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
});

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

// When client connect
(async function () {
    wss.on('connection', async function (ws, req) {

        console.log("connected");
        // Add client id to web socket
        ws.id = req.identity;

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

        // Broadcast message to specific connected client
        return new Promise(async function(resolve, reject) {
            const ccc = await Array.from(wss.clients).find(client => (client.readyState === client.OPEN && client.id == req.identity));
            resolve(ccc)
        }).then((client)=>{

            if(client != undefined){
                if(checkCertificateValidity(daysRemaining, valid) == true){
                    // console.log(ocspCache.cache);
                    
                    apiCon.onlineAPI(sapp, wss, client);
                    // Check revoke status of the certificates
                    ocsp.check({cert: rawCert, issuer: rawIssuer}, function(err, res) {
                        if(err) {
                            console.log(err.message);
                            client.send(err.message);
                            if(err.message == "OCSP Status: revoked"){
                                client.send("Please update the user certificate");
                            }
                            else{
                                client.close();
                            }                         
                        } else {
                            console.log(res.type);
                            var status = res.type;

                            // Check status of the certificates
                            if(status == 'good' && !onlineclients.has(req.identity)){
                                // Add client to the online client list
                                onlineclients.add(req.identity);

                                console.log("Connected Charger ID: "  + client.id);
                                client.send("Connected to the server");

                                // Send and resive data
                                client.on('message', function incoming(message) {
                                    // console.log("From client: ", client.id, ": ", message.toString());
                                    // let traResRow = fs.readFileSync('./json/TransactionEventResponse.json');
                                    // client.send(traResRow)
                                });

                                // Client disconnected event
                                client.on('close', function () {
                                    // Client remove from online client set
                                    onlineclients.delete(client.id);
                                    console.log('Client disconnected '+ client.id);
                                    console.log(onlineclients);
                                    client.close();
                                    restartServer();
                                });
                            }
                            else{
                                // apiCon.onlineAPI(sapp, wss, client);
                                client.send("Client already connected!");
                            }
                        }                              
                    });      
                }
                else{
                    client.send("Client certificate expired!");
                }
            }
            else{
                console.log("Client Undefined!");
            }
        });
    });

    wsn.on('connection', async function (ws, req) {
        console.log("connected");
        ws.id = req.identity;
        console.log(req.identity);
        // Broadcast message to specific connected client
        return new Promise(async function(resolve, reject) {
            const ccc = await Array.from(wsn.clients).find(client => (client.readyState === client.OPEN && client.id == req.identity));
            resolve(ccc)
        }).then((client)=>{

            if(client != undefined){
                apiCon.onlineAPI(app, wsn, client);
                onlineclients.add(req.identity);

                console.log("Connected Charger ID: "  + client.id);
                client.send("Connected to the server");

                // Send and resive data
                client.on('message', function incoming(message) {
                    // console.log("From client: ", client.id, ": ", message.toString());
                    // let traResRow = fs.readFileSync('./json/TransactionEventResponse.json');
                    // client.send(traResRow)
                });

                // Client disconnected event
                client.on('close', function () {
                    // Client remove from online client set
                    onlineclients.delete(client.id);
                    console.log('Client disconnected '+ client.id);
                    console.log(onlineclients);
                    client.close();
                    restartServer();
                });
            }
            else{
                console.log("Client Undefined!");
            }
        });
    });
})();

// Start the server
sserver.listen(SPORT, ()=>{
    // init APIs
    apiDis.initAPI(sapp);
    restartServer();
    console.log( (new Date()) + " Secure server is listening on port " + SPORT);
});

// Start the server
server.listen(PORT, ()=>{
    // init APIs
    apiDis.initAPI(app);
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
        // Restart the OCSP server every 3 second
        setInterval(() => {
            try {
                kill(cbocsp.pid, 'SIGKILL', function() {
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