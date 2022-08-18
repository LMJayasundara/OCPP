// Import libs
const WebSocket = require('ws');
const fs = require('fs-extra');
const path = require('path');

// Define variables
const username = "ID001";
const URL = "wss://localhost:8080/";
var reconn = null;
const DB_FILE_PATH = path.join('credential.db');

const wsEvents = require('ws-events');
var exec = require('child_process').exec;
const crypto = require('crypto');

// Check password and by username
const gethash = function(id) {
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

// Crete new credential.db file when update the client password
const addUser = function(username, passhash) {
    return new Promise(function(resolve, reject) {
        fs.unlinkSync(DB_FILE_PATH);
        fs.ensureFileSync(DB_FILE_PATH);
        passfile = username + ':' + passhash +'\n';
        fs.writeFileSync(DB_FILE_PATH, passfile, 'utf8');
        resolve(true);
    });
};

var createClient = function(passphrase) {
    // Prepare client dir
    fs.ensureDirSync('new');
    fs.ensureDirSync('new/certs');
    fs.ensureDirSync('new/private');
    fs.ensureDirSync('new/csr');

    var rootname = 'intermediate';
    var chainname = 'ca-chain';
    var passphrase = 'adminpass';
    var days = 365;
    var country = 'LK';
    var state = 'WEST';
    var locality = 'COL';
    var organization = 'VEGA';
    var unit = 'CG';
    var commonname = "ID001_"+Date.now();

    const pkidir = path.resolve(__dirname + '/pki/').split(path.sep).join("/")+"/";

    openssl_client = fs.readFileSync(__dirname + '/openssl_client.cnf.tpl', 'utf8');
    openssl_client = openssl_client.replace(/{basedir}/g, pkidir + 'intermediate');
    openssl_client = openssl_client.replace(/{rootname}/g, rootname);
    openssl_client = openssl_client.replace(/{chainname}/g, chainname);
    openssl_client = openssl_client.replace(/{name}/g, username);
    openssl_client = openssl_client.replace(/{days}/g, days);
    openssl_client = openssl_client.replace(/{country}/g, country);
    openssl_client = openssl_client.replace(/{state}/g, state);
    openssl_client = openssl_client.replace(/{locality}/g, locality);
    openssl_client = openssl_client.replace(/{organization}/g, organization);
    openssl_client = openssl_client.replace(/{unit}/g, unit);
    openssl_client = openssl_client.replace(/{commonname}/g, commonname);
    fs.writeFileSync('new/openssl.cnf', openssl_client);

    console.log(">>> Creating Client Keys");

    return new Promise(function(resolve, reject) {
        // Create key
        exec('openssl req -config openssl.cnf -new -newkey rsa:2048 -nodes -keyout private/client.key.pem -out csr/client.csr.pem', {
            cwd: 'new'
        }, function(err, stdout, stderr) {
            console.log("err: ", err);
            console.log("stdout: ", stdout);
            console.log("stderr: ", stderr);
            resolve();
        });

    });
};

// Start web socket function
function startWebsocket() {
    gethash(username).then(function(hash) {
        if(hash != false){
            // Define websocket
            var ws = new WebSocket(URL + "" + username, {
                key: fs.readFileSync(`${__dirname}/ID001/private/client.key.pem`),
                cert: fs.readFileSync(`${__dirname}/ID001/certs/client.cert.pem`),

                // To enable security option 2, comment out the ca certificate and change the rejectUnauthorized: false
                ca: [
                    fs.readFileSync(`${__dirname}/ca-chain.cert.pem`)
                ],
                requestCert: true,
                rejectUnauthorized: true,
                perMessageDeflate: false,
                // Use for basic authentication
                headers: {
                    Authorization: Buffer.from(username + ':' + hash).toString('base64')
                },
            });

            const evt = wsEvents(ws);

            // Trigger event when client is connected
            ws.on('open', function() {

                checkCert().then(function(daysRemaining){
                    // console.log(daysRemaining);
                    if(daysRemaining <= 30){
                        passphrase = "adminpass";
                        createClient(passphrase).then(function(){
                            evt.emit('SignCertificateRequest', {
                                csr: fs.readFileSync(path.join('new/csr/client.csr.pem'), 'utf8'),
                                typeOfCertificate: "ChargingStationCertificate"
                            });
                        });
                    }
                });

                // Clear reconnecting interval
                clearInterval(reconn);

                // let rawdata = fs.readFileSync('./json/TransactionEventRequest.json');
                // let sTrans = JSON.parse(rawdata);
                // sTrans.eventType = "Started";
                // sTrans.timestamp = Date.now();

                // ws.send(JSON.stringify(sTrans));
            });

            // Trigger event when server send message
            ws.on('message', function(res) {

                // If msg is in JSON format
                try {
                    var msg = JSON.parse(res);

                // If msg is not in JSON format
                } catch (error) {
                    console.log(res.toString());
                }
                
            });

            // Error event handler
            ws.on('error', function (err) {
                console.log(err.message);
            });

            // Close event handler
            ws.on('close', function(code) {
                // If cllient in close event reconnect every 5 seconds

                if(code == 3005){
                    var newdir = "ID001_"+Date.now();
                    fs.renameSync(`${__dirname+"\\"+username}`, `${__dirname+"\\"+newdir}`, function(err) {
                        if (err) {
                          console.log(err)
                        } else {
                          console.log("Successfully renamed the directory.")
                        }
                    });

                    const currPath = `${__dirname+"\\new"}`;
                    const newPath = `${__dirname+"\\"+username}`;
                    fs.renameSync(currPath, newPath, function(err) {
                        if (err) {
                          console.log(err)
                        } else {
                          console.log("Successfully renamed the directory.")
                        }
                    });
                }

                // ws.emit('close');
                ws = null;
                reconn = setTimeout(startWebsocket, 5000);    
            });

            evt.on('SetVariablesRequest', (data) => {
                addUser(data.component, data.variable).then(function(ack) {
                    if(ack) {
                        console.log("Password updated");
                        evt.emit('SetVariablesResponse', {
                            state: "Accepted"
                        });
                        ws.close();
                    }
                    else {
                        console.log("Password not updated"); 
                        evt.emit('SetVariablesResponse', {
                            state: "Rejected"
                        });
                    }
                });
            });

            evt.on('TriggerMessageRequest', (data) => {
                if(data.requestedMessage == "SignChargingStationCertificate"){
                    evt.emit('TriggerMessageResponse', {
                        state: "Accepted"
                    });

                    passphrase = "adminpass";
                    createClient(passphrase).then(function(){
                        evt.emit('SignCertificateRequest', {
                            csr: fs.readFileSync(path.join('new/csr/client.csr.pem'), 'utf8'),
                            typeOfCertificate: "ChargingStationCertificate"
                        });
                    });
                }
                else{
                    evt.emit('TriggerMessageResponse', {
                        state: "Rejected"
                    });
                }
            });

            const clientdir = path.resolve(__dirname + '/client/').split(path.sep).join("/")+"/";

            evt.on('CertificateSignedRequest', (data) => {
                console.log(data.cert);
                fs.writeFileSync(`${__dirname}/new/certs/client.cert.pem`, data.cert);

                var veryfycert = function() {
                    return new Promise(function(resolve, reject) {
                        // Create key
                        exec('openssl x509 -noout -modulus -in certs/client.cert.pem', {
                            cwd: `${__dirname}/new/`
                        }, function(err, stdout, stderr) {
                            // console.log("err: ", err);
                            // console.log("stdout: ", stdout);
                            // console.log("stderr: ", stderr);
                            resolve(stdout);
                        });
                    });
                };

                var veryfykey = function() {
                    return new Promise(function(resolve, reject) {
                        // Create key
                        exec('openssl rsa -noout -modulus -in private/client.key.pem -passin pass:adminpass', {
                            cwd: `${__dirname}/new/`
                        }, function(err, stdout, stderr) {
                            // console.log("err: ", err);
                            // console.log("stdout: ", stdout);
                            // console.log("stderr: ", stderr);
                            resolve(stdout);
                        });
                    });
                };

                veryfycert().then(function(datacert){
                    veryfykey().then(function(datakey){
                        console.log("datacert: ", datacert);
                        console.log("datakey: ", datakey);
                        if(datacert == datakey){
                            console.log("Veryfied");
                            evt.emit('CertificateSignedResponse', {
                                status: "Accepted"
                            });

                            ws.close(3005);
                        }
                        else{
                            console.log("Non Veryfied");
                            evt.emit('CertificateSignedResponse', {
                                type: "Rejected",
                                type
                            });
                        }
                    });
                });
            });

            // A04 - Security Event Notification
            evt.emit('SecurityEventNotificationRequest', {
                state: "FailedToAuthenticateAtCsms",
                timestamp: new Date()
            });

            evt.on('CertificateSignedResponse', (data) => {
                console.log(data);
            });

        }
        else{
            console.log("Id not include in data base");
            setTimeout(() => {
                startWebsocket();
            }, 5000);
        }
    });
}

const { validateSSLCert } = require('ssl-validator');

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

function checkCert(){
    return new Promise(function(resolve, reject) {
        var certificate = fs.readFileSync(`${__dirname}/ID001/certs/client.cert.pem`);

        validateSSLCert(certificate).then(function(data){
            var validTo = new Date(data.validity.end);
            var daysRemaining = getDaysRemaining(new Date(), validTo);
            resolve(daysRemaining);
        });
    });
};

startWebsocket();