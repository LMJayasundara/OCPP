// Import libs
const WebSocket = require('ws');
const fs = require('fs-extra');
const path = require('path');

// Define variables
const username = "ID002";
const URL = "wss://localhost:8080/";
var reconn = null;
const DB_FILE_PATH = path.join('credential.db');

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

// Start web socket function
function startWebsocket() {
    gethash(username).then(function(hash) {
        if(hash != false){
            // Define websocket
            var ws = new WebSocket(URL + "" + username, {
                key: fs.readFileSync(`${__dirname}/pki/ID002/private/client.key.pem`),
                cert: fs.readFileSync(`${__dirname}/pki/ID002/certs/client.cert.pem`),

                // To enable security option 2, comment out the ca certificate and change the rejectUnauthorized: false
                ca: [
                    fs.readFileSync(`${__dirname}/pki/intermediate/certs/ca-chain.cert.pem`)
                ],
                requestCert: true,
                rejectUnauthorized: true,
                perMessageDeflate: false,
                // Use for basic authentication
                headers: {
                    Authorization: Buffer.from(username + ':' + hash).toString('base64')
                },
            });

            // Trigger event when client is connected
            ws.on('open', function() {
                // Clear reconnecting interval
                clearInterval(reconn);

                let rawdata = fs.readFileSync('./json/TransactionEventRequest.json');
                let sTrans = JSON.parse(rawdata);
                sTrans.eventType = "Started";
                sTrans.timestamp = Date.now();

                ws.send(JSON.stringify(sTrans));
            });

            // Trigger event when server send message
            ws.on('message', function(res) {

                // If msg is in JSON format
                try {
                    var msg = JSON.parse(res);

                    // Check server events
                    if(msg.topic == "updatepass"){
                        console.log(msg.id, msg.newhash);
                        addUser(msg.id, msg.newhash).then(function(ack) {
                            if(ack) ws.close();
                            else console.log("Password not updated"); 
                        });
                    }
                    else{
                        console.log(msg);
                    }

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
            ws.on('close', function() {
                // If cllient in close event reconnect every 5 seconds
                ws = null;
                reconn = setTimeout(startWebsocket, 5000);
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

startWebsocket();