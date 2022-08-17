// Import libs
const apipath = '/ocsp';
const fs = require('fs-extra');
const path = require('path');
const crypto = require('crypto');
// Define variables
const pkidir = path.resolve(__dirname + '/pki/').split(path.sep).join("/")+"/";
const DB_FILE_PATH = path.join(pkidir, 'db', 'user.db');
const wsEvents = require('ws-events');
var exec = require('child_process').exec;

// Delete user data form the user.db file
const deluserdb = function(username){
    return new Promise(function(resolve, reject) {
        fs.readFile(DB_FILE_PATH, {encoding: 'utf-8'}, function(err, data) {
            if (err) resolve(false);
        
            let dataArray = data.split('\n');
            const searchKeyword = username;
            let lastIndex = -1;
        
            for (let index=0; index<dataArray.length; index++) {
                if (dataArray[index].includes(searchKeyword)) {
                    lastIndex = index;
                    break; 
                }
            };
        
            dataArray.splice(lastIndex, 1);
            const updatedData = dataArray.join('\n');
            fs.writeFile(DB_FILE_PATH, updatedData, (err) => {
                if (err) resolve(false);
                resolve(true);
            });
        });
    });
};

// Update the user password
const updatepass = function(username, newpass){
    return new Promise(function(resolve, reject) {
        deluserdb(username).then(function(ack){
            if(ack){
                addUser(username, newpass).then(function(ack){
                    resolve(ack);
                });
            }
            else{
                resolve(false);
            }
        });
    });
};

// Check if user exist
const userExists = function(username) {
    return new Promise(function(resolve, reject) {
        // Read existing file
        const passfile = fs.readFileSync(DB_FILE_PATH, 'utf8');
        // Check if user alreadys exists
        const lines = passfile.split('\n');
        let found = false;
        lines.forEach(function(line) {
            const line_username = line.split(':')[0];
            if (line_username === username) {
                found = true;
            }
        });
        resolve(found);
    });    
};

// Add user credential to the user.db file
const addUser = function(username, password) {
    return new Promise(function(resolve, reject) {
        // Make sure DB file exists ...
        fs.ensureFileSync(DB_FILE_PATH);
        // Calc passhash
        const passhash = crypto.createHash('sha256').update(username + ':' + password).digest('hex');
        // Read existing file
        let passfile = fs.readFileSync(DB_FILE_PATH, 'utf8');
        // Check if user alreadys exists
        userExists(username).then(function(found){
            if (found === false) {
                // Update file
                passfile = passfile + username + ':' + passhash +'\n';
                fs.writeFileSync(DB_FILE_PATH, passfile, 'utf8');
                resolve(true);
            } else {
                resolve(false);
            }
        });
    });
};

// Check user password
const checkUser = function(hash) {
    return new Promise(function(resolve, reject) {
        fs.readFile(DB_FILE_PATH, 'utf8', function(err, passFile) {
            if (err) {
                console.log(err);
                resolve(false);
            } else {
                const lines = passFile.split('\n');

                lines.forEach(function(line) {
                    if (line.split(':')[1] === hash) {
                        resolve(true);
                    }
                });
            }
            resolve(false);
        });
    });
};

const onlineAPI = function(app, ws, wss) {
    const events = wsEvents(ws);

    app.post(apipath + '/updatepass/', function(req, res) {
        console.log("Admin is requesting to update Basic auth password of client " + req.body.username);
        var newhash = crypto.createHash('sha256').update(req.body.username + ':' + req.body.newpasswd).digest('hex');

        var hash = crypto.createHash('sha256').update(req.body.username + ':' + req.body.passwd).digest('hex');
        checkUser(hash).then(function(ack){
            if(ack == true){
                return new Promise(function(resolve, reject) {
                    wss.clients.forEach(function (client) {
                        if(client.id == ws.id){
                            events.emit('SetVariablesRequest', {
                                component: ws.id,
                                variable: newhash
                            });
                            resolve(true);
                        }
                        else{
                            reject();
                        }
                    });
                }).then(function(){
                    events.on('SetVariablesResponse', (ack) => {
                        if(ack.state){
                            updatepass(req.body.username, req.body.newpasswd).then(function(ack){
                                res.json({
                                    success: "true",
                                    result: req.body.username + " Client update password"
                                });
                            }); 
                        }
                        else{
                            res.json({
                                success: "fasle",
                                result: req.body.username + " Client can not update password"
                            });
                        }
                    });
                });
            }
            else{
                res.json({
                    success: "Auth fail"
                });
            }
        });
    });


    app.post(apipath + '/updatecertcsms/', function(req, res) {
        console.log("Admin is requesting to update charging station " + req.body.username + " cert by using CSMS");

        return new Promise(function(resolve, reject) {
            wss.clients.forEach(function (client) {
                if(client.id == ws.id){
                    events.emit('TriggerMessageRequest', {
                        requestedMessage: "SignChargingStationCertificate"
                    });

                    events.on('TriggerMessageResponse', (ack) => {
                        if(ack.state){
                            // res.json({
                            //     success: "true",
                            //     result: req.body.username + " Client update certs"
                            // });

                            // events.on('SignCertificateRequest', (ack) => {
                            //     if(ack.csr != null){
                            //         events.emit('SignCertificateResponse', {
                            //             state: "Accepted"
                            //         });

                            //         console.log(ack.csr);
                            //         fs.writeFile(pkidir + ws.id + '/csr/new.csr.pem', ack.csr).then(function(){
                            //             return new Promise(function(resolve, reject) {
                            //                 // Create certificate
                            //                 exec('openssl ca -config openssl.cnf -extensions usr_cert -days 365 -notext -md sha256 -in csr/new.csr.pem -out certs/new.cert.pem -passin pass:intermediatecapass -batch', {
                            //                     cwd: pkidir + ws.id
                            //                 }, function(err) {
                            //                     console.log("Create Admin Keys Err: ", err);
                            //                     resolve();
                            //                 });
                            //             }).then(function(){
                            //                 events.emit('CertificateSignedRequest', {
                            //                     cert: fs.readFileSync(path.join(pkidir + ws.id +'/certs/new.cert.pem'), 'utf8'),
                            //                     typeOfCertificate: "ChargingStationCertificate"
                            //                 });
                            //             });
                            //         });

                            //         events.on('CertificateSignedResponse', (ack) => {
                            //             console.log(ack.status);
                            //         });
                            //     }
                            //     else{
                            //         events.emit('SignCertificateResponse', {
                            //             state: "Rejected"
                            //         });
                            //     } 
                            // });
                        }
                        else{
                            res.json({
                                success: "fasle",
                                result: req.body.username + " Client can not update certs"
                            });
                        }
                    });
                }
                else{
                    reject();
                    res.json({
                        success: "False"
                    });
                }
            });
        });

    });


    events.on('SignCertificateRequest', (ack) => {
        if(ack.csr != null){
            events.emit('SignCertificateResponse', {
                state: "Accepted"
            });

            console.log(ack.csr);
            fs.writeFile(pkidir + ws.id + '/csr/new.csr.pem', ack.csr).then(function(){
                return new Promise(function(resolve, reject) {
                    // Create certificate
                    exec('openssl ca -config openssl.cnf -extensions usr_cert -days 365 -notext -md sha256 -in csr/new.csr.pem -out certs/new.cert.pem -passin pass:intermediatecapass -batch', {
                        cwd: pkidir + ws.id
                    }, function(err) {
                        console.log("Create Admin Keys Err: ", err);
                        resolve();
                    });
                }).then(function(){
                    events.emit('CertificateSignedRequest', {
                        cert: fs.readFileSync(path.join(pkidir + ws.id +'/certs/new.cert.pem'), 'utf8'),
                        typeOfCertificate: "ChargingStationCertificate"
                    });
                });
            });

            events.on('CertificateSignedResponse', (ack) => {
                console.log(ack.status);
            });
        }
        else{
            events.emit('SignCertificateResponse', {
                state: "Rejected"
            });
        } 
    });

    // A04 - Security Event Notification
    events.on('SecurityEventNotificationRequest', (ack) => {
        events.emit('SecurityEventNotificationResponse', {
            state: ack.state
        });
    });
};

module.exports = {
    onlineAPI
};