// Import libs
const WebSocket = require('ws');
const fs = require('fs-extra');
const path = require('path');

// Define variables
const username = "ID001";
const URL = "wss://localhost:8080/";
var reconn = null;
var boot_reconn = null;
const DB_FILE_PATH = path.join('credential.db');

const wsEvents = require('ws-events');
var exec = require('child_process').exec;
const { validateSSLCert } = require('ssl-validator');

const crypto = require('crypto');
var ALGORITHM = "sha384"; // Accepted: any result of crypto.getHashes(), check doc dor other options
var SIGNATURE_FORMAT = "hex"; // Accepted: hex, latin1, base64
let pki = require('node-forge').pki;

var extract = require('extract-zip')

var reconn = null;
require('dotenv').config();
var AWS = require('aws-sdk');
AWS.config.update({
    // maxRetries: 3,
    // httpOptions: {
    //     timeout: 2 * 1000,
    //     connectTimeout: 3 * 1000,
    // },
    region: process.env.AWS_REGION,
    accessKeyId: process.env.AWS_ACCESS_KEY,
    secretAccessKey: process.env.AWS_SECRET_KEY
});
var s3 = new AWS.S3();

/* 
    #################################
     Self check the charging station 
    #################################
*/

// Check requirement files and folders are exist
const requirement = [username, 'ca-chain.cert.pem', 'credential.db', username+'/certs/client.cert.pem', username+'/private/client.key.pem']

function checkFileExist() {
    return new Promise(function(resolve, reject) {
        requirement.forEach((dir)=>{
            fs.pathExists(__dirname +'\\'+ dir, (err, exists)=>{
                if(exists == false){
                    console.log("Not Exist: ", dir);
                }
            });
            resolve();
        });
    });
};

// Remove old certificate dirs
function getDirectories(path) {
    return fs.readdirSync(path).filter(function (file) {
      return fs.statSync(path+'/'+file).isDirectory();
    });
};

getDirectories(__dirname).forEach(function(name) {
    if((name.split("_")[1]) != undefined){
        var exp = (Date.now() - (name.split("_")[1]))/(1000 * 60 * 60 * 24);
        if(exp >= 30){
            fs.rmSync(path.resolve(__dirname + "\\"+ name), { recursive: true, force: true });
            console.log("Removed dir: ", name);
        }
    }
});

/* 
    ###############
     API Functions
    ###############
*/

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
        fs.unlink(DB_FILE_PATH).then(()=>{
            fs.ensureFile(DB_FILE_PATH).then(()=>{
                passfile = username + ':' + passhash +'\n';
                fs.writeFile(DB_FILE_PATH, passfile, 'utf8').then(()=>{
                    resolve(true);
                });
            });
        });
    });
};

var createClient = function(commonname) {
    // Prepare client dir
    fs.ensureDirSync('new');
    fs.ensureDirSync('new/certs');
    fs.ensureDirSync('new/private');
    fs.ensureDirSync('new/csr');

    var rootname = 'intermediate';
    var chainname = 'ca-chain';
    var days = 365;
    var country = 'LK';
    var state = 'WEST';
    var locality = 'COL';
    var organization = 'VEGA';
    var unit = 'CG';
    
    openssl_client = fs.readFileSync(__dirname + '/openssl_client.cnf.tpl', 'utf8');
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
                key: fs.readFileSync(`${__dirname+"\\"+username}/private/client.key.pem`),
                cert: fs.readFileSync(`${__dirname+"\\"+username}/certs/client.cert.pem`),

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

            var evt = wsEvents(ws);

            // Trigger event when client is connected
            ws.on('open', function() {

                // let run = false;
                // if (run == false){
                    checkCert().then(function(daysRemaining){
                        // console.log(daysRemaining);
                        if(daysRemaining <= 30){
                            var commonname = username+"_"+Date.now();
                            createClient(commonname).then(function(){
                                evt.emit('SignCertificateRequest', {
                                    csr: fs.readFileSync(path.join('new/csr/client.csr.pem'), 'utf8'),
                                    typeOfCertificate: "ChargingStationCertificate"
                                });
                                // run = true;
                            });
                        }
                    });
                // }

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
                reconn = setTimeout(startWebsocket, 5000);
            });

            evt.on('SetVariablesRequest', (data) => {
                console.log("SetVariablesRequest event");
                addUser(data.component, data.variable).then(function(ack) {
                    if(ack) {
                        console.log("Password updated");
                        
                        return new Promise((resolve) => {
                            evt.emit('SetVariablesResponse', {
                                state: "Accepted"
                            });
                            resolve();
                        })
                        .then(()=>{
                            setTimeout(() => {
                                ws.close();
                            }, 1000);
                        });
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
                    var commonname = username+"_"+Date.now();
                    evt.emit('TriggerMessageResponse', {
                        state: "Accepted"
                    });

                    createClient(commonname).then(function(){
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

            evt.on('CertificateSignedRequest', (data) => {
                console.log(data.cert);
                fs.writeFileSync(`${__dirname}/new/certs/client.cert.pem`, data.cert);

                var veryfycert = function() {
                    return new Promise(function(resolve, reject) {
                        exec('openssl x509 -noout -modulus -in certs/client.cert.pem', {
                            cwd: `${__dirname}/new/`
                        }, function(err, stdout, stderr) {
                            // console.log("err: ", err);
                            // console.log("stdout: ", stdout);
                            // console.log("stderr: ", stderr);
                            if(err == null){
                                resolve(stdout);
                            }
                            else{
                                reject();
                            }
                        });
                    });
                };

                var veryfykey = function() {
                    return new Promise(function(resolve, reject) {
                        exec('openssl rsa -noout -modulus -in private/client.key.pem -passin pass:adminpass', {
                            cwd: `${__dirname}/new/`
                        }, function(err, stdout, stderr) {
                            // console.log("err: ", err);
                            // console.log("stdout: ", stdout);
                            // console.log("stderr: ", stderr);
                            if(err == null){
                                resolve(stdout);
                            }
                            else{
                                reject();
                            }
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

                            var newdir = username+"_"+Date.now();
                            fs.renameSync(`${__dirname+"\\"+username}`, `${__dirname+"\\"+newdir}`, function(err) {
                                if (err) {
                                    console.log(err);
                                } else {
                                    console.log("Successfully renamed the directory.")
                                }
                            });

                            var currPath = `${__dirname+"\\new"}`;
                            var newPath = `${__dirname+"\\"+username}`;
                            fs.renameSync(currPath, newPath, function(err) {
                                if (err) {
                                    console.log(err);
                                } else {
                                    console.log("Successfully renamed the directory.")
                                }
                            });

                            ws.close();

                        }
                        else{
                            console.log("Non Veryfied");
                            evt.emit('CertificateSignedResponse', {
                                type: "Rejected"
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

            //////// need to fixx the boot notifiacation ////////

            // function BootNotificationRequest() {
            //     return new Promise(function(resolve, reject) {
            //         try {
            //             evt.emit("BootNotificationRequest", {
            //                 reason: "PowerUp",
            //                 chargingStation: {
            //                     model: username,
            //                     vendorName: "vendorName_"+username
            //                 }
            //             });
            //             resolve();
            //         } catch (error) {
            //             console.log(error.message);
            //         }
            //     });
            // };

            // function BootNotificationResponse() {
            //     try {
            //         function look() {
            //             return new Promise(function(resolve, reject) {
            //                 evt.on("BootNotificationResponse", (ack)=>{
            //                     console.log(ack);
            //                     resolve();
            //                 });
            //             });
            //         };

            //         look().catch((err)=>{
            //             console.log(err);
            //         });

            //     } catch (error) {
            //         console.log(error.message);
            //     }
            // };

            // BootNotificationRequest().then(()=>{
            //     BootNotificationResponse();
            // });

            evt.on('UpdateFirmwareRequest', (datax) => {

                evt.emit('UpdateFirmwareResponse', {
                    state: "Accepted"
                });
                
                // console.log(datax);

                let caCert;
                let caStore;
                let requestId = datax.requestId;
                try {
                    caCert = fs.readFileSync(`${__dirname}/rootFirmCerts/firmroot.cert.pem`).toString();
                    caStore = pki.createCaStore([ caCert ]);
                } catch (e) {
                    console.log('Failed to load CA certificate');
                    evt.emit('FirmwareStatusNotificationRequest', {
                        state: "Rejected",
                        requestId: requestId
                    });
                }

                try {
                    var client = pki.certificateFromPem(datax.firmware.signingCertificate);
                    // console.log(client);
                    try {
                        var verfy = pki.verifyCertificateChain(caStore, [ client ]);
                        console.log("Verify certificate: ",verfy);
                        if(verfy){
                            evt.emit('FirmwareStatusNotificationRequest', {
                                state: "CertificateVerified",
                                requestId: requestId
                            });
                        }
                        else{
                            evt.emit('FirmwareStatusNotificationRequest', {
                                state: "Rejected",
                                requestId: requestId
                            });
                        }
                        
                    } catch (e) {
                        console.log(e);
                        evt.emit('FirmwareStatusNotificationRequest', {
                            state: "Rejected",
                            requestId: requestId
                        });
                    }

                } catch (error) {
                    console.log('Failed to load Client CA certificate');
                    evt.emit('FirmwareStatusNotificationRequest', {
                        state: "Rejected",
                        requestId: requestId
                    });
                }

                evt.on('FirmwareStatusNotificationResponse', (ack) => {

                    if(ack.status == "CertificateVerified"){
                        // var BUCKET_NAME = process.env.AWS_S3_BUCKET;
                        var BUCKET_NAME = datax.firmware.location;
                        var runCount = 0;
                        var filename = "Firmware.zip";

                        var createFileStructure = function() {
                            runCount++;
                            return new Promise(function(resolve, reject) {
                                s3.getObject({ Bucket: BUCKET_NAME, Key: filename }, async function(err, data){
                                    console.log("Start!");
                                    if(err == null){
                                        // console.log(data);
                                        clearInterval(reconn);
                                        let writeStream = fs.createWriteStream(path.join(__dirname, 'Firmware.zip'));
                                        var resp = s3.getObject({ Bucket: BUCKET_NAME, Key: filename }).createReadStream();
                                        resp.pipe(writeStream);

                                        let downloaded = 0;
                                        let percent = 0;
                                        let size = data.ContentLength;

                                        evt.emit('FirmwareStatusNotificationRequest', {
                                            state: "Downloading",
                                            requestId: requestId
                                        });

                                        resp.on('data', function(chunk){
                                            downloaded += chunk.length;
                                            percent = (100.0 * downloaded / size).toFixed(2);
                                            process.stdout.write(`Downloading ${percent}%\r`);
                                        })
                                        .on('end', function() {
                                            evt.emit('FirmwareStatusNotificationRequest', {
                                                state: "Downloaded",
                                                requestId: requestId
                                            });
                                            // console.log('\nFile Downloaded!');
                                            // return res.json({ success: true, message: 'File Downloaded!' });
                                        })
                                        .on('error', function (error) {
                                            evt.emit('FirmwareStatusNotificationRequest', {
                                                state: "Rejected",
                                                requestId: requestId
                                            });
                                            console.log("Error occur when downloading: ",error);
                                            fs.unlinkSync(path.join(__dirname, 'Firmware.zip'));
                                            // return res.status(500).json({ success: false, message: "Error occur when downloading: "+ error.message });
                                        });

                                        resolve(true);
                                    }
                                    else{
                                        if(runCount > datax.retries){
                                            clearInterval(reconn);
                                            console.log("Timeout with error: ",err.message);
                                            // return res.status(500).json({ success: false, message: "Timeout with error: "+err.message });
                                        }
                                        else{
                                            console.log("Retring: ", runCount);
                                            reconn = setTimeout(() => {createFileStructure()}, datax.retryInterval);
                                        }
                                        resolve(false);
                                    }
                                });
                            });
                        };

                        createFileStructure().then((ack)=>{
                            console.log("Download staus: ",ack);
                        });
                    }

                    else if(ack.status == "Downloading"){
                        console.log('\nFirmware Downloading...');
                    }

                    else if(ack.status == "Downloaded"){
                        console.log('\nFirmware Downloaded!');
                        function getPrivateKey() {
                            var privKey = fs.readFileSync(`${__dirname}/clientPrivate/admin.key.pem`, 'utf8');
                            return privKey;
                        };
                        
                        function getSignatureToVerify(data) {
                            var privateKey = getPrivateKey();
                            var sign = crypto.createSign(ALGORITHM);
                            sign.update(data);
                            var signature = sign.sign(privateKey, SIGNATURE_FORMAT);
                            return signature;
                        };
        
                        var publicKey = datax.firmware.signingCertificate;
                        var verify = crypto.createVerify(ALGORITHM);
                        var data = (datax.requestId).toString();
                        var signature = getSignatureToVerify(data);
                        verify.update(data);
                        var verification = verify.verify(publicKey, signature, SIGNATURE_FORMAT);
                        console.log('\nVerify signature: ' + verification);

                        if(verification){
                            evt.emit('FirmwareStatusNotificationRequest', {
                                state: "SignatureVerified",
                                requestId: requestId
                            });
                        }
                        else{
                            evt.emit('FirmwareStatusNotificationRequest', {
                                state: "Rejected",
                                requestId: requestId
                            });
                        }
                    }

                    else if(ack.status == "SignatureVerified"){
                        console.log("SignatureVerified");
                        // Unzip firmware file
                        var zipfile = path.join(__dirname, 'Firmware.zip');
                        var outputPath = path.join( __dirname, 'Firmware');
                        
                        function extractFirm () {
                            return new Promise(async function(resolve, reject) {
                                try {
                                    await extract(zipfile, { dir: outputPath });
                                    console.log('Extraction complete!');
                                    resolve();
                                } catch (err) {
                                    console.log(err.message);
                                    reject();
                                }
                            })
                        }
                        console.log('\nExtracting Firmware...');
                        extractFirm().then(()=>{
                            // // Reboot
                            // function execute(command, callback){
                            //     exec(command, function(error, stdout, stderr){ callback(stdout); });
                            // }
                            // execute('sudo reboot -h now', function(callback){
                            //     console.log(callback);
                            // });
                        });
                    }

                    else{
                        console.log("Wrong Firmware Status Notification Response status!");
                    }

                });
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
        var certificate = fs.readFileSync(`${__dirname+"\\"+username}/certs/client.cert.pem`);

        validateSSLCert(certificate).then(function(data){
            var validTo = new Date(data.validity.end);
            var daysRemaining = getDaysRemaining(new Date(), validTo);
            resolve(daysRemaining);
        });
    });
};

checkFileExist().then(()=>{
    startWebsocket();
});