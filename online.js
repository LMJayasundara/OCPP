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

var reconn = null;
require('dotenv').config();
var AWS = require('aws-sdk');
AWS.config.update({
    maxRetries: 2,
    httpOptions: {
        timeout: 2 * 1000,
        connectTimeout: 3 * 1000,
    },
    region: process.env.AWS_REGION,
    accessKeyId: process.env.AWS_ACCESS_KEY,
    secretAccessKey: process.env.AWS_SECRET_KEY
});
var s3 = new AWS.S3();
// var BUCKET_NAME = process.env.AWS_S3_BUCKET;

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

const onlineAPI = function(app, wss, client) {
    var events = wsEvents(client);


    app.post(apipath + '/updatepass/', async function(req, res) {
        console.log("Admin is requesting to update Basic auth password of client " + req.body.username);
        var newhash = crypto.createHash('sha256').update(req.body.username + ':' + req.body.newpasswd).digest('hex');
        var hash = crypto.createHash('sha256').update(req.body.username + ':' + req.body.passwd).digest('hex');

        // var start = new Date().getTime();
        checkUser(hash).then(function(ack){
            console.log("checkUser ack: ",ack);
            if(ack == true){
                return new Promise(async function(resolve, reject) {
                    const ccc = await Array.from(wss.clients).find(client => (client.readyState === client.OPEN && client.id == req.body.username));
                    resolve(ccc)
                }).then((client)=>{
                    if (client != undefined) {
                        var events_update_pass = wsEvents(client);

                        events_update_pass.emit('SetVariablesRequest', {
                            component: req.body.username,
                            variable: newhash
                        });

                        events_update_pass.on('SetVariablesResponse', (ack) => {
                            console.log("SetVariablesResponse state: ",ack.state );
                            if(ack.state == 'Accepted'){

                                updatepass(req.body.username, req.body.newpasswd).then(function(ack){
                                    console.log("updatepass ack: ",ack);
                                    if(ack == true){
                                        res.json({
                                            success: "true",
                                            result: req.body.username + " Client update the password"
                                        });
                                    }
                                    else{
                                        res.json({
                                            success: "fasle",
                                            result: req.body.username + " Client can not update the password"
                                        });
                                    }
                                });
                            }
                            else{
                                res.json({
                                    success: "fasle",
                                    result: "SetVariables Response: Rejected"
                                });
                            }
                        });
                    }
                    else{
                        res.json({
                            success: "fasle",
                            result: "Can not find client " + req.body.username
                        });
                    }
                });
            }
            else{
                res.json({
                    success: "Auth fail"
                });
            }
        });
    });
    
    app.post(apipath + '/updatecertcsms/', async function(req, res) {
        console.log("Admin is requesting to update charging station " + req.body.username + " cert by using CSMS");

        return new Promise(async function(resolve, reject) {
            const ccc = await Array.from(wss.clients).find(client => (client.readyState === client.OPEN && client.id == req.body.username));
            resolve(ccc)
        }).then((client)=>{
            if(client != undefined){
                var events_update_cert_csms = wsEvents(client);

                events_update_cert_csms.emit('TriggerMessageRequest', {
                    requestedMessage: "SignChargingStationCertificate"
                });

                events_update_cert_csms.on('TriggerMessageResponse', (ack) => {
                    if(ack.state){
                        events_update_cert_csms.on('SignCertificateRequest', (ack) => {
                            if(ack.csr != null){
                                events_update_cert_csms.emit('SignCertificateResponse', {
                                    state: "Accepted"
                                });

                                fs.writeFile(pkidir + req.body.username + '/csr/new.csr.pem', ack.csr).then(async function(){
                                    return new Promise(function(resolve, reject) {
                                        // Create certificate
                                        exec('openssl ca -config openssl.cnf -extensions usr_cert -days 365 -notext -md sha256 -in csr/new.csr.pem -out certs/new.cert.pem -passin pass:intermediatecapass -batch', {
                                            cwd: pkidir + req.body.username
                                        }, function(err) {
                                            console.log("Create Admin Keys Err: ", err);
                                            if(err == null){
                                                resolve();
                                            }
                                            else{
                                                reject();
                                            }
                                        });
                                    }).then(function(){
                                        events_update_cert_csms.emit('CertificateSignedRequest', {
                                            cert: fs.readFileSync(path.join(pkidir + req.body.username +'/certs/new.cert.pem'), 'utf8'),
                                            typeOfCertificate: "ChargingStationCertificate"
                                        });
                                    });
                                });

                            }
                            else{
                                events_update_cert_csms.emit('SignCertificateResponse', {
                                    state: "Rejected"
                                });
                                res.json({
                                    success: "fasle",
                                    result: "CSR file error!"
                                });
                            }

                            events_update_cert_csms.on('CertificateSignedResponse', (ack) => {
                                client.close();
                                if(ack.status == "Accepted"){
                                    res.json({
                                        success: "true",
                                        result: req.body.username + " Client update certs"
                                    });
                                }
                                else{
                                    res.json({
                                        success: "fasle",
                                        result: req.body.username + " Client doesn't update certs"
                                    });
                                }
                            });

                        });
                    }
                    else{
                        res.json({
                            success: "fasle",
                            result: "Trigger Message Response: Rejected"
                        });
                    }
                });
            }
            else{
                res.json({
                    success: "fasle",
                    result: "Can not find client " + req.body.username
                });
            };
        });
    });

    events.on('SignCertificateRequest', (ack) => {
        if(ack.csr != null){
            events.emit('SignCertificateResponse', {
                state: "Accepted"
            });

            console.log(ack.csr);
            fs.writeFile(pkidir + client.id + '/csr/new.csr.pem', ack.csr).then(async function(){
                return new Promise(function(resolve, reject) {
                    // Create certificate
                    exec('openssl ca -config openssl.cnf -extensions usr_cert -days 365 -notext -md sha256 -in csr/new.csr.pem -out certs/new.cert.pem -passin pass:intermediatecapass -batch', {
                        cwd: pkidir + client.id
                    }, function(err) {
                        console.log("Create Admin Keys Err: ", err);
                        resolve();
                    });
                }).then(function(){
                    events.emit('CertificateSignedRequest', {
                        cert: fs.readFileSync(path.join(pkidir + client.id +'/certs/new.cert.pem'), 'utf8'),
                        typeOfCertificate: "ChargingStationCertificate"
                    });
                });
            });

            events.on('CertificateSignedResponse', (ack) => {
                client.close();
                if(ack.status == "Accepted"){
                    console.log(client.id + " Client update certs");
                }
                else{
                    console.log(client.id + " Client doesn't update certs");
                }
            });
        }
        else{
            events.emit('SignCertificateResponse', {
                state: "Rejected"
            });
            console.log("CSR file error!");
        }
    });

    // A04 - Security Event Notification
    events.on('SecurityEventNotificationRequest', (ack) => {
        events.emit('SecurityEventNotificationResponse', {
            state: ack.state
        });
    });

    app.post(apipath + '/reboot/', async function(req, res) {
        console.log("Admin is requesting to reboot the charging station: " + req.body.username);

        res.json({
            success: "true",
            result: "Charging station: " + req.body.username+ " reboot after 10 sec"
        });

        return new Promise(async function(resolve, reject) {
            const ccc = await Array.from(wss.clients).find(client => (client.readyState === client.OPEN && client.id == req.body.username));
            resolve(ccc)
        }).then((client)=>{
            if(client != undefined){
                function closeClient() {
                    return new Promise((resolve) => {
                      setTimeout(() => {
                        client.close();
                        resolve();
                      }, 10000);
                    });
                }
                  
                function rebootPi() {
                    return new Promise((resolve) => {
                        setTimeout(() => {
                            console.log("Reboting...");

                            // function execute(command, callback){
                            //     exec(command, function(error, stdout, stderr){ callback(stdout); });
                            // }
                            // execute('sudo reboot -h now', function(callback){
                            //     console.log(callback);
                            // });

                            resolve();
                        }, 1000);
                    });
                }

                async function sequentialStart() {
                    await closeClient();
                    await rebootPi();
                }

                sequentialStart();
                  
            }
        });
    });

    app.post(apipath + '/update/', async function(req, res) {
        console.log("Admin is requesting to update firmware of the charging station: " + req.body.username);
        console.log("Url: ", req.body.url);
        console.log("Retrieved: ", req.body.retrieved);
        console.log("Retry: ", req.body.retry);
        var filename = "Firmware.zip";

        var BUCKET_NAME = process.env.AWS_S3_BUCKET;
        var runCount = 0;

        var createFileStructure = function() {
            runCount++;
            return new Promise(function(resolve, reject) {
                s3.getObject({ Bucket: BUCKET_NAME, Key: filename }, function(err, data){
                    if(err == null){
                        // console.log(data);
                        clearInterval(reconn);
                        let writeStream = fs.createWriteStream(path.join(__dirname, 'test.zip'));
                        var resp = s3.getObject({ Bucket: BUCKET_NAME, Key: filename }).createReadStream();
                        resp.pipe(writeStream);

                        let downloaded = 0;
                        let percent = 0;
                        let size = data.ContentLength;

                        resp.on('data', function(chunk){
                            downloaded += chunk.length;
                            percent = (100.0 * downloaded / size).toFixed(2);
                            process.stdout.write(`Downloading ${percent}%\r`);
                        })
                        .on('end', function() {
                            console.log('\nFile Downloaded!');
                            return res.json({ success: true, message: 'File Downloaded!' });
                        })
                        .on('error', function (error) {
                            console.log("Error occur when downloading: ",error);
                            fs.unlinkSync(path.join(__dirname, 'test.zip'));
                            return res.status(500).json({ success: false, message: "Error occur when downloading: "+ error.message });
                        });

                        resolve(true);
                    }
                    else{
                        if(runCount > 3){
                            clearInterval(reconn);
                            console.log("Timeout with error: ",err.message);
                            return res.status(500).json({ success: false, message: "Timeout with error: "+err.message });
                        }
                        else{
                            console.log("Retring: ", runCount);
                            reconn = setTimeout(() => {createFileStructure()}, 5000);
                        }
                        resolve(false);
                    }
                });
            });
        };
        
        createFileStructure().then((ack)=>{
            console.log("Dowload staus: ", ack);
        });

    });

    events.on('BootNotificationRequest', async (ack) => {
        console.log(ack);
        events.emit('BootNotificationResponse', {
            state: "Accepted",
            currentTime: Date.now(),
            interval: 1000
        });
    });

};

module.exports = {
    onlineAPI
};