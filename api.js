// Import libs
const apipath = '/ocsp';
const path = require('path');
const fs = require('fs-extra');
const exec = require('child_process').exec;
const yaml = require('js-yaml');
const crypto = require('crypto');

// Define variables
const pkidir = path.resolve(__dirname + '/pki/').split(path.sep).join("/")+"/";
const DB_FILE_PATH = path.join(pkidir, 'db', 'user.db');
global.config = yaml.load(fs.readFileSync('config/config.yml', 'utf8'));

// Create new user key
const createUserKey = function(username) {
    console.log(">>> Creating a User");
    fs.ensureDirSync(pkidir + username);
    fs.ensureDirSync(pkidir + username +'/certs');
    fs.ensureDirSync(pkidir + username +'/private');
    fs.ensureDirSync(pkidir + username +'/csr');

    openssl_client = fs.readFileSync(__dirname + '/openssl_template/openssl_client.cnf.tpl', 'utf8');
    openssl_client = openssl_client.replace(/{basedir}/g, pkidir + 'intermediate');
    openssl_client = openssl_client.replace(/{rootname}/g, global.config.ca.admin.rootname);
    openssl_client = openssl_client.replace(/{chainname}/g, global.config.ca.admin.chainname);
    openssl_client = openssl_client.replace(/{name}/g, username);
    openssl_client = openssl_client.replace(/{days}/g, global.config.ca.admin.days);
    openssl_client = openssl_client.replace(/{country}/g, global.config.ca.admin.country);
    openssl_client = openssl_client.replace(/{state}/g, global.config.ca.admin.state);
    openssl_client = openssl_client.replace(/{locality}/g, global.config.ca.admin.locality);
    openssl_client = openssl_client.replace(/{organization}/g, global.config.ca.admin.organization);
    openssl_client = openssl_client.replace(/{unit}/g, global.config.ca.admin.unit);
    openssl_client = openssl_client.replace(/{commonname}/g, username);
    fs.writeFileSync(pkidir + username+ '/openssl.cnf', openssl_client);

    return new Promise(function(resolve, reject) {
        // Create key
        exec('openssl genrsa -out private/client.key.pem 4096', {
            cwd: pkidir + username
        }, function() {
            // Create request
            exec('openssl req -config openssl.cnf -new -sha256 -key private/client.key.pem -out csr/client.csr.pem', {
                cwd: pkidir + username
            }, function() {
                // Create certificate
                exec('openssl ca -config openssl.cnf -extensions usr_cert -days 365 -notext -md sha256 -in csr/client.csr.pem -out certs/client.cert.pem -passin pass:' + global.config.ca.intermediate.passphrase + ' -batch', {
                    cwd: pkidir + username
                }, function(err) {
                    // console.log(err.message);
                    if(err){
                        resolve([err.message, false]);
                    }
                    // fs.removeSync(pkidir + 'client/csr/client.csr.pem');
                    console.log(username + " Created");
                    resolve([username + " Created", true]);
                });
            });
        });
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

// Revoke the certificate by using serial number
const serialRevoke = function(serial) {
    return new Promise(function(resolve, reject) {
        console.log('>>>>>>>>>> Revoke serial ', serial);
        revokeCertificate(serial).then(function(revokation){
            resolve(revokation);
        });
    });
};

const revokeCertificate = function(serialNumber) {
    return new Promise(function(resolve, reject) {
        exec('openssl ca -config openssl.cnf -revoke ./newcerts/' + serialNumber.toString() + '.pem -passin pass:' + global.config.ca.intermediate.passphrase, {
            cwd: pkidir + "intermediate"
        }, function(err, stdout, stderr) {
            resolve(err, stdout, stderr);
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

// Send public and private key pair
const getPair = function(username) {
    return new Promise(function(resolve, reject) {
        userExists(username).then(function(found){
            if (!found) {
                resolve('Unknown user');
            }
            const userDirPath = path.join(pkidir, username);
            const key =  fs.readFileSync(path.join(userDirPath, 'private/client.key.pem'), 'utf8');
            const cert = fs.readFileSync(path.join(userDirPath, 'certs/client.cert.pem'), 'utf8');

            resolve ({
                key: key,
                cert: cert
            });
        });
    });
};

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

// Post updatepass topic to the client
var check = function(clients, id, newhash){
    return new Promise(function(resolve, rejects){
        if(clients.size != 0){
            clients.forEach(function (client) {
                if(client.id == id){
                    client.send(
                        JSON.stringify({
                            topic: "updatepass",
                            id: client.id,
                            newhash: newhash
                        })
                    );
                    resolve(true);
                }
                else{
                    resolve(false);
                }
            });
        }
        else{
            resolve(false);
        }
    });
};

/////////////////////////////////////////////////////// Init APIs ///////////////////////////////////////////////////////

const initAPI = function(app, wss) {

    app.post(apipath + '/user/', function(req, res) {
        console.log("Admin is requesting to create a new user:", req.body.name);

        addUser(req.body.name, req.body.passwd).then(function(ack){
            if(ack == true){
                createUserKey(req.body.name).then((msg) =>{
                    result = msg[0]
                    res.json({
                        success: msg[1],
                        result
                    });
                });
            }
            else{
                res.json({
                    success: "false",
                    result: "Client ID already exist"
                });
            }
        });    
    });

    app.post(apipath + '/revoke/', function(req, res) {
        console.log("Admin is requesting revokation of serial " + req.body.serial);

        serialRevoke(req.body.serial).then(function(err, stdout, stderr){
            if(err == null){
                res.json({
                    success: "true",
                    err: err
                });
            }
            else{
                res.json({
                    success: "false",
                    err: err.message
                });
            }
        });
    });

    app.post(apipath + '/auth/', function(req, res) {
        console.log("Admin is requesting auth user " + req.body.username);

        var hash = crypto.createHash('sha256').update(req.body.username + ':' + req.body.passwd).digest('hex');
        checkUser(hash).then(function(ack){
            if(ack == true){
                res.json({
                    success: "true"
                });
            }
            else{
                res.json({
                    success: "false"
                });
            }
        });
    });

    app.post(apipath + '/getPair/', function(req, res) {
        console.log("Admin is requesting key pairs of client " + req.params.username);

        var hash = crypto.createHash('sha256').update(req.body.username + ':' + req.body.passwd).digest('hex');
        checkUser(hash).then(function(ack){
            if(ack == true){
                getPair(req.body.username).then(function(ack){
                    res.json({
                        success: "true",
                        result: ack
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

    app.post(apipath + '/updatepass/', function(req, res) {
        console.log("Admin is requesting to update Basic auth password of client " + req.body.username);
        var newhash = crypto.createHash('sha256').update(req.body.username + ':' + req.body.newpasswd).digest('hex');

        var hash = crypto.createHash('sha256').update(req.body.username + ':' + req.body.passwd).digest('hex');
        checkUser(hash).then(function(ack){
            if(ack == true){
                check(wss.clients, req.body.username, newhash).then(function(ack) {
                    if(ack){
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
                
            }
            else{
                res.json({
                    success: "Auth fail"
                });
            }
        });
    });

}

module.exports = {
    initAPI
};