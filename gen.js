// Script generates OpenSSL PKI based on the configuration in config.yml

var fs = require('fs-extra');
var yaml = require('js-yaml');
var exec = require('child_process').exec;
var path = require('path');

const pkidir = path.resolve(__dirname + '/pki/').split(path.sep).join("/")+"/";
global.config = yaml.load(fs.readFileSync('config/config.yml', 'utf8'));

var createFileStructure = function() {
    console.log(">>> Creating CA file structure")

    return new Promise(function(resolve, reject) {
        fs.ensureDirSync(pkidir);

        // Prepare root dir
        fs.ensureDirSync(pkidir + 'root');
        fs.ensureDirSync(pkidir + 'root/certs');
        fs.ensureDirSync(pkidir + 'root/private');
        fs.ensureDirSync(pkidir + 'root/newcerts');
        fs.ensureDirSync(pkidir + 'root/crl');
        fs.writeFileSync(pkidir + 'root/index.txt', '', 'utf8');
        fs.writeFileSync(pkidir + 'root/serial', '1000', 'utf8');

        openssl_root = fs.readFileSync(__dirname + '/openssl_template/openssl_root.cnf.tpl', 'utf8');
        openssl_root = openssl_root.replace(/{basedir}/g, pkidir + 'root');
        openssl_root = openssl_root.replace(/{rootname}/g, global.config.ca.root.rootname);
        openssl_root = openssl_root.replace(/{days}/g, global.config.ca.root.days);
        openssl_root = openssl_root.replace(/{country}/g, global.config.ca.root.country);
        openssl_root = openssl_root.replace(/{state}/g, global.config.ca.root.state);
        openssl_root = openssl_root.replace(/{locality}/g, global.config.ca.root.locality);
        openssl_root = openssl_root.replace(/{organization}/g, global.config.ca.root.organization);
        openssl_root = openssl_root.replace(/{unit}/g, global.config.ca.root.unit);
        openssl_root = openssl_root.replace(/{commonname}/g, global.config.ca.root.commonname);
        fs.writeFileSync(pkidir + 'root/openssl.cnf', openssl_root);

        // Prepare intermediate dir
        fs.ensureDirSync(pkidir + 'intermediate');
        fs.ensureDirSync(pkidir + 'intermediate/certs');
        fs.ensureDirSync(pkidir + 'intermediate/private');
        fs.ensureDirSync(pkidir + 'intermediate/newcerts');
        fs.ensureDirSync(pkidir + 'intermediate/crl');
        fs.writeFileSync(pkidir + 'intermediate/index.txt', '', 'utf8');
        fs.writeFileSync(pkidir + 'intermediate/serial', '1000', 'utf8');

        openssl_intermediate = fs.readFileSync(__dirname + '/openssl_template/openssl_intermediate.cnf.tpl', 'utf8');
        openssl_intermediate = openssl_intermediate.replace(/{basedir}/g, pkidir + 'intermediate');
        openssl_intermediate = openssl_intermediate.replace(/{rootname}/g, global.config.ca.intermediate.rootname);
        openssl_intermediate = openssl_intermediate.replace(/{chainname}/g, global.config.ca.intermediate.chainname);
        openssl_intermediate = openssl_intermediate.replace(/{days}/g, global.config.ca.intermediate.days);
        openssl_intermediate = openssl_intermediate.replace(/{country}/g, global.config.ca.intermediate.country);
        openssl_intermediate = openssl_intermediate.replace(/{state}/g, global.config.ca.intermediate.state);
        openssl_intermediate = openssl_intermediate.replace(/{locality}/g, global.config.ca.intermediate.locality);
        openssl_intermediate = openssl_intermediate.replace(/{organization}/g, global.config.ca.intermediate.organization);
        openssl_intermediate = openssl_intermediate.replace(/{unit}/g, global.config.ca.intermediate.unit);
        openssl_intermediate = openssl_intermediate.replace(/{commonname}/g, global.config.ca.intermediate.commonname);
        fs.writeFileSync(pkidir + 'intermediate/openssl.cnf', openssl_intermediate);

        // Prepare ocsp dir
        fs.ensureDirSync(pkidir + 'ocsp');
        fs.ensureDirSync(pkidir + 'ocsp/certs');
        fs.ensureDirSync(pkidir + 'ocsp/private');
        fs.ensureDirSync(pkidir + 'ocsp/csr');

        openssl_ocsp = fs.readFileSync(__dirname + '/openssl_template/openssl_ocsp.cnf.tpl', 'utf8');
        openssl_ocsp = openssl_ocsp.replace(/{basedir}/g, pkidir + 'intermediate');
        openssl_ocsp = openssl_ocsp.replace(/{rootname}/g, global.config.ca.ocsp.rootname);
        openssl_ocsp = openssl_ocsp.replace(/{chainname}/g, global.config.ca.ocsp.chainname);
        openssl_ocsp = openssl_ocsp.replace(/{name}/g, global.config.ca.ocsp.name);
        openssl_ocsp = openssl_ocsp.replace(/{days}/g, global.config.ca.ocsp.days);
        openssl_ocsp = openssl_ocsp.replace(/{country}/g, global.config.ca.ocsp.country);
        openssl_ocsp = openssl_ocsp.replace(/{state}/g, global.config.ca.ocsp.state);
        openssl_ocsp = openssl_ocsp.replace(/{locality}/g, global.config.ca.ocsp.locality);
        openssl_ocsp = openssl_ocsp.replace(/{organization}/g, global.config.ca.ocsp.organization);
        openssl_ocsp = openssl_ocsp.replace(/{unit}/g, global.config.ca.ocsp.unit);
        openssl_ocsp = openssl_ocsp.replace(/{commonname}/g, global.config.ca.ocsp.commonname);
        fs.writeFileSync(pkidir + 'ocsp/openssl.cnf', openssl_ocsp);

        // Prepare server dir
        fs.ensureDirSync(pkidir + 'server');
        fs.ensureDirSync(pkidir + 'server/certs');
        fs.ensureDirSync(pkidir + 'server/private');
        fs.ensureDirSync(pkidir + 'server/csr');

        openssl_server = fs.readFileSync(__dirname + '/openssl_template/openssl_server.cnf.tpl', 'utf8');
        openssl_server = openssl_server.replace(/{basedir}/g, pkidir + 'intermediate');
        openssl_server = openssl_server.replace(/{rootname}/g, global.config.ca.server.rootname);
        openssl_server = openssl_server.replace(/{chainname}/g, global.config.ca.server.chainname);
        openssl_server = openssl_server.replace(/{name}/g, global.config.ca.server.name);
        openssl_server = openssl_server.replace(/{days}/g, global.config.ca.server.days);
        openssl_server = openssl_server.replace(/{country}/g, global.config.ca.server.country);
        openssl_server = openssl_server.replace(/{state}/g, global.config.ca.server.state);
        openssl_server = openssl_server.replace(/{locality}/g, global.config.ca.server.locality);
        openssl_server = openssl_server.replace(/{organization}/g, global.config.ca.server.organization);
        openssl_server = openssl_server.replace(/{unit}/g, global.config.ca.server.unit);
        openssl_server = openssl_server.replace(/{commonname}/g, global.config.ca.server.commonname);
        fs.writeFileSync(pkidir + 'server/openssl.cnf', openssl_server);

        // Prepare client dir
        fs.ensureDirSync(pkidir + 'admin');
        fs.ensureDirSync(pkidir + 'admin/certs');
        fs.ensureDirSync(pkidir + 'admin/private');
        fs.ensureDirSync(pkidir + 'admin/csr');

        openssl_client = fs.readFileSync(__dirname + '/openssl_template/openssl_client.cnf.tpl', 'utf8');
        openssl_client = openssl_client.replace(/{basedir}/g, pkidir + 'intermediate');
        openssl_client = openssl_client.replace(/{rootname}/g, global.config.ca.admin.rootname);
        openssl_client = openssl_client.replace(/{chainname}/g, global.config.ca.admin.chainname);
        openssl_client = openssl_client.replace(/{name}/g, global.config.ca.admin.name);
        openssl_client = openssl_client.replace(/{days}/g, global.config.ca.admin.days);
        openssl_client = openssl_client.replace(/{country}/g, global.config.ca.admin.country);
        openssl_client = openssl_client.replace(/{state}/g, global.config.ca.admin.state);
        openssl_client = openssl_client.replace(/{locality}/g, global.config.ca.admin.locality);
        openssl_client = openssl_client.replace(/{organization}/g, global.config.ca.admin.organization);
        openssl_client = openssl_client.replace(/{unit}/g, global.config.ca.admin.unit);
        openssl_client = openssl_client.replace(/{commonname}/g, global.config.ca.admin.commonname);
        fs.writeFileSync(pkidir + 'admin/openssl.cnf', openssl_client);

        resolve();
    });
};
 
var createRootCA = function() {
    console.log(">>> Creating Root CA");

    return new Promise(function(resolve, reject) {
        // Create root key
        exec('openssl genrsa -aes256 -out private/root.key.pem -passout pass:' + global.config.ca.root.passphrase + ' 4096', {
            cwd: pkidir + 'root'
        }, function() {
            // Create Root certificate
            exec('openssl req -config openssl.cnf -key private/root.key.pem -new -x509 -days ' + global.config.ca.root.days + ' -sha256 -extensions v3_ca -out certs/root.cert.pem -passin pass:' + global.config.ca.root.passphrase, {
                cwd: pkidir + 'root'
            }, function(err) {
                console.log("Create Root CA err: ", err);
                resolve();
            });
        });
    });
};

var createIntermediateCA = function() {
    console.log(">>> Creating Intermediate CA");

    return new Promise(function(resolve, reject) {
        // Create intermediate key
        exec('openssl genrsa -aes256 -out private/intermediate.key.pem -passout pass:' + global.config.ca.intermediate.passphrase + ' 4096', {
            cwd: pkidir + 'intermediate'
        }, function() {
            // Create intermediate certificate request
            exec('openssl req -config openssl.cnf -new -sha256 -key private/intermediate.key.pem -out intermediate.csr.pem -passin pass:' + global.config.ca.intermediate.passphrase, {
                cwd: pkidir + 'intermediate'
            }, function() {
                // Create intermediate certificate
                exec('openssl ca -config ../root/openssl.cnf -extensions v3_intermediate_ca -days ' + global.config.ca.intermediate.days + ' -notext -md sha256 -in intermediate.csr.pem -out certs/intermediate.cert.pem -passin pass:' + global.config.ca.root.passphrase + ' -batch', {
                    cwd: pkidir + 'intermediate'
                }, function(err, stdout, stderr) {
                    console.log("Create Intermediate CA Err: ", err);
                    // Remove intermediate.csr.pem file
                    fs.removeSync(pkidir + 'intermediate/intermediate.csr.pem');

                    // Create CA chain file
                    // Read intermediate
                    intermediate = fs.readFileSync(pkidir + 'intermediate/certs/intermediate.cert.pem', 'utf8');
                    // Read root cert
                    root = fs.readFileSync(pkidir + 'root/certs/root.cert.pem', 'utf8');
                    cachain = intermediate + '\n\n' + root;
                    fs.writeFileSync(pkidir + 'intermediate/certs/ca-chain.cert.pem', cachain);
                    resolve();
                });
            });
        });
    });
};

var createOCSPKeys = function() {
    console.log(">>> Creating OCSP Keys")

    return new Promise(function(resolve, reject) {
        // Create key
        exec('openssl genrsa -out private/ocsp.key.pem 4096', {
            cwd: pkidir + 'ocsp'
        }, function() {
            // Create request
            exec('openssl req -config openssl.cnf -new -sha256 -key private/ocsp.key.pem -out csr/ocsp.csr.pem', {
                cwd: pkidir + 'ocsp'
            }, function() {
                // Create certificate
                exec('openssl ca -config openssl.cnf -extensions ocsp -days 3650 -notext -md sha256 -in csr/ocsp.csr.pem -out certs/ocsp.cert.pem -passin pass:' + global.config.ca.intermediate.passphrase + ' -batch', {
                    cwd: pkidir + 'ocsp'
                }, function(err) {
                    console.log("Create OCSP Keys Err: ", err);
                    fs.removeSync(pkidir + 'ocsp/csr/ocsp.csr.pem');
                    resolve();
                });
            });
        });
    });
};
 
var createServer = function() {
    console.log(">>> Creating Server certificates");

    return new Promise(function(resolve, reject) {
        // Create key
        exec('openssl genrsa -out private/server.key.pem 4096', {
            cwd: pkidir + 'server'
        }, function() {
            // Create request
            exec('openssl req -config openssl.cnf -new -sha256 -key private/server.key.pem -out csr/server.csr.pem', {
                cwd: pkidir + 'server'
            }, function() {
                // Create certificate
                exec('openssl ca -config openssl.cnf -extensions server_cert -days 365 -notext -md sha256 -in csr/server.csr.pem -out certs/server.cert.pem -passin pass:' + global.config.ca.intermediate.passphrase + ' -batch', {
                    cwd: pkidir + 'server'
                }, function(err) {
                    console.log("Create Server certificates Err: ", err);
                    fs.removeSync(pkidir + 'server/csr/server.csr.pem');
                    resolve();
                });
            });
        });
    });
};

var createClient = function() {
    console.log(">>> Creating Admin Keys")

    return new Promise(function(resolve, reject) {
        // Create key
        exec('openssl genrsa -aes256 -out private/admin.key.pem -passout pass:' + global.config.ca.admin.passphrase + ' 4096', {
            cwd: pkidir + 'admin'
        }, function() {
            // Create request
            exec('openssl req -config openssl.cnf -new -sha256 -key private/admin.key.pem -passin pass:' + global.config.ca.admin.passphrase + ' -out csr/admin.csr.pem', {
                cwd: pkidir + 'admin'
            }, function() {
                // Create certificate
                exec('openssl ca -config openssl.cnf -extensions usr_cert -days 3650 -notext -md sha256 -in csr/admin.csr.pem -out certs/admin.cert.pem -passin pass:' + global.config.ca.intermediate.passphrase + ' -batch', {
                    cwd: pkidir + 'admin'
                }, function(err) {
                    console.log("Create Admin Keys Err: ", err);
                    fs.removeSync(pkidir + 'admin/csr/admin.csr.pem');
                    resolve();
                });
            });
        });
    });
}

// var setFilePerms = function() {
//     console.log(">>> Setting file permissions")

//     return new Promise(function(resolve, reject) {
//         // Root CA
//         fs.chmodSync(pkidir + 'root/root.key.pem', 0400);
//         fs.chmodSync(pkidir + 'root/root.cert.pem', 0444);
//         fs.chmodSync(pkidir + 'root/openssl.cnf', 0400);

//         // Intermediate CA
//         fs.chmodSync(pkidir + 'intermediate/intermediate.key.pem', 0400);
//         fs.chmodSync(pkidir + 'intermediate/intermediate.cert.pem', 0444);
//         fs.chmodSync(pkidir + 'intermediate/openssl.cnf', 0400);

//         resolve();
//     });
// };

function create() {
    return new Promise(function(resolve, reject) {
        createFileStructure().then(function() {
            createRootCA().then(function() {
                createIntermediateCA().then(function() {
                    createServer().then(function() {
                        createClient().then(function() {
                            createOCSPKeys().then(function() {
                                console.log("All Done!");
                                resolve()
                            })
                            .catch(function(err) {
                                reject("Error: " + err)
                            });
                        })
                        .catch(function(err) {
                            reject("Error: " + err)
                        });
                    })
                    .catch(function(err) {
                        reject("Error: " + err)
                    });
                })
                .catch(function(err) {
                    reject("Error: " + err)
                });
            })
            .catch(function(err) {
                reject("Error: " + err)
            })
        })
        .catch(function(err) {
            reject("Error: " + err)
        });
    })
}
 
create();