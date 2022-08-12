const spawn = require('child_process').spawn;
const yaml = require('js-yaml');
const fs = require('fs-extra');

global.config = yaml.load(fs.readFileSync('config/config.yml', 'utf8'));
var ocsp = null;

var startServer = function() {
    return new Promise(function(resolve, reject) {
        console.log("Starting OCSP server...")
        // Run openssl OCSP server
        ocsp = spawn('openssl', [
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

        console.log(">>>>>> OCSP server is listening on " + global.config.ca.ocsp.ip + ':' + global.config.ca.ocsp.port + " <<<<<<");

        ocsp.on('error', function(error) {
            console.log("OCSP server startup error: " + error);
            reject(error);
        });

        resolve(ocsp);
    });
};

module.exports = {
    startServer: startServer
}