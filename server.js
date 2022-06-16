// const WebSocket = require('ws');
// const fs = require('fs');

// const PORT = 5000;

// const wss = new WebSocket.Server({
//     port: PORT
// });

// var passwd = 'pa$$word' // should be get form db

// wss.on('connection', function (ws, req) {
//     var urlData = req.headers['sec-websocket-protocol'].split(',');
//     ws.id = urlData[1];
//     ws.passwd = urlData[2]
//     console.log("Connected Charger ID: "  + ws.id);

//     if (ws.id == urlData[1] && ws.passwd == passwd) {
//         console.log("Username / Password matched");

//         ws.on('message', function (msg) {
//             // console.log("From client: ", msg.toString());
//             // ws.send("Hello " + ws.id);
    
//             // Broadcast message to all connected clients
//             wss.clients.forEach(function (client) {
//                 if(client.id == urlData[1]){
//                     console.log("From client: ", msg.toString());
    
//                     let traResRow = fs.readFileSync('./json/TransactionEventResponse.json');
//                     let traRes = JSON.parse(traResRow);
//                     client.send(JSON.stringify(traRes));
//                 };
//             });
//         });

//     } else {
//         console.log("ERROR Username / Password NOT matched");
//     }

//     ws.on('close', function () {
//         console.log('Client disconnected '+ ws.id);
//     });

// });

// console.log( (new Date()) + " Server is listening on port " + PORT);

//////////////////////////////////////////////////////////////////////////////////////////////////////

const WebSocketServer = require('ws').Server;
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const fs = require('fs');

dotenv.config();
let PORT = process.env.PORT || 5000;
let jwtSecretKey = process.env.JWT_SECRET_KEY;

var passwd = 'pa$$word' // should be get form db

const wss = new WebSocketServer({
    port: PORT,
    verifyClient: function (info, cb) {
        var token = info.req.headers.token;
        console.log(token);
        // if (!token)
        //     cb(false, 401, 'Unauthorized')
        // else {
        //     jwt.verify(token, jwtSecretKey, function (err, decoded) {
        //         console.log(err, decoded);
        //         if (err) {
        //             cb(false, 401, 'Unauthorized')
        //         } else {
        //             cb(true)
        //         }
        //     })

        // }
    }
});

wss.on('connection', function (ws, req) {
    var urlData = req.headers['sec-websocket-protocol'].split(',');
    ws.id = urlData[1];
    ws.passwd = urlData[2]
    console.log("Connected Charger ID: "  + ws.id);

    if (ws.id == urlData[1] && ws.passwd == passwd) {
        console.log("Username / Password matched");

        ws.on('message', function (msg) {
            // console.log("From client: ", msg.toString());
            // ws.send("Hello " + ws.id);
    
            // Broadcast message to all connected clients
            wss.clients.forEach(function (client) {
                if(client.id == urlData[1]){
                    console.log("From client: ", msg.toString());
    
                    let traResRow = fs.readFileSync('./json/TransactionEventResponse.json');
                    let traRes = JSON.parse(traResRow);
                    client.send(JSON.stringify(traRes));
                };
            });
        });

    } else {
        console.log("ERROR Username / Password NOT matched");
    }

    ws.on('close', function () {
        console.log('Client disconnected '+ ws.id);
    });

});

console.log( (new Date()) + " Server is listening on port " + PORT);