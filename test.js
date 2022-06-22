const http = require('http');
const WebSocket = require('ws');

const server = http.createServer();
const wss = new WebSocket.Server({ noServer: true });

wss.on('connection', function connection(ws, request, ...args) {
  // ...
});

server.on('upgrade', async function upgrade(request, socket, head) {
  // Do what you normally do in `verifyClient()` here and then use
  // `WebSocketServer.prototype.handleUpgrade()`.
  let args;

  try {
    args = await getDataAsync();
  } catch (e) {
    socket.destroy();
    return;
  }

  wss.handleUpgrade(request, socket, head, function done(ws) {
    wss.emit('connection', ws, request, ...args);
  });
});

server.listen(8080);