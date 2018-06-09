# henChat (Latest update: 2018.06.09)
A simple IM (?) based on websocket.<br>
## Deployment

### Python-Server

hcServer.py is the server. It works with azLib.py and websocket_server/.

### Node.js-Server

Install Node.js and npm first, then

```
cd nodejs_server
npm install
cd src
node app.js
```

### Client

Index.html works as interface, which also needs jsRSA.js(crypto support) and hc-core.js.<br>
And a HTTP server is necessary. Even though end-to-end encryption is supported since 2018.04.05, you'd better deploy it with TLS protection.

## Reference

Python websocket server:<br>
https://github.com/Pithikos/python-websocket-server<br>
RSA in JavaScript:<br>
https://github.com/wwwtyro/cryptico<br>
