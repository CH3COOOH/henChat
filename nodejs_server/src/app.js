
var crypto = require('crypto');
var randstr = require('js-randstr');

const SERVER_VER = '180609';
const ONLINE_ERR = {"type": "err", "msg": "There is another device online. Please retry."};
const TYPE_ERR = {"type": "err", "msg": "Type Error"};
const INVALID_ERR = {"type": "info", "msg": "Invalid reciver: "};
const INVALID_TOKEN_ERR = {"type:" : "err", "msg": "Invalid Token"};

function hashAlgorithm(algorithm, data){
    var shasum = crypto.createHash(algorithm);
    shasum.update(data);
    return shasum.digest('hex');
}

var online_list = {};
var message_list = {};
var WebSocketServer = require('ws').Server,
wss = new WebSocketServer({ port: 9001 });

wss.on('connection', function (ws) {
    console.log('client connected');
    ws.on('message', function (message) {
        var data;
        try{
            data = JSON.parse(message);
        } catch(err) {
            return;
        }
        var type = data.type;
        if(type ==='login'){
            var pvk = data.msg;
            if(!pvk){
                return;
            }
            var cid = hashAlgorithm('sha1', pvk);
            if(Object.keys(online_list).indexOf(cid) > -1){
                ws_old = online_list[cid][0];
                if(ws_old.isAlive) {
                    ws.send(JSON.stringify(ONLINE_ERR));
                    return;
                }
                
            } 
            token = randstr(16);
            reply = {
                'to': cid,
                'type': 'login',
                'msg': token,
                'ver': SERVER_VER,
                'time': (new Date().getTime() / 1000).toString()
            }
            ws.send(JSON.stringify(reply));
            ws.id = cid;
            online_list[cid] = [ws, token];
            if(Object.keys(message_list).indexOf(cid) > -1){
                for(m in message_list[cid]){
                    ws.send(JSON.stringify(message_list[cid][m]));
                }
                delete(message_list.cid);
            }
            
        }

        else if(type === 'msg') {
            if (Object.keys(online_list).indexOf(data.from) > -1 && data.token === online_list[data.from][1]) {
                var content = JSON.parse(JSON.stringify(data));
                delete(content.token);
                delete(content.to);
    
                var ofline_num = 0;
                for(to_cid_index in data.to) {
                    to_cid = data.to[to_cid_index];
                    if(to_cid.length != 40 || to_cid === cid) {
                        console.log(to_cid.length);
                        console.log(to_cid);
                        var err_info = INVALID_ERR;
                        err_info.msg += to_cid;
                        ws.send(JSON.stringify(err_info));
                    }
                    else if(Object.keys(online_list).indexOf(to_cid) > -1) {
                        var target = online_list[to_cid][0];
                        target.send(JSON.stringify(content));
                    } else {
                        ofline_num += 1;
                        if(Object.keys(message_list).indexOf(to_cid) > -1) {
                            message_list[to_cid].push(content);
                        } else {
                            message_list[to_cid] = [];
                            message_list[to_cid].push(content);
                        }
                    }
                    if(Object.keys(data).indexOf("rest") > -1) {
                        reply = {'type': 'slice',
                            'msg': 'OK',
                            'time': (new Date().getTime() / 1000).toString()
                        }
                        ws.send(JSON.stringify(reply));
                    }
                }
                if(ofline_num > 0) {
                    ws.send(JSON.stringify({"type" : "info", "msg" : ofline_num.toString() + " reciver(s) offline"}));
                }
            } else {
                ws.send(JSON.stringify(INVALID_TOKEN_ERR));
            }

        }
        else {
            ws.send(JSON.stringify(TYPE_ERR));
            return;
        }

    });
});