const ShareDB_I = require('sharedb');
ShareDB_I.types.register(require('ot-text').type);
const WebSocket_I = require('ws');
const WebSocketJSONStream_I = require('websocket-json-stream');
const Express_I = require('express');
const SocketIO_I = require('socket.io');
const HTTP_I = require('http');

var crypto = require('crypto');

//Mongo + ShareDB
const db = require('sharedb-mongo')(process.env.MONGODB_URL || 'mongodb://localhost:27017/sharedb');
const sharedb = new ShareDB_I({db});
const shareconn = sharedb.connect();
const shareserver = HTTP_I.createServer();
const sharewss = new WebSocket_I.Server({ server: shareserver, verifyClient:function(info){
        let authurl = info.req.url.substr(1);
        let authcred = authurl.split("/");
        if(authcred.length !== 4 || ! verify_cred(authcred[0], authcred[1], authcred[2], authcred[3]))
        {
            console.log("Wrong cred when sharedb connected");
            return false;
        }
        return true;
    }
});
sharewss.on('connection', client => sharedb.listen(new WebSocketJSONStream_I(client)));
shareserver.listen(8080);
console.log(`ShareDB listening on port 8080`);


// HTTP Server
const app = Express_I();
const APIKEY = process.env.APIKEY || "db30b5bbe4f17e4bc543b71703c72716";
const SIGNKEY = crypto.createHash('md5').update(APIKEY + "Not a good security measure").digest("hex");



function check_token(req)
{
    return req.get("S-TOKEN") === APIKEY;
}

app.use("/createpad", function(req, res, next){
    // Create the document if it hasn't been already
    // const sharedoc = shareconn.get('docs', res.query.doc || 'default')
    res.set('Content-Type', 'application/json');
    if(check_token(req))
    {
        var pid = req.query.pid;
        var text = req.query.text;
        if(pid === undefined || text === undefined)
        {
            res.status(500);
            res.send(JSON.stringify({ "result": "failed", "reason": "not pid or text provided" }));
        }
        else
        {
            var sharedoc = shareconn.get(pid, 'default');
            if (sharedoc.data === undefined)
            {
                sharedoc.create(text, 'text');
                res.status(200);
                res.send(JSON.stringify({ "result": "ok"}));
            }
            else
            {
                res.status(500);
                res.send(JSON.stringify({ "result": "failed", "reason": "pad already exists"}));
            }
        }
    }
    else
    {
        res.status(401);
        res.send(JSON.stringify({ "result": "failed", "reason": "access denied" }));
    }
});

app.use("/fetchpad", function(req, res, next){
    // Create the document if it hasn't been already
    // const sharedoc = shareconn.get('docs', res.query.doc || 'default')
    res.set('Content-Type', 'application/json');
    if(check_token(req))
    {
        var pid = req.query.pid;
        var version = parseInt(req.query.version);
        if(pid === undefined || version === undefined || isNaN(version) || version < 0)
        {
            res.status(500);
            res.send(JSON.stringify({ "result": "failed", "reason": "not pid or version provided" }));
        }
        else
        {

            shareconn.fetchSnapshot(pid, 'default', version, function(err, snapshot)
            {
                if(err)
                {
                    res.status(500);
                    res.send(JSON.stringify({ "result": "failed", "reason": "not able to fetch"}));
                }
                else
                {
                    res.send(JSON.stringify({ "result": "ok", "data": snapshot}));
                }
            });
        }
    }
    else
    {
        res.status(401);
        res.send(JSON.stringify({ "result": "failed", "reason": "access denied" }));
    }
});


app.use("/createsession", function(req, res, next){
    // Create the document if it hasn't been already
    // const sharedoc = shareconn.get('docs', res.query.doc || 'default')
    res.set('Content-Type', 'application/json');
    if(check_token(req))
    {
        var pid = req.query.pid;
        var username = req.query.username;
        if(pid === undefined || username === undefined)
        {
            res.status(500);
            res.send(JSON.stringify({ "result": "failed", "reason": "not pid or username provided" }));
        }
        else
        {
            var expTime = Date.now() + 86400 * 1000;
            var sid = pid + username + expTime + SIGNKEY;
            var sign = crypto.createHash('md5').update(sid).digest("hex");
            res.status(200);
            res.send(JSON.stringify({ "result": "ok", "data" :{ "sid": sign, "username":username, "exptime":expTime, "pid":pid }} ));
        }
    }
    else
    {
        res.status(401);
        res.send(JSON.stringify({ "result": "failed", "reason": "access denied" }));
    }
});


// app.use("/pad", function(req, res, next){
//     var pid = req.query.pid;
//     var username = req.query.username;
//     var exptime = req.query.exptime;
//     var sid = req.query.sid;
//     res.render('pad.ejs', {pid: pid, username: username, exptime: exptime, sid:sid});
// });


function verify_cred(pid, username, exptime, sid)
{
    var exptimeint = parseInt(exptime);
    if(pid === undefined || username === undefined || exptime === undefined || sid === undefined || isNaN(exptimeint))
    {
        return false;
    }
    if(Date().now > exptimeint)
    {

        return false;
    }

    var suppose_sid = pid + username + exptime + SIGNKEY;
    if(crypto.createHash('md5').update(suppose_sid).digest("hex") !== sid)
    {
        return false;
    }
    return true;
}

const server = HTTP_I.createServer(app);
const port = 80;
server.listen(port);
console.log(`listening on port ${port}`);



//ClientServer
const clientserver = HTTP_I.createServer();
const io = SocketIO_I(clientserver);
io.set('transports', [ 'websocket' ]);
const clientdata = {};

io.on('connection', client => {

    const id = client.id;
    let names = {};
    let anchors = {};
    let clients = {};
    let pid = undefined;
    let sid = undefined;
    let username = undefined;
    let exptime = '0';
    client.on('login', msg => {

        pid = msg['pid'];
        username = msg['username'];
        exptime = msg['exptime'];
        sid = msg['sid'];
        if(!verify_cred(pid, username, exptime, sid))
        {
            console.log("wrong cred");
            client.disconnect();
            return;
        }
        if (!clientdata.hasOwnProperty(pid))
        {
                clientdata[pid] = [{}, {}, {}]
        }
        anchors = clientdata[pid][0];
        names = clientdata[pid][1];
        clients = clientdata[pid][2];
        names[id] = username;
        anchors[id] = {'stindex':0, 'edindex':0, 'prefixed': false};
        clients[id] = client;


        client.emit('initialize', { anchors, names });

        for(var key in clients)
        {
            var tc = clients[key];
            tc.emit('id-join', { id, name: username, anchor: {'stindex':0, 'edindex':0, 'prefixed': false} });
        }

        client.on('anchor-update', msg => {
            anchors[id] = msg;
            for(var key in clients)
            {
                var tc = clients[key];
                tc.emit('anchor-update', { id, anchor: anchors[id] });
            }

        });




        client.on('disconnect', () => {
            console.log('left', id);
            delete names[id];
            delete anchors[id];
            delete clients[id];
            for(var key in clients)
            {
                var tc = clients[key];
                tc.emit('id-left', { id });
            }

        });

    });


});


clientserver.listen(8081);
console.log(`ChatServer listening on port 8081`);