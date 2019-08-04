const ShareDB_I = require('sharedb');
ShareDB_I.types.register(require('ot-text').type);
const WebSocket_I = require('ws');
const WebSocketJSONStream_I = require('websocket-json-stream');
const MongoMilestoneDB = require('sharedb-milestone-mongo');
const ShardDB_Mongo = require('sharedb-mongo');
const HTTP_I = require('http');
const crypto = require('crypto');
const SIGNKEY = process.env.SIGNKEY || "33524889A72732256A9C92F1ADFCEF80F459431BA35FBCCB5D57CB03EF4C4FC8";
function verify_cred(username, accesstoken, exptime, sid)
{
    let exptimeint = parseInt(exptime);
    if(username === undefined || accesstoken === undefined || exptime === undefined || sid === undefined || isNaN(exptimeint))
    {
        return false;
    }
    if(Date().now > exptimeint)
    {
        return false;
    }

    let suppose_sid = username + SIGNKEY + accesstoken + SIGNKEY + exptime + SIGNKEY;
    if(crypto.createHash('sha256').update(suppose_sid).digest("hex") !== sid)
    {
        return false;
    }
    console.log("User verified " + username);
    return true;
}


//Mongo + ShareDB
const mongodb = new ShardDB_Mongo(process.env.MONGODB_URL || 'mongodb://localhost:27017/sharedb');
const milestoneDb = new MongoMilestoneDB({mongo: process.env.MONGODB_URL || 'mongodb://localhost:27017/sharedbmilestone', loggerLevel: 'info', interval : 100 });
const sharedb = new ShareDB_I({db:mongodb, milestoneDb: milestoneDb});

sharedb.use('connect', (request, callback) => {
    let connecturl = request.req.url;
    //request.agent.custom['url'] = connecturl;
    request.agent.custom['username'] = connecturl.split("/")[1];
    callback();
});

sharedb.use('commit', (request, callback) => {
    let username = request.agent.custom['username'];
    request.snapshot.m.username = username;
    callback();
});


sharedb.use('apply', (request, callback) =>{
    let username = request.agent.custom['username'];
    request.snapshot.m.username = username;
    request.op.m.username = username;
    callback();
});


const shareserver = HTTP_I.createServer();
const sharewss = new WebSocket_I.Server({ server: shareserver, verifyClient:function(info){
        let authurl = info.req.url.substr(1);
        let authcred = authurl.split("/");
        if(authcred.length !== 4 || ! verify_cred(authcred[0], authcred[1], authcred[2], authcred[3]))
        {
            console.log("Wrong cred when sharedb connected " + authcred[0]);
            return false;
        }
        return true;
    }
});
sharewss.on('connection', (client, req) => {
    //console.log(req.url);
    let jsonSocket = new WebSocketJSONStream_I(client);
    //console.log(req);
    sharedb.listen(jsonSocket, req);
});
shareserver.listen(18080);
console.log(`ShareDB listening on port 18080`);










