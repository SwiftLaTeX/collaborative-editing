const ShareDB_I = require('sharedb');
ShareDB_I.types.register(require('ot-text').type);
const WebSocket_I = require('ws');
const WebSocketJSONStream_I = require('websocket-json-stream');
const HTTP_I = require('http');
let crypto = require('crypto');

let SIGNKEY = process.env.SIGNKEY || "834B5B44C3EA4F8D9E332FECD3F032841198E349F7642134D4F6AB70BBAF91F0";
function verify_cred(accesstoken, exptime, sid)
{
    let exptimeint = parseInt(exptime);
    if(accesstoken === undefined || exptime === undefined || sid === undefined || isNaN(exptimeint))
    {
        return false;
    }
    if(Date().now > exptimeint)
    {
        return false;
    }

    let suppose_sid = accesstoken + SIGNKEY + exptime + SIGNKEY;
    if(crypto.createHash('sha256').update(suppose_sid).digest("hex") !== sid)
    {
        return false;
    }
    return true;
}
//Mongo + ShareDB
const mongodb = require('sharedb-mongo')(process.env.MONGODB_URL || 'mongodb://localhost:27017/sharedb');
const sharedb = new ShareDB_I({mongodb});


const shareserver = HTTP_I.createServer();
const sharewss = new WebSocket_I.Server({ server: shareserver, verifyClient:function(info){
        let authurl = info.req.url.substr(1);
        let authcred = authurl.split("/");
        if(authcred.length !== 3 || ! verify_cred(authcred[0], authcred[1], authcred[2]))
        {
            console.log("Wrong cred when sharedb connected");
            return false;
        }
        return true;
    }
});
sharewss.on('connection', client => sharedb.listen(new WebSocketJSONStream_I(client)));
shareserver.listen(18080);
console.log(`ShareDB listening on port 18080`);










