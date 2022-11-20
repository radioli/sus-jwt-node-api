const Express = require('express');
const jwt = require('jsonwebtoken');
const st = require('st');
const jose = require('node-jose');
const jwktopem = require('jwk-to-pem')
const axios = require('axios')
const app = new Express();
const request = require('request')
var sqlite3 = require('sqlite3').verbose();
const jwt_latest = require('jsonwebtoken-latest');
app.use(Express.json())

//var privateKEY  = fs.readFileSync('./key.pem', 'utf8');
//var publicKEY  = fs.readFileSync('./pubkey.pem', 'utf8');

// define the payload
const http = require('http')

const path = require('path')
const mount = st({ path: path.join(__dirname, '/static'), url: '/static'})

http.createServer((req, res) => {
  const stHandled = mount(req, res)
  if (stHandled)
    return
  else
    res.end('this is not a static file')
}).listen(1338)
//app.use(mount)

  app.get('/token', async (req, res) => {
   // const ks = fs.readFileSync('attacker_keys.json')
    //const keyStore = await jose.JWK.asKeyStore(ks.toString())
    //const [key] = keyStore.all({ use: 'sig' })
    const key = await getKey('pubkey.pem')
    console.log(key)
    const opt = { compact: true, fields: { typ: 'jwt', kid: "pubkey.pem" } }
    const payload = JSON.stringify({
      exp: Math.floor((Date.now() + 24*60*60*1000) / 1000),
      iat: Math.floor(Date.now() / 1000),
      sub: 'test',

    })
   let token = jwt_latest.sign(payload, key,
      { algorithm: 'HS256', header: {"typ": 'jwt', 'kid':'pubkey.pem'} })
    token = token.toString('base64')
    res.send({ token})
  })
  app.get('/verify', validateToken, async (req, res) => {
    res.send("Token valid")
  })
  app.get('/admin', validateToken, async (req, res) => {
    const authHeader = req.headers["authorization"]
    const token = authHeader.split(" ")[1]
    var decoded = JSON.parse(jwt.decode(token));
    if (decoded.sub== 'admin') {
      res.send(`Successfully accessed admin endpoint`)
    }
    else {
      res.status(403).send("Access Forbidden")
    }
  
  })

//`0 UNION SELECT \'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDOZ2ZxoEmy0oSkE+XF1Nau+7OM\nw1uHQiasyx6Tvp+SEVjRf+gcIuUdfbVIni1QcrM6jnqBM/HokCH+3/prTc1yKi31\nU41a7bRreb20qYDN7cvGf4UdQsoNbIgfC65OcTPAxHMdGcOTiLRqi4HjpyEPfbv7\nJ0j2DeRQPMOUk6xLDwIDAQAB\n-----END PUBLIC KEY-----\'`
  
  async function validateToken(req, res, next) {
    const authHeader = req.headers["authorization"]
    const token = authHeader.split(" ")[1]
    var decoded = jwt.decode(token);
    const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64').toString())
    console.log(header)
    //header.kid = `0 UNION SELECT \'-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBAM3CosR73CBNcJsLv5E90NsFt6qN1uziQ484gbOoule8leXHFbyIzPQRozgEpSpiwhr6d2/c0CfZHEJ3m5tV0klxfjfM7oqjRMURnH/rmBjcETQ7qzIISZQ/iptJ3p7Gi78X5ZMhLNtDkUFU9WaGdiEb+SnC39wjErmJSfmGb7i1AgMBAAE=\n-----END RSA PUBLIC KEY-----\'`
    let kid = header.kid
    const publicKey = await getKey(kid)
    console.log(publicKey)
    //publicKey  = db.get("SELECT pem FROM keys where id= "+header.kid)
    //let publicKeys = []
    //const result = db1.get("SELECT pem FROM keys where id = 3");
    //let results12 = await getData()
    //console.log("hereere"+results12)
    //console.log(results1);
     jwt.verify(token, publicKey, (err, user) => {
      if (err) {
        console.log(err)
          res.status(403).send("Token invalid")
      }
      else {
          req.user = user
          next() //proceed to the next action in the calling function
      }
  })
}

    

async function getKey(path){
  //'http://localhost:1338/static/%2e%2e/key.pem'
  return new Promise((resolve, reject) => {
    request.get('http://localhost:1338/static/'+path, function (error, response, body) {
      var data = body;
      console.log('xd');
      resolve(data);
      });
  })
}   

  app.listen(5001, () => console.log('server started :5001'))