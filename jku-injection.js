const Express = require('express');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const jose = require('node-jose');
const jwktopem = require('jwk-to-pem')
const axios = require('axios')
const app = new Express();

app.use(Express.json())

const keyStore = jose.JWK.createKeyStore()
keyStore.generate('RSA', 2048, { alg: 'RS256', use: 'sig' })
  .then(result => {
    fs.writeFileSync(
      'keys.json',
      JSON.stringify(keyStore.toJSON(true), null, '  ')
    )
  })

app.get('/jwks', async (req, res) => {
  const ks = fs.readFileSync('keys.json')
  const keyStore = await jose.JWK.asKeyStore(ks.toString())

  res.send(keyStore.toJSON())
})

app.get('/tokens', async (req, res) => {
  const ks = fs.readFileSync('keys.json')
  const keyStore = await jose.JWK.asKeyStore(ks.toString())
  const [key] = keyStore.all({ use: 'sig' })

  const opt = { compact: true, jwk: key, fields: { typ: 'jwt', jku: "http://localhost:5001/jwks" } }
  const payload = JSON.stringify({
    exp: Math.floor((Date.now() + 24 * 60 * 60 * 1000) / 1000),
    iat: Math.floor(Date.now() / 1000),
    sub: 'test',

  })
  let token = await jose.JWS.createSign(opt, key)
    .update(payload)
    .final()
  token = token.toString('base64')
  res.send({ token })
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
  const { data } = await axios.get(header.jku)
  const [firstKey] = data.keys
  console.log(firstKey)
  const publicKey = jwktopem(firstKey)
  console.log(publicKey)
  if (token == null) res.sendStatus(400).send("Token not present")
  const key = await jose.JWK.asKey(publicKey, 'pem');
  const verifier = jose.JWS.createVerify(key);
  const v = await verifier.verify(token);
  console.log(v.header)
  console.log(v.payload.toString())
  next()
}

app.listen(5001, () => console.log('server started :5001'))
