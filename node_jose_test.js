const jwt = require('jsonwebtoken');
const fs = require('fs');
const jose = require('node-jose');
const jwkToPem = require('jwk-to-pem')

const certDir = '.cert'
const keystoreFile = join(certDir, 'keystore.json')
const raw = {
  iss: 'test',
  exp: new Date().getTime() + 3600,
  sub: {
    test: 'This is a test',
  },
}

async function start() {
  var keystore = JWK.createKeyStore();

  if (!fs.existsSync(keystoreFile)) {
    if (!fs.existsSync(certDir)) {
      fs.mkdirSync(certDir)
    }
    console.log('generate keystore')
    await keystore.generate('RSA', 2048, { alg: 'RS256', use: 'sig' })
    fs.writeFileSync(keystoreFile, JSON.stringify(keystore.toJSON(true)))
  }
  else {
    console.log('import keystore')
    const ks = fs.readFileSync(join('.cert', 'keystore.json'))
    keystore = await JWK.asKeyStore(ks.toString())
  }

  // Use first sig key
  const key = keystore.all({ use: 'sig' })[0]

  // Sign payload
  const payload = JSON.stringify(raw)
  const opt = { compact: true, jwk: key, fields: { typ: 'jwt' } }
  const token = await JWS.createSign(opt, key)
    .update(payload).final()

  // Make JWT
  console.log('JWT')
  console.log(token)

  // Verify Token
  const v = await JWS.createVerify(keystore).verify(token)
  console.log('Verify Token')
  console.log(v.header)
  console.log(v.payload.toString())

  // Verify Token with jsonwebtoken
  const publicKey = jwkToPem(key.toJSON())
  const privateKey = jwkToPem(key.toJSON(true), { private: true })

  console.log('public', publicKey)
  console.log('private', privateKey)

  const decoded = jwt.verify(token, publicKey)
  console.log(decoded)
  process.exit()
}

start()