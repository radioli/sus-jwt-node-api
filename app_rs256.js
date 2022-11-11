var express = require("express")
var jwt = require("jsonwebtoken");
var jws = require("jws")
const fs = require("fs")
const jose = require('node-jose');
var app = express()
const test_user = { user: "test", password: "test"}
app.use(express.json())

// PRIVATE and PUBLIC key
//var privateKEY  = fs.readFileSync('./key.pem', 'utf8');
const privateKEY = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAKBgQDNwqLEe9wgTXCbC7+RPdDbBbeqjdbs4kOPOIGzqLpXvJXlxxW8iMz0EaM4BKUqYsIa+ndv3NAn2RxCd5ubVdJJcX43zO6Ko0TFEZx/65gY3BE0O6syCEmUP4qbSd6exou/F+WTISzbQ5FBVPVmhnYhG/kpwt/cIxK5iUn5hm+4tQIDAQABAoGBAI+8xiPoOrA+KMnG/T4jJsG6TsHQcDHvJi7o1IKC/hnIXha0atTX5AUkRRce95qSfvKFweXdJXSQ0JMGJyfuXgU6dI0TcseFRfewXAa/ssxAC+iUVR6KUMh1PE2wXLitfeI6JLvVtrBYswm2I7CtY0q8n5AGimHWVXJPLfGV7m0BAkEA+fqFt2LXbLtyg6wZyxMA/cnmt5Nt3U2dAu77MzFJvibANUNHE4HPLZxjGNXN+a6m0K6TD4kDdh5HfUYLWWRBYQJBANK3carmulBwqzcDBjsJ0YrIONBpCAsXxk8idXb8jL9aNIg15Wumm2enqqObahDHB5jnGOLmbasizvSVqypfM9UCQCQl8xIqy+YgURXzXCN+kwUgHinrutZms87Jyi+D8Br8NY0+Nlf+zHvXAomD2W5CsEK7C+8SLBr3k/TsnRWHJuECQHFE9RA2OP8WoaLPuGCyFXaxzICThSRZYluVnWkZtxsBhW2W8z1b8PvWUE7kMy7TnkzeJS2LSnaNHoyxi7IaPQUCQCwWU4U+v4lD7uYBw00Ga/xt+7+UqFPlPVdz1yyr4q24Zxaw0LgmuEvgU5dycq8N7JxjTubX0MIRR+G9fmDBBl8=\r\n-----END RSA PRIVATE KEY-----'
var publicKEY  = fs.readFileSync('./pubkey.pem', 'utf8');



app.post("/RS256/login", async (req, res) => {
    console.log(req.body)
    //check to see if the user exists in the list of registered users
    if (test_user.user != req.body.user && test_user.password != req.body.password) res.status(404).send("Login Failed!")

    //if user does not exist, send a 400 response
    const accessToken = generateAccessTokenFromKey({ user: req.body.user })
    res.json({ accessToken: accessToken})
});
// accessTokens

function generateAccessTokenFromKey(user) {
    return jwt.sign(user, privateKEY, { expiresIn: "12h", algorithm: 'RS256' })
}


function validateTokenRS256(req, res, next) {
    //get token from request header
    const authHeader = req.headers["authorization"]
    const token = authHeader.split(" ")[1]
    //the request header contains the token "Bearer <token>", split the string and use the second value in the split array.
    if (token == null) res.sendStatus(400).send("Token not present")
    data = jws.verify(token, publicKEY)
    console.log(data)
    let buff = new Buffer(publicKEY);
    let base64data = buff.toString('base64');
    console.log(base64data)
    jwt.verify(token, publicKEY, (err, user) => {
        if (err) {
            console.log(err)
            res.status(403).send("Token invalid")
        }
        else {
            req.user = user
            next() //proceed to the next action in the calling function
        }
    }) //end of jwt.verify()
} 



app.get("/jwt/admin", validateTokenRS256, (req, res) => {
    const authHeader = req.headers["authorization"]
    const token = authHeader.split(" ")[1]
    var decoded = JSON.parse(jwt.decode(token));
    if(decoded.user == "admin"){
    res.send(`${req.user} successfully accessed rs-256 admin`)
    }else{
    res.status(403).send("not admin")
    }
})


app.get("/RS256/posts", validateTokenRS256, (req, res) => {
    console.log("Token is valid")
    console.log(req.user.user)
    res.send(`${req.user.user} successfully accessed posts jwt-rs256`)
})


app.listen(5000, () => console.log('server started :5000'))


