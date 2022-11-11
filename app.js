var express = require("express")
var jwt = require("jsonwebtoken");
var jws = require("jws")
const fs = require("fs")
const jose = require('node-jose');
var app = express()
const test_user = { user: "test", password: "test" }
app.use(express.json())

// PRIVATE and PUBLIC key
var privateKEY = fs.readFileSync('./key.pem', 'utf8');
var publicKEY = fs.readFileSync('./pubkey.pem', 'utf8');

app.get('/', (req, res) => {
    res.send("Hello world");
});

app.post("/HS256/login", async (req, res) => {
    console.log(req.body)
    if (test_user.user != req.body.user && test_user.password != req.body.password) res.status(404).send("Login Failed!")
    const accessToken = generateAccessTokenFromSecret({ user: req.body.user })
    const refreshToken = generateRefreshTokenFromSecret({ user: req.body.user })
    res.json({ accessToken: accessToken, refreshToken: refreshToken })
});
app.post("/RS256/login", async (req, res) => {
    console.log(req.body)
    if (test_user.user != req.body.user && test_user.password != req.body.password) res.status(404).send("Login Failed!")
    const accessToken = generateAccessTokenFromKey({ user: req.body.user })
    const refreshToken = generateRefreshTokenFromKey({ user: req.body.user })
    res.json({ accessToken: accessToken, refreshToken: refreshToken })
});

function generateAccessTokenFromSecret(user) {
    return jwt.sign(user, "some secret no cap", { expiresIn: "15m" })
}

function generateAccessTokenFromKey(user) {
    return jwt.sign(user, privateKEY, { expiresIn: "12h", algorithm: 'RS256' })
}

let refreshTokensFromSecret = []
let refreshTokensFromKey = []

function generateRefreshTokenFromSecret(user) {
    const refreshToken =
        jwt.sign(user, "sussy baka", { expiresIn: "20m" })
    refreshTokensFromSecret.push(refreshToken)
    return refreshTokensFromSecret
}

function generateRefreshTokenFromKey(user) {
    const refreshToken =
        jwt.sign(user, privateKEY, { expiresIn: "12h" })
    refreshTokensFromKey.push(refreshToken)
    return refreshToken
}

function validateTokenHS256(req, res, next) {
    const authHeader = req.headers["authorization"]
    const token = authHeader.split(" ")[1]
    if (token == null) res.sendStatus(400).send("Token not present")
    jwt.verify(token, "some secret no cap", (err, user) => {
        if (err) {
            res.status(403).send("Token invalid")
        }
        else {
            req.user = user
            next()
        }
    })
}

function decodeToken(req, res, next) {
    const authHeader = req.headers["authorization"]
    const token = authHeader.split(" ")[1]
    if (token == null) res.sendStatus(400).send("Token not present")
    var decoded = jwt.decode(token);
    console.log(decoded)
    req.user = decoded.user
    next() //proceed to the next action in the calling function
}

function validateTokenRS256(req, res, next) {
    const authHeader = req.headers["authorization"]
    const token = authHeader.split(" ")[1]
    if (token == null) res.sendStatus(400).send("Token not present")
    data = jws.verify(token, publicKEY)
    console.log(data)
    jwt.verify(token, publicKEY, (err, user) => {
        if (err) {
            res.status(403).send("Token invalid")
        }
        else {
            req.user = user
            next()
        }
    })
}

app.get("/HS256/posts", validateTokenHS256, (req, res) => {
    console.log("Token is valid")
    console.log(req.user.user)
    res.send(`${req.user.user} successfully accessed post hs-256`)
})

app.get("/decode/admin", decodeToken, (req, res) => {
    console.log("Token is valid")
    if (req.user == "admin") {
        res.send(`${req.user} successfully accessed hs-256 admin`)
    } else {
        res.status(403).send("Token invalid")
    }
})

app.get("/jwt/admin", decodeToken, (req, res) => {
    console.log("Token is valid")
    if (req.user == "admin") {
        res.send(`${req.user} successfully accessed hs-256 admin`)
    } else {
        res.status(403).send("Token invalid")
    }
})

app.get("/RS256/posts", validateTokenRS256, (req, res) => {
    console.log("Token is valid")
    console.log(req.user.user)
    res.send(`${req.user.user} successfully accessed posts jwt-rs256`)
})

//REFRESH TOKEN API
app.post("HS256/refreshToken", (req, res) => {
    if (!refreshTokensFromSecret.includes(req.body.token)) res.status(400).send("Refresh Token Invalid")
    refreshTokens = refreshTokensFromSecret.filter((c) => c != req.body.token)
    //remove the old refreshToken from the refreshTokens list
    const accessToken = generateAccessTokenFromSecret({ user: req.body.name })
    const refreshToken = generateRefreshTokenFromSecret({ user: req.body.name })
    //generate new accessToken and refreshTokens
    res.json({ accessToken: accessToken, refreshToken: refreshToken })
})

app.post("RS256/refreshToken", (req, res) => {
    if (!refreshTokensFromKey.includes(req.body.token)) res.status(400).send("Refresh Token Invalid")
    refreshTokens = refreshTokensFromKey.filter((c) => c != req.body.token)
    //remove the old refreshToken from the refreshTokens list
    const accessToken = generateAccessTokenFromKey({ user: req.body.name })
    const refreshToken = generateRefreshTokenFromKey({ user: req.body.name })
    //generate new accessToken and refreshTokens
    res.json({ accessToken: accessToken, refreshToken: refreshToken })
})

app.delete("RS256/logout", (req, res) => {
    refreshTokens = refreshTokensFromKey.filter((c) => c != req.body.token)
    //remove the old refreshToken from the refreshTokens list
    res.status(204).send("Logged out!")
})

app.delete("HS256/logout", (req, res) => {
    refreshTokens = refreshTokensFromSecret.filter((c) => c != req.body.token)
    //remove the old refreshToken from the refreshTokens list
    res.status(204).send("Logged out!")
})

app.listen(5000, () => console.log('server started :5000'))


