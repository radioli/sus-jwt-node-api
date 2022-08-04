var express = require("express")
var jwt = require("jsonwebtoken");
var app = express()
const test_user = { user: "test", password: "test" }
app.use(express.json())
app.get('/', (req, res) => {
    res.send("Hello world");
});

app.post("/login", async (req, res) => {
    console.log(req.body)
    //check to see if the user exists in the list of registered users
    if (test_user.user != req.body.user && test_user.password != req.body.password) res.status(404).send("Login Failed!")

    //if user does not exist, send a 400 response
    const accessToken = generateAccessToken({ user: req.body.user })
    const refreshToken = generateRefreshToken({ user: req.body.user })
    res.json({ accessToken: accessToken, refreshToken: refreshToken })
});
// accessTokens
function generateAccessToken(user) {
    return jwt.sign(user, "some secret no cap", { expiresIn: "15m" })
}
// refreshTokens
let refreshTokens = []
function generateRefreshToken(user) {
    const refreshToken =
        jwt.sign(user, "sussy baka", { expiresIn: "20m" })
    refreshTokens.push(refreshToken)
    return refreshToken
}

function validateToken(req, res, next) {
    //get token from request header
    const authHeader = req.headers["authorization"]
    const token = authHeader.split(" ")[1]
    //the request header contains the token "Bearer <token>", split the string and use the second value in the split array.
    if (token == null) res.sendStatus(400).send("Token not present")
    jwt.verify(token, "some secret no cap", (err, user) => {
        if (err) {
            res.status(403).send("Token invalid")
        }
        else {
            req.user = user
            next() //proceed to the next action in the calling function
        }
    }) //end of jwt.verify()
} //end of function

app.get("/posts", validateToken, (req, res) => {
    console.log("Token is valid")
    console.log(req.user.user)
    res.send(`${req.user.user} successfully accessed post`)
})
//REFRESH TOKEN API
app.post("/refreshToken", (req, res) => {
    if (!refreshTokens.includes(req.body.token)) res.status(400).send("Refresh Token Invalid")
    refreshTokens = refreshTokens.filter((c) => c != req.body.token)
    //remove the old refreshToken from the refreshTokens list
    const accessToken = generateAccessToken({ user: req.body.name })
    const refreshToken = generateRefreshToken({ user: req.body.name })
    //generate new accessToken and refreshTokens
    res.json({ accessToken: accessToken, refreshToken: refreshToken })
})
app.delete("/logout", (req, res) => {
    refreshTokens = refreshTokens.filter((c) => c != req.body.token)
    //remove the old refreshToken from the refreshTokens list
    res.status(204).send("Logged out!")
})
app.listen(5000, () => console.log('server started :5000'))


