var express = require("express")
var jwt = require("express-jwt");
var app = express()
jwt( {secret: "shhhhhhared-secret", algorithms: ["HS256"] });

app.get('/', (req, res) => {
    res.send("Hello world");
  });
app.listen(5000, () => console.log('server started :5000'))
