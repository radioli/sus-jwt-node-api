var sqlite3 = require('sqlite3');
let db = new sqlite3.Database('vuln_api.db');
db.each("SELECT pem FROM keys where id = 3", function(err, row) {
    console.log(row);
  });
  //console.log(db.get("SELECT pem FROM keys where id=3"));