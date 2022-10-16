var sqlite3 = require('sqlite3');
let db= new sqlite3.Database('./vuln_api.db');
createTables(db)


function createDatabase() {
    var newdb = new sqlite3.Database('vuln_api.db', (err) => {
        if (err) {
            console.log("Getting error " + err);
            exit(1);
        }
        createTables(newdb);
    });
}

function createTables(newdb) {
   // newdb.run(
   // "create table keys ( id int primary key not null, pem text not null)"
   // );
   var pub=`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv7HnCof70zX5clpEeoqC
yJmA3+WWqC8J1uCy0L2wLX7j1qTZOyz2X+74rF/b0Wlvex62SLl33AIRqUrO3Fuk
cVvpo6vOPFx4iIrW7fJ2Oa5//fkDAUBobYLwEUWyiBtl+3NNe6qoeiPDk8Cx64pm
3x681cHjJ9ehrGb7yevnWh4FXn4UY4KEx2GChwkudF5alU9jmMeu22rkfCmbhzHf
BPGN/ZEA246aOF4SLohNsDPAGZ4UGRGwqm5XVksRPyoS+EeuL7E58aY8PoPylplj
0XRMI5LWCcWrSV55LE4I3UJq5rr3uOcVicmoiWH3vMBgJ6niBNQ4zKauMCAwLnZD
DwIDAQAB
-----END PUBLIC KEY-----`
   console.log("insert into keys (id, pem) values (3, \'"+pub+"\'")
    newdb.run("insert into keys (id, pem) values (3, \'"+pub+"\')");

};//klucze do ataku kid:



