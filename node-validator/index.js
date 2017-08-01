const express = require('express');
const chalk = require('chalk');
const clear = require('clear');
const http = require('https');
var jwt = require('jsonwebtoken');
var jwkToPem = require('jwk-to-pem');
var figlet = require('figlet');
const app = express();

var keyStore = [];

//define endpoints
app.get('/', (req, res) => {
    var status = {
        service: 'Transim JWT Validator'
    }
    res.send(JSON.stringify(status));
});

app.get('/verify', (req, res) => {
    if (typeof req.query.token === 'undefined') {
        res.status(400).json({ state: 'error', msg: 'no token provided' });
        return;
    }

    console.log(chalk.green('[VERIFY TOKEN]') + ' Begin request...');

    var decodedToken = jwt.decode(req.query.token, { complete: true });

    var kid = decodedToken.header.kid;
    console.log(chalk.green('[SIGN KID]') + ' ' + kid);

    fetchKeys(decodedToken.payload, kid, (pemkey) => {
        jwt.verify(req.query.token, pemkey,{ignoreNotBefore:true}, (err, decoded) => {
            console.log(chalk.green('[VERIFIED] ' + err));

            if (err) {
                var jsonResponse = {
                    token_valid: false,
                    error: err
                }
                res.status(200).json(jsonResponse);
            }
            else {
                var jsonResponse = {
                    token_valid: true,
                    decoded_token: decoded
                }
                res.status(200).json(jsonResponse);

                
            }
        });
    });
});

var fetchKeys = function (tokenPayload, kid, callback) {

    if(keyStore.some(k => k.kid === kid)) {
        //We know the key already
        var pemkeyFromStore = keyStore.filter(k => k.kid === kid)[0].pemKey;
        console.log(chalk.green('[FETCH KEYS]') + ' Using PEM key from Store for ' + chalk.yellow(kid));
       
        callback(pemkeyFromStore);
        return;
    }

    console.log(chalk.green('[FETCH KEYS]') + ' Need to fetch PEM key for ' + chalk.yellow(kid));
    
    var url = tokenPayload.iss + '.well-known/openid-configuration?p=' + tokenPayload.tfp;
    console.log("PolicyBase: " + url)
    http.get(url, (response) => {
        var policyBody = '';
        response.on('data', d => {
            policyBody += d;
        });

        response.on('end', () => {
            var jr = JSON.parse(policyBody);
            console.log(chalk.green('[OpenID CONNECT RESPONSE]') + ' ' + jr.jwks_uri);

            http.get(jr.jwks_uri, (jwksResponse) => {
                var body = '';
                jwksResponse.on('data', d => { body += d; })
                jwksResponse.on('end', () => {
                    var jwks = JSON.parse(body);
                    var key = jwks.keys.filter(k => k.kid === kid)[0];
                    var pemKey = jwkToPem(key);
                    console.log(chalk.green('[PEM KEY]') + ' ' + pemKey);
                    keyStore.push({kid, pemKey});
                    callback(pemKey);
                });
            });
        });

    });
}

clear();
console.log(chalk.green(figlet.textSync('Transim JWT Validator')));

//start the server
app.listen(3000, () => {
    console.log(chalk.yellow('Validator is listening on port 3000!'));
});