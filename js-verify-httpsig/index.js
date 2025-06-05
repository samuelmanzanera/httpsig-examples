const { createVerifier } = require("http-message-signatures");
const { verifyMessage } = require("http-message-signatures/lib/httpbis");
const NodeRSA = require('node-rsa');

async function main() {
    const URL = "http://localhost:8734/~meta@1.0/info/address"
    return fetch(URL)
        .then( async(res) => {
            const headers = Object.fromEntries(res.headers.entries())
            return await verifyMessage({
                all: true,
                // logic for finding a key based on the signature parameters
                async keyLookup(params) {
                    if (params.alg == "hmac-sha256") {
                        return {
                            id: params.keyid,
                            algs: ['hmac-sha256'],
                            verify: createVerifier(params.keyid, 'hmac-sha256')
                        }
                    }
                    if (params.alg == "rsa-pss-sha512") {
                        const n = Buffer.from(params.keyid, 'base64');
                        const key = new NodeRSA();
                        key.importKey({
                            n: n,
                            e: 65537
                        }, 'components-public');
                        const pem = key.exportKey('pkcs8-public-pem');
                        return {
                            id: params.keyid,
                            algs: ['rsa-pss-sha512'],
                            verify: createVerifier(pem, 'rsa-pss-sha512')
                        }
                    }   
                },
            }, {
                method: 'GET',
                url: URL,
                headers: headers
            });
        })
}``

main()
    .then(console.log)
    .catch((err) => {
        console.log(err)
        process.exit(1)
    })

