import crypto from 'crypto';
async function createHash(payload, saltRounds, secret) {
    return new Promise((rs, rj) => {
        crypto.pbkdf2(payload, secret, 64, saltRounds, 'sha256', (err, key) => {
            if (err) {
                rj(err);
            }
            else {
                rs(key.toString('base64'));
            }
        });
    });
}
let signature = '';
/**
 * 1. Sigining
 *  i. Stringify the Payload
 *  ii. Create a Hashed Payload.
 *  iii. Convert Payload to base64
 *  iv. Concentenate: Base64 of the Header, Base 64 of Payload, Hashed Payload separated by the period '.' character
 *
 * 2. Verify
 *  i. Split the Token into Header Base64, Payload Base64 and Hash by splitting on the '.' character
 *  ii. Convert the Payload to ASCII
 *  iii. Create a hash of the payload using the server signing secret
 *  iv. Compare the Recieved Hash with the Computed Hash
 */
async function signer(header, payload, secret) {
    const header_b64 = Buffer.from(JSON.stringify(header), "binary").toString("base64");
    const payload_b64 = Buffer.from(JSON.stringify(payload), "binary").toString("base64");
    console.log(payload_b64);
    // hash using the plaintext payload.
    const hashed_payload_b64 = await createHash(JSON.stringify(payload), 10, secret);
    // assign signature
    signature = hashed_payload_b64;
    // JWT 
    return header_b64 + '.' + payload_b64 + '.' + hashed_payload_b64;
}
async function verifier(JWT, secret) {
    const [header, payload, signature] = JWT.split('.');
    const payload_text = Buffer.from(payload, "binary").toString("ascii");
    console.log(payload_text);
    const test_signature = await createHash(payload_text, 10, secret);
    return signature === test_signature;
}
const JWT = await signer({ alg: 'sha256', typ: 'JWT' }, { id: '123' }, 'xyz');
console.log(await verifier(JWT, 'xyz'));
