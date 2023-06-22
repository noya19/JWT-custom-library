import { createHmac } from 'crypto';
async function createHash(payload, saltRounds, secret) {
    return new Promise((rs, rj) => {
        // crypto.pbkdf2(payload, secret, 64, saltRounds, 'sha256', (err, key) => {
        //     if (err) {
        //         rj(err);
        //     } else {
        //         rs(key.toString('base64url'));
        //     }
        // });
        const hmac = createHmac('sha256', secret);
        rs(hmac.update(payload).digest("hex"));
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
    const header_b64 = Buffer.from(JSON.stringify(header)).toString("base64url");
    const payload_b64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
    // console.log(payload_b64);
    // hash using the plaintext payload.
    const hashed_payload_b64 = await createHash(header_b64 + "." + payload_b64, 10, secret);
    // assign signature
    signature = hashed_payload_b64;
    // JWT 
    console.log("Payload -->", header_b64 + '.' + payload_b64 + '.' + hashed_payload_b64);
    return header_b64 + '.' + payload_b64 + '.' + hashed_payload_b64;
}
async function verifier(JWT, secret) {
    const [header, payload, signature] = JWT.split('.');
    // const payload_text = Buffer.from(header+"."+payload, "base64").toString("ascii");
    // console.log(payload_text);
    const test_signature = await createHash(header + "." + payload, 10, secret);
    return signature === test_signature;
}
const JWT = await signer({ alg: 'sha256', typ: 'JWT' }, { id: '123' }, 'xyz');
console.log(await verifier(JWT, 'xyz'));
