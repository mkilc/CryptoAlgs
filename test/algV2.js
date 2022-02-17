let elliptic = require('elliptic');
let sha3 = require('js-sha3');
let ec = new elliptic.ec('secp256k1');
const { box } = require("tweetnacl");

const generateKeyPair = () => box.keyPair();

// const keys = generateKeyPair()
const keys = ec.genKeyPair()
// const publicKey = secp256k1.publicKeyCreate(keys.secretKey);

let msg = { hello: 'world' };
let msgHash = sha3.keccak256(JSON.stringify(msg));
let signature = ec.sign(msgHash, keys, "hex", {canonical: true});
console.log(`Msg: ${msg}`);
console.log(`Msg hash: ${msgHash}`);
console.log("Signature:", signature.toDER());

// Verify signature
const hexToDecimal = (x) => ec.keyFromPrivate(x, "hex").getPrivate().toString(10);
const pubKeyRecovered = ec.recoverPubKey(
    hexToDecimal(msgHash), signature, signature.recoveryParam, "hex");
console.log("Signature verified:", ec.verify(msgHash, signature.toDER(), pubKeyRecovered));
// console.log("Signature verified:", keys.verify(msgHash, signature.toDER()));