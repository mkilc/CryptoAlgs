const { secretbox, randomBytes, box } = require("tweetnacl");
const {
    decodeUTF8,
    encodeBase64,
} = require("tweetnacl-util");

const generateKeyPair = () => box.keyPair();
const newNonce = () => randomBytes(secretbox.nonceLength);

const toBuffer = (arr) => {
    if (Buffer.isBuffer(arr)) {
        return arr
    }

    if (arr instanceof Uint8Array) {
        return Buffer.from(arr.buffer, arr.byteOffset, arr.byteLength)
    }

    return Buffer.from(arr)
}

const encrypt = (
    secretOrSharedKey,
    json,
    key
) => {
    const nonce = newNonce();
    const messageUint8 = decodeUTF8(JSON.stringify(json));
    const encrypted = key
        ? box(messageUint8, nonce, key, secretOrSharedKey)
        : box.after(messageUint8, nonce, secretOrSharedKey);

    const fullMessage = new Uint8Array(nonce.length + encrypted.length);
    fullMessage.set(nonce);
    fullMessage.set(encrypted, nonce.length);

    return encodeBase64(fullMessage);
}

const obj = { account_id: 'crazyman.testnet' };
const pairA = generateKeyPair();
const pairB = generateKeyPair();
const sharedA = box.before(pairB.publicKey, pairA.secretKey);
const sharedB = box.before(pairA.publicKey, pairB.secretKey);
const encrypted = encrypt(sharedA, obj);

console.log(encrypted, toBuffer(sharedB).toString("hex"))