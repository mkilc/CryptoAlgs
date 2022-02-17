const { secretbox, randomBytes, box } = require("tweetnacl");
const bs58 = require("bs58")
const {
    decodeUTF8,
    decodeBase64,
    encodeUTF8,
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

const decrypt = (
    secretOrSharedKey,
    messageWithNonce,
    key
) => {
    const messageWithNonceAsUint8Array = decodeBase64(messageWithNonce);
    const nonce = messageWithNonceAsUint8Array.slice(0, box.nonceLength);
    const message = messageWithNonceAsUint8Array.slice(
        box.nonceLength,
        messageWithNonce.length
    );

    console.log(box.nonceLength,
        messageWithNonce.length)

    const decrypted = key
        ? box.open(message, nonce, key, secretOrSharedKey)
        : box.open.after(message, nonce, secretOrSharedKey);

    if (!decrypted) {
        throw new Error('Could not decrypt message');
    }

    const base64DecryptedMessage = encodeUTF8(decrypted);
    return JSON.parse(base64DecryptedMessage);
};

// const keyPair = generateKeyPair()
// console.log("Public: ", bs58.encode(toBuffer(keyPair.publicKey)))
// console.log("Private: ", bs58.encode(toBuffer(keyPair.secretKey)))


const obj = { hello: 'world' };
const pairA = generateKeyPair();
const pairB = generateKeyPair();
const sharedA = box.before(pairB.publicKey, pairA.secretKey);
const sharedB = box.before(pairA.publicKey, pairB.secretKey);
const encrypted = encrypt(sharedA, obj);
const decrypted = decrypt(sharedB, encrypted);
console.log(obj, encrypted, decrypted);

console.log(encrypted, sharedB, toBuffer(sharedB).toString("hex"))