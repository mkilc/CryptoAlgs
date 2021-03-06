const {
    decodeUTF8,
    encodeBase64,
    encodeUTF8
} = require("tweetnacl-util");
const tweetnacl = require("tweetnacl");
const borsh = require("borsh");
const bs58 = require("bs58")

const toBuffer = (arr) => {
    if (Buffer.isBuffer(arr)) {
        return arr
    }

    if (arr instanceof Uint8Array) {
        return Buffer.from(arr.buffer, arr.byteOffset, arr.byteLength)
    }

    return Buffer.from(arr)
}

// 3by8kdJoJHu7uUkKfoaLJ2Dp1q1TigeWMGpHu9UGXsWdREqPcshCM223kWadmrMKpV9AsWG5wL9F9hZzjHSRFXud
const secret = "5yAym4cAJcns6KysnoXSedoCWALpn2gJsg4X21GZiQQsXDoiuEN8RUtrzrZL5he8L2XkKhL2MsKZK76BvDixorAN"
const keyPair = tweetnacl.sign.keyPair.fromSecretKey(borsh.baseDecode(secret));
console.log(keyPair);
const signature = tweetnacl.sign.detached(decodeUTF8("crazyman.testnet"), keyPair.secretKey)
// console.log({ signature: toBuffer(signature).toString("base64"), publicKey: toBuffer(keyPair.publicKey).toString("base64") })
console.log({ signature: toBuffer(signature).toString("base64"), publicKey: bs58.encode(toBuffer(keyPair.publicKey)) })