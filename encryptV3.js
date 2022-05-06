const {
    decodeUTF8,
    encodeBase64,
    encodeUTF8
} = require("tweetnacl-util");
const tweetnacl = require("tweetnacl");
const borsh = require("borsh");

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
const secret = "3by8kdJoJHu7uUkKfoaLJ2Dp1q1TigeWMGpHu9UGXsWdREqPcshCM223kWadmrMKpV9AsWG5wL9F9hZzjHSRFXud"
const keyPair = tweetnacl.sign.keyPair.fromSecretKey(borsh.baseDecode(secret));
console.log(keyPair);
const signature = tweetnacl.sign.detached(decodeUTF8("aaaddd"), keyPair.secretKey)
console.log({ signature: toBuffer(signature).toString("base64"), publicKey: toBuffer(keyPair.publicKey).toString("base64") })