const bs58 = require("bs58")
const fs = require("fs")
const cry = require("crypto")

// Calling generateKeyPair() method
// with its parameters
const asd = cry.generateKeyPairSync('ed25519', {
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    })

console.log(asd)

function main() {
    const publicBase58 = "BGCCDDHfysuuVnaNVtEhhqeT4k9Muyem3Kpgq2U1m9HX";
    const privateKeyBase58 = "4qAABW9HfVW4UNQjuQAaAWpB21jqoP58kGqDia18FZDRat6Lg6TLWdAD9FyvAd3PPQLYF4hhx2mZAotJudVjoqfs";

    let publicKey = bs58.decode(publicBase58);
    let privateKey = bs58.decode(privateKeyBase58);

    // publicKey = cry.createPublicKey({
    //     key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), publicKey]),
    //     format: "der",
    //     type: "spki",
    // });
    //
    // privateKey = cry.createPrivateKey({
    //     key: Buffer.concat([
    //         Buffer.from("302e020100300506032b657004220420", "hex"),
    //         privateKey,
    //     ]),
    //     format: "der",
    //     type: "pkcs8",
    // })

    // const sig = cry.sign("sha256", "aaaaaaa", asd.privateKey)
    // console.log(sig)
}

main()