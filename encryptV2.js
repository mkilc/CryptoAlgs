const crypto = require('crypto');

function encrypt(text) {
    // random salt
    const salt = crypto.randomBytes(32);

    const key = crypto.pbkdf2Sync("asd123", salt, 100, 32, 'sha256');
    console.log("KEY", key.toString("base64"));

    const nonce = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, nonce);

    // encrypt the given text
    const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);

    // generate output
    return Buffer.concat([salt, nonce, encrypted]).toString('base64');
}


console.log(encrypt("textaaaaaa"));