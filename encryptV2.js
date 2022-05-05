const crypto = require('crypto');

function encrypt(text) {
    // random salt
    const salt = crypto.randomBytes(32);
    console.log("SALT", salt.toString('base64'));

    const key = crypto.pbkdf2Sync("asd123", salt, 100, 32, 'sha256');
    console.log("KEY", key.toString("base64"));

    const nonce = getRandomIV();
    console.log("NONCE", nonce.toString('base64'));
    var cipher = crypto.createCipheriv('aes-256-cbc', key, nonce);

    // encrypt the given text
    var encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
    console.log("ENCTEXT", encrypted.toString('base64'));

    // generate output
    return Buffer.concat([salt, nonce, encrypted]).toString('base64');
}

function getRandomIV() {
    return crypto.randomBytes(16);
}


console.log(encrypt("textaaaaaa"));