"use strict";

function getHexString(arr) {
    var s = "";
    arr.forEach((a) => {
        s += a.toString(16);
    })
    return s;
}

function generateSymmetric256Key() {
    var array = new Uint8Array(256 / 8);
    return window.crypto.getRandomValues(array);
}

function hmacSha256(cek, type, algorithm) {
    var hmac = crypto_1.createHmac('sha256', cek);
    hmac.update(type);
    hmac.update(algorithm);
    hmac.update(cek.byteLength.toString());
    return hmac.digest();
}

function cipherKeyFromContentEncryptionKey(cek, algorithm) {
    return hmacSha256(cek, 'Microsoft Teams Vault Symmetric Encryption Key', algorithm);
}

function symmetricKeyTest() {
    var key = generateSymmetric256Key();
    console.log('Key (' + key.length + ' bytes): ' + getHexString(key));
    var cipherKey = cipherKeyFromContentEncryptionKey(key, algorithm);
    console.log('ENC_KEY (' + cipherKey.length + ' bytes): ' + cipherKey.toString('hex'));
    // var macKey = macKeyFromContentEncryptionKey(key, algorithm);
    // console.log('MAC_KEY (' + macKey.length + ' bytes): ' + macKey.toString('base64') + " " + macKey.toString('hex'));
    // var secrets = [
    //     'some seriously secret stuff',
    //     '',
    //     '1',
    //     '22',
    //     '333',
    //     '4444',
    //     '55555',
    //     '666666',
    //     '7777777',
    //     '88888888',
    //     '999999999',
    //     'aaaaaaaaaa',
    //     'bbbbbbbbbbb',
    //     'cccccccccccc',
    //     'ddddddddddddd',
    //     'eeeeeeeeeeeeee',
    //     'fffffffffffffff',
    //     '0000000000000000',
    //     generateSymmetric256Key().toString('base64')
    // ];
    // for (var i = 0; i != secrets.length; ++i) {
    //     var encryptedPayload = encryptSymmetric256(Buffer.from(secrets[i]), key);
    //     console.log(decryptSymmetric256(encryptedPayload, key).toString());
    //     var message = splitEncryptedMessage(encryptedPayload);
    //     console.log('algorithmCode (1 byte): ' + message.algorithmCode.toString());
    //     console.log('initializationVector (' + message.initializationVector.length + " bytes): " + message.initializationVector.toString('base64') + " " + message.initializationVector.toString('hex'));
    //     console.log('encryptedSecret (' + message.encryptedSecret.length + " bytes): " + message.encryptedSecret.toString('base64') + " " + message.encryptedSecret.toString('hex'));
    //     console.log('tag (' + message.tag.length + " bytes): " + message.tag.toString('base64') + " " + message.tag.toString('hex'));
    //     console.log('concatenated payload (' + encryptedPayload.length + ' bytes):');
    //     console.log(encryptedPayload.toString('base64'));
    //     console.log(encryptedPayload.toString('hex'));
    //     console.log();
    // }
}

(function() {
    symmetricKeyTest();
    // asymmetricKeyTestAsync().then(function () {
    //     ietfTestCase();
    // });
})();

// const cbcAlgorithm = 'aes-256-cbc';
// const encryptedData = Buffer.from("iAqWCtUDyQZ3ggdolHNAhLUw/kHunN8eAtID3Q2/76o=", 'base64');
// const key = Buffer.from("vgdbB0u1WOF9QfDtu1XPQg==", 'base64');
// console.log(key.toString('hex'));
// console.log(encryptedData.toString('hex'));
// const cipher = createCipher(cbcAlgorithm, key);
// let encrypted = cipher.update("123456789abcdefgh ijklmnopq");
// encrypted = Buffer.concat([encrypted, cipher.final()]);
// console.log(encrypted.toString('hex'));
// const decipher = createDecipher(cbcAlgorithm, key);
// let secret = decipher.update(encryptedData);
// secret = Buffer.concat([secret, decipher.final()]);
// console.log(secret.toString());
