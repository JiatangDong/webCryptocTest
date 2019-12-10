"use strict";
exports.__esModule = true;
var crypto_1 = require("crypto");
var util_1 = require("util");
var cbcAlgorithm = 'aes-256-cbc';
var aes256BlockSize = 16;
var algorithm = 'AEAD_AES_256_CBC_HMAC_SHA384';
var algorithmCode = 1;
var algorithmCodeByteLength = 1;
var ivLength = aes256BlockSize;
var tagLength = 24; // from half of sha384 (384/2/8)
var FIXED_ARRAY = [99, 183, 249, 18, 137, 227, 35, 73, 241, 243, 134, 94, 109, 227, 127, 115, 128, 55, 115, 66, 163, 238, 63, 239, 250, 236, 168, 247, 21, 10, 201, 134];
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
function macKeyFromContentEncryptionKey(cek, algorithm) {
    return hmacSha256(cek, 'Microsoft Teams Vault Message Authentication Code Key', algorithm);
}
function generateSymmetric256Key(fixed) {
    if (fixed === void 0) { fixed = false; }
    if (fixed) {
        return Buffer.from(FIXED_ARRAY);
    }
    return crypto_1.randomBytes(256 / 8);
}
exports.generateSymmetric256Key = generateSymmetric256Key;
function messageAuthenticationCodeFromEncryptedSecret(macKey, associatedData, initializationVector, encryptedSecret) {
    var associatedDataLengthBits = Buffer.alloc(64 / 8);
    associatedDataLengthBits.writeBigUInt64BE(BigInt(associatedData.length * 8), 0);
    var hmac = crypto_1.createHmac('sha384', macKey);
    hmac.update(associatedData);
    hmac.update(initializationVector);
    hmac.update(encryptedSecret);
    hmac.update(associatedDataLengthBits);
    return hmac.digest().slice(0, tagLength);
}
function encryptAndTag(cipherKey, macKey, associatedData, initializationVector, secret) {
    var cipher = crypto_1.createCipheriv(cbcAlgorithm, cipherKey, initializationVector);
    var encryptedSecret = cipher.update(secret); // api automatically adds PKCS7 padding so no need to manually add
    encryptedSecret = Buffer.concat([encryptedSecret, cipher.final()]);
    var tag = messageAuthenticationCodeFromEncryptedSecret(macKey, associatedData, initializationVector, encryptedSecret);
    return { tag: tag, encryptedSecret: encryptedSecret };
}
function encryptSymmetric256(secret, secretKey) {
    var associatedData = Buffer.from([algorithmCode]);
    var cipherKey = cipherKeyFromContentEncryptionKey(secretKey, algorithm);
    var macKey = macKeyFromContentEncryptionKey(secretKey, algorithm);
    var initializationVector = crypto_1.randomBytes(ivLength);
    var result = encryptAndTag(cipherKey, macKey, associatedData, initializationVector, secret);
    var encryptedMessage = Buffer.concat([
        associatedData,
        initializationVector,
        result.encryptedSecret,
        result.tag
    ]);
    return encryptedMessage;
}
exports.encryptSymmetric256 = encryptSymmetric256;
function splitEncryptedMessage(encryptedMessage) {
    var ivStart = algorithmCodeByteLength;
    var encryptedSecretStart = ivStart + ivLength;
    var encryptedSecretEnd = encryptedMessage.length - tagLength;
    var tagStart = encryptedSecretEnd;
    var algorithmCode = encryptedMessage.readUInt8(0);
    var initializationVector = encryptedMessage.slice(ivStart, ivStart + ivLength);
    var encryptedSecret = encryptedMessage.slice(encryptedSecretStart, encryptedSecretEnd);
    var tag = encryptedMessage.slice(tagStart, tagStart + tagLength);
    return { algorithmCode: algorithmCode, initializationVector: initializationVector, encryptedSecret: encryptedSecret, tag: tag };
}
function isMessageAuthentic(macKey, message) {
    var associatedData = Buffer.from([message.algorithmCode]);
    var tag = messageAuthenticationCodeFromEncryptedSecret(macKey, associatedData, message.initializationVector, message.encryptedSecret);
    return (Buffer.compare(message.tag, tag) === 0);
}
function decryptMessage(message, secretKey) {
    var cipherKey = cipherKeyFromContentEncryptionKey(secretKey, algorithm);
    var decipher = crypto_1.createDecipheriv(cbcAlgorithm, cipherKey, message.initializationVector);
    var secret = decipher.update(message.encryptedSecret);
    secret = Buffer.concat([secret, decipher.final()]);
    return secret;
}
function decryptSymmetric256(encryptedMessage, secretKey) {
    var message = splitEncryptedMessage(encryptedMessage);
    if (message.algorithmCode !== algorithmCode)
        throw "bad message type. this algorithm can only decode AEAD";
    var macKey = macKeyFromContentEncryptionKey(secretKey, algorithm);
    if (!isMessageAuthentic(macKey, message)) {
        throw "not able to authenticate";
    }
    var secret = decryptMessage(message, secretKey);
    return secret;
}
exports.decryptSymmetric256 = decryptSymmetric256;
function generateAsymmetric2048KeyPairAsync(passphrase) {
    var options = {
        modulusLength: 2048,
        publicExponent: 0x10001,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem',
            cipher: 'aes-256-cbc',
            passphrase: passphrase
        }
    };
    var generateKeyPairAsync = util_1.promisify(crypto_1.generateKeyPair);
    return generateKeyPairAsync('rsa', options);
}
exports.generateAsymmetric2048KeyPairAsync = generateAsymmetric2048KeyPairAsync;
function encryptUsingPublicKey(secret, publicKeyAsString) {
    if (secret.length > 256 / 8)
        throw "RSA encryption is limited in the size of payload";
    var publicKey = crypto_1.createPublicKey({ key: publicKeyAsString, format: 'pem', type: 'spki' });
    return crypto_1.publicEncrypt(publicKey, secret);
}
exports.encryptUsingPublicKey = encryptUsingPublicKey;
function decryptUsingPrivateKey(encryptedSecret, privateKey) {
    return crypto_1.privateDecrypt(privateKey, encryptedSecret);
}
exports.decryptUsingPrivateKey = decryptUsingPrivateKey;
function decryptPrivateKey(passphrase, privateKeyAsString) {
    var privateKey = crypto_1.createPrivateKey({ key: privateKeyAsString, format: 'pem', type: 'pkcs8', passphrase: passphrase });
    return privateKey;
}
exports.decryptPrivateKey = decryptPrivateKey;
function symmetricKeyTest() {
    var key = generateSymmetric256Key(true);
    console.log('Key (' + key.length + ' bytes): ' + key.toString('base64') + " " + key.toString('hex'));
    var cipherKey = cipherKeyFromContentEncryptionKey(key, algorithm);
    console.log('ENC_KEY (' + cipherKey.length + ' bytes): ' + cipherKey.toString('base64') + " " + cipherKey.toString('hex'));
    // const macKey = macKeyFromContentEncryptionKey(key, algorithm);
    // console.log('MAC_KEY (' + macKey.length + ' bytes): ' + macKey.toString('base64')+" "+ macKey.toString('hex'));
    // const secrets = [
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
    // for(var i = 0; i != secrets.length; ++i) {
    //     const encryptedPayload = encryptSymmetric256(Buffer.from(secrets[i]), key);
    //     console.log(decryptSymmetric256(encryptedPayload, key).toString());
    //     const message = splitEncryptedMessage(encryptedPayload);
    //     console.log('algorithmCode (1 byte): ' + message.algorithmCode.toString());
    //     console.log('initializationVector (' + message.initializationVector.length + " bytes): " + message.initializationVector.toString('base64') + " " + message.initializationVector.toString('hex'));
    //     console.log('encryptedSecret (' + message.encryptedSecret.length + " bytes): " + message.encryptedSecret.toString('base64') + " " + message.encryptedSecret.toString('hex'));
    //     console.log('tag (' + message.tag.length + " bytes): " + message.tag.toString('base64') + " " + message.tag.toString('hex'));
    //     console.log('concatenated payload ('+ encryptedPayload.length +' bytes):');
    //     console.log(encryptedPayload.toString('base64'));
    //     console.log(encryptedPayload.toString('hex'));
    //     console.log()
    // }
}
function asymmetricKeyTestAsync() {
    var secret = generateSymmetric256Key();
    var passphrase = generateSymmetric256Key().toString('base64');
    return generateAsymmetric2048KeyPairAsync(passphrase).then(function (keys) {
        console.log('public key:');
        console.log(keys.publicKey);
        console.log('private key:');
        console.log(keys.privateKey);
        console.log('private key passphrase: ' + passphrase);
        var encryptedPayload = encryptUsingPublicKey(Buffer.from(secret), keys.publicKey);
        console.log(encryptedPayload.toString('base64'));
        var privateKey = decryptPrivateKey(passphrase, keys.privateKey);
        console.log('decrypted secret: ' + decryptUsingPrivateKey(encryptedPayload, privateKey).toString('base64'));
        console.log('original secret:  ' + secret.toString('base64'));
        console.log();
    });
}
function ietfTestCase() {
    // verify against known implementation https://tools.ietf.org/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05#section-5.3
    var cipherKey = Buffer.from("18191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637", "hex");
    var macKey = Buffer.from("000102030405060708090a0b0c0d0e0f1011121314151617", 'hex');
    var associatedData = Buffer.from("546865207365636f6e64207072696e6369706c65206f662041756775737465204b6572636b686f666673", "hex");
    var initializationVector = Buffer.from("1af38c2dc2b96ffdd86694092341bc04", "hex");
    var secret = Buffer.from("41206369706865722073797374656d206d757374206e6f7420626520726571756972656420746f206265207365637265742c20616e64206974206d7573742062652061626c6520746f2066616c6c20696e746f207468652068616e6473206f662074686520656e656d7920776974686f757420696e636f6e76656e69656e6365", "hex");
    console.log(secret.toString());
    var associatedDataLengthBits = Buffer.alloc(8);
    associatedDataLengthBits.writeBigUInt64BE(BigInt(associatedData.length * 8), 0);
    var expectedAssociatedDataLengthBits = Buffer.from("0000000000000150", "hex");
    if (expectedAssociatedDataLengthBits.compare(associatedDataLengthBits) !== 0) {
        console.log('  actual associated data length: ' + associatedDataLengthBits.toString('hex'));
        console.log('expected associated data length: ' + expectedAssociatedDataLengthBits.toString('hex'));
    }
    var result = encryptAndTag(cipherKey, macKey, associatedData, initializationVector, secret);
    var expectedSecret = Buffer.from("893129b0f4ee9eb18d75eda6f2aaa9f3607c98c4ba0444d34162170d8961884e58f27d4a35a5e3e3234aa99404f327f5c2d78e986e5749858b88bcddc2ba05218f195112d6ad48fa3b1e89aa7f20d596682f10b3648d3bb0c983c3185f59e36d28f647c1c13988de8ea0d821198c150977e28ca768080bc78c35faed69d8c0b7d9f506232198a489a1a6ae03a319fb30", "hex");
    if (expectedSecret.compare(result.encryptedSecret) !== 0) {
        console.log('  actual secret: ' + result.encryptedSecret.toString('base64'));
        console.log('expected secret: ' + expectedSecret.toString('base64'));
    }
    var expectedTag = Buffer.from("dd131d05ab3467dd056f8e882bad70637f1e9a541d9c23e7", "hex");
    if (expectedTag.compare(result.tag) !== 0) {
        console.log('  actual tag: ' + result.tag.toString('hex'));
        console.log('expected tag: ' + expectedTag);
    }
}
symmetricKeyTest();
// asymmetricKeyTestAsync().then(() => {
//     ietfTestCase();
// });
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
