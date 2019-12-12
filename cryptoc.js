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
var FIXED_ARRAY = [98, 183, 249, 18, 137, 227, 35, 73, 241, 243, 134, 94, 109, 227, 127, 115, 128, 55, 115, 66, 163, 238, 63, 239, 250, 236, 168, 247, 21, 10, 201, 134];
var FIXED_ARRAY16 = [78, 27, 238, 163, 112, 200, 84, 93, 183, 58, 101, 218, 37, 131, 14, 212];
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
    // const initializationVector = randomBytes(ivLength);
    var initializationVector = Buffer.from(FIXED_ARRAY16);
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
    console.log("isMessageAuthentic tag", tag);
    console.log("isMessageAuthentic message.tag", message.tag);
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
    var macKey = macKeyFromContentEncryptionKey(key, algorithm);
    console.log('MAC_KEY (' + macKey.length + ' bytes): ' + macKey.toString('base64') + " " + macKey.toString('hex'));
    var secrets = [
        'some seriously secret stuff',
    ];
    for (var i = 0; i != secrets.length; ++i) {
        var encryptedPayload = encryptSymmetric256(Buffer.from(secrets[i]), key);
        console.log(decryptSymmetric256(encryptedPayload, key).toString());
        var message = splitEncryptedMessage(encryptedPayload);
        console.log('algorithmCode (1 byte): ' + message.algorithmCode.toString());
        console.log('initializationVector (' + message.initializationVector.length + " bytes): " + message.initializationVector.toString('base64') + " " + message.initializationVector.toString('hex'));
        console.log('encryptedSecret (' + message.encryptedSecret.length + " bytes): " + message.encryptedSecret.toString('base64') + " " + message.encryptedSecret.toString('hex'));
        console.log('tag (' + message.tag.length + " bytes): " + message.tag.toString('base64') + " " + message.tag.toString('hex'));
        console.log('concatenated payload (' + encryptedPayload.length + ' bytes):');
        console.log(encryptedPayload.toString('base64'));
        console.log(encryptedPayload.toString('hex'));
        console.log();
    }
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY3J5cHRvYy5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbImNyeXB0b2MudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7QUFBQSxpQ0FZZ0I7QUFDaEIsNkJBQStCO0FBRS9CLElBQU0sWUFBWSxHQUFHLGFBQWEsQ0FBQztBQUNuQyxJQUFNLGVBQWUsR0FBRyxFQUFFLENBQUM7QUFDM0IsSUFBTSxTQUFTLEdBQUcsOEJBQThCLENBQUM7QUFDakQsSUFBTSxhQUFhLEdBQUcsQ0FBQyxDQUFDO0FBQ3hCLElBQU0sdUJBQXVCLEdBQUcsQ0FBQyxDQUFDO0FBQ2xDLElBQU0sUUFBUSxHQUFHLGVBQWUsQ0FBQztBQUNqQyxJQUFNLFNBQVMsR0FBRyxFQUFFLENBQUMsQ0FBQyxnQ0FBZ0M7QUFDdEQsSUFBTSxXQUFXLEdBQUcsQ0FBQyxFQUFFLEVBQUMsR0FBRyxFQUFDLEdBQUcsRUFBQyxFQUFFLEVBQUMsR0FBRyxFQUFDLEdBQUcsRUFBQyxFQUFFLEVBQUMsRUFBRSxFQUFDLEdBQUcsRUFBQyxHQUFHLEVBQUMsR0FBRyxFQUFDLEVBQUUsRUFBQyxHQUFHLEVBQUMsR0FBRyxFQUFDLEdBQUcsRUFBQyxHQUFHLEVBQUMsR0FBRyxFQUFDLEVBQUUsRUFBQyxHQUFHLEVBQUMsRUFBRSxFQUFDLEdBQUcsRUFBQyxHQUFHLEVBQUMsRUFBRSxFQUFDLEdBQUcsRUFBQyxHQUFHLEVBQUMsR0FBRyxFQUFDLEdBQUcsRUFBQyxHQUFHLEVBQUMsRUFBRSxFQUFDLEVBQUUsRUFBQyxHQUFHLEVBQUMsR0FBRyxDQUFDLENBQUM7QUFDNUksSUFBTSxhQUFhLEdBQUcsQ0FBQyxFQUFFLEVBQUUsRUFBRSxFQUFFLEdBQUcsRUFBRSxHQUFHLEVBQUUsR0FBRyxFQUFFLEdBQUcsRUFBRSxFQUFFLEVBQUUsRUFBRSxFQUFFLEdBQUcsRUFBRSxFQUFFLEVBQUUsR0FBRyxFQUFFLEdBQUcsRUFBRSxFQUFFLEVBQUUsR0FBRyxFQUFFLEVBQUUsRUFBRSxHQUFHLENBQUMsQ0FBQTtB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