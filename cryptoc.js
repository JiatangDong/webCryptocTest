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
var FIXED_ARRAY = [215, 4, 169, 9, 70, 78, 202, 51, 31, 6, 146, 226, 225, 115, 17, 158, 44, 65, 68, 137, 154, 4, 124, 226, 182, 177, 158, 61, 48, 150, 25, 205];
var FIXED_ARRAY16 = [78, 27, 238, 163, 112, 200, 84, 93, 183, 58, 101, 218, 37, 131, 14, 212];
var utf8Decoder = new TextDecoder();
var utf8Encoder = new TextEncoder();
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
        '',
        '1',
        '22',
        '333',
        '4444',
        '55555',
        '666666',
        '7777777',
        '88888888',
        '999999999',
        'aaaaaaaaaa',
        'bbbbbbbbbbb',
        'cccccccccccc',
        'ddddddddddddd',
        'eeeeeeeeeeeeee',
        'fffffffffffffff',
        '0000000000000000',
    ];
    for (var i = 0; i != secrets.length; ++i) {
        var encryptedPayload = encryptSymmetric256(Buffer.from(secrets[i]), key);
        var decryptedPayload = decryptSymmetric256(encryptedPayload, key);
        var message = splitEncryptedMessage(encryptedPayload);
        console.log('algorithmCode (1 byte): ' + message.algorithmCode.toString());
        console.log('initializationVector (' + message.initializationVector.length + " bytes): " + message.initializationVector.toString('base64') + " " + message.initializationVector.toString('hex'));
        console.log('encryptedSecret (' + message.encryptedSecret.length + " bytes): " + message.encryptedSecret.toString('base64') + " " + message.encryptedSecret.toString('hex'));
        console.log('tag (' + message.tag.length + " bytes): " + message.tag.toString('base64') + " " + message.tag.toString('hex'));
        console.log('concatenated payload (' + encryptedPayload.length + ' bytes):');
        // console.log(encryptedPayload.toString('base64'));
        console.log(encryptedPayload.toString('hex'));
        console.log(decryptedPayload.toString());
        console.log();
    }
}
function asymmetricKeyTestAsync() {
    var secret = "ABCDEF";
    var passphrase = '12345';
    return generateAsymmetric2048KeyPairAsync(passphrase).then(function (keys) {
        console.log('public key:');
        console.log(keys.publicKey);
        console.log('private key:');
        console.log(keys.privateKey);
        console.log('private key passphrase: ' + passphrase);
        var encryptedPayload = encryptUsingPublicKey(Buffer.from(utf8Encoder.encode(secret)), keys.publicKey);
        console.log(encryptedPayload.toString('base64'));
        console.log(encryptedPayload.toString('hex'));
        var privateKey = decryptPrivateKey(passphrase, keys.privateKey);
        console.log('decrypted secret: ' + utf8Decoder.decode(decryptUsingPrivateKey(encryptedPayload, privateKey)));
        console.log('original secret:  ' + secret);
        console.log();
    });
}
function ietfTestCase() {
    console.log("Running");
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
// symmetricKeyTest();
// asymmetricKeyTestAsync().then(() => {
//     ietfTestCase();
// });
// asymmetricKeyTestAsync()
var ppk = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIODDAHfjJfzQCAggA\nMAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBAR4nD0EKPW8jf7m+QqJ+yqBIIE\n0Gqfmez18vZyWbPBEnGeaqkWE1WWkmxO+z+ISuVqrzf/CCcUzp+JM7eK5yHwpz8d\nylzmfVXXlVWQjidFHBV0KlB4KymOpjiaEJKFk6DlJ6J4ilrNnpIRjdR5st7WHhTj\nnWevgVmog+LgUwqJqtrH/g4xJJH0WS1dAJ/lMeaum0x4X1oXoHCHNsQQht8oesBC\nKUBmzvu0kIEGaPICxOXby5MH3y2qepg8g2+5v4Wjs8NeIJEjvvqmxDfLNjzP+XMB\nMkYp07OOFnLNuR28fCrhuG3ZoB6dNXDT64lonynT/3DY8iCB9Ff31ikJuHHkWAgV\nmrxUZoXbUBdGeGZiTtYJl5t7KmyvUMvy5aOMS2Oqpc4asDrmPxWyhWWsFGx2Jc7y\nVOTwtFyb44po5x+q81piNi7843TfUapT5bj47uUncV3FhSKOAdIrZebn1G0bTzsy\ns1t0UOkkQ1BdWtP9R3qui6x9/yPrqR0LKMfDBg4N0Rj7IZLlFRsRPS/M5RWtKaTM\n14KQX2d9dkGOtzni34ZnN1wj0Iv2ugKuHc8AafrUoyrTM7pfCxy/nlJWOjRAPPd+\nTlZHm+lJJ+kr8zpc+6E7siNFbWiRZyfcxWR8RPkrazJwCdw+ChxmAdaF4uYpuge+\nXCVkOliS40NSVcczGofuWa/1/czZ7x/UBxagOy7wbtuG/0JmnyKPmVXnbseIeZLO\nBpjQyDGefRQpCQGRgqH17FIkMSK6oMvkbn1diAYGNXgLshsKgWmKO4ZNcJYQldix\nomERWCNnEGVDxkkF/O225oWdq4Bh7zd/DwpkU4fNqQy2kaV0hLfDgNDPXUwqAjku\nBqqdmJveMIrKkkviZ3/fyE0+bFdsPufBN3HikONSFuJWEMDhQOTULdsCt/SVyZJ8\nnpbCuarErDmv2BFf6eB/WFjwRQc1UtrNMxMN99kFmKxiwctF+v/FyHELiq0ZM/cB\nGqCoaD3FsnfmxKmOJL/xQhZwcMBnoO4PzzEpIELvsGgddsMbPCmDkM+geoUA51oi\n6d0wya0tAFDloD4lpz4Y+ztlDGCn517Bm3IRHMisi6xiDg125wxnWtlPUyj0bBGF\nCnHnCYano6J++QeT1J1nv6kluTKHDPTc/GIVPbyIQsw6wxc3uzrNaUac5uk28E3G\nsPYpR4TnYWRbr4E3MZF4fijY0AzN1VjztuYLVjEyzgOd9ySBQgjD6GAEXy6hI7N/\n4BIvgyNXZEap+X2LhaZM44DIj1HRVk+apnwHzo1JkQl8hzW48aLnOElm3TIqlbkm\n+zKeqZsv3C0mluvvLKZqTHcaq7RRqawv26rpNeGGlT9w5nVbjAV7w97ZXK+Nmw5Q\n4y7zfp6PTip3BKY7OE6FLMWUIRe8UU9IlYAUBui/6ZTkNlwuTthSPcUl/YW/Zs8b\nmcSSCNXRu4t15zHQKhK4PQFNxXGEvh4SYfuU8qwbTfA03BjbzJPRpgyHk8GVik9l\nMSb908CT++deFxinjc42SOdsMsfLDq0rNR0/B0PiVj6n7tTXCB+ZJWoxpp8CsZZi\nHEddx7R8MWvcWoxN0XM7mU1a6sI5dVi0QRHQUsiYKVdhNVOjZU9jGETy95xAZY6+\n0oCcX52LSWbaF0aTiayEPvynQf3+rVz5DpPvcW5jg/V8\n-----END ENCRYPTED PRIVATE KEY-----";
var pub = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuN2wrjziTzUHA0NfM6VU\nCuk6wJHIrjVNaFM3n9TlXkogSQk2kMQ94bQZJPdESQeeQiZAtdTBbI8Mzwfpt+nT\nK5FX+WjvDhur2ZoQzpl+2BQOXAw5y0nAT7jZHT45BdGd4Hmlv+PkKEj7VYV6euHY\nmE0QYWdRZn63esjj2GJHJRyr0uEWzXbUqrYN4MH1TvhyE8uk3axOVwEO9TPHOnAq\nFQO2AriSETtZnvxaGUxWMtE3ykK8XlWB0NZ5sH+X5QeBFX/UqRi7glNR5yBkI0D4\nM3C6RKkV9Eopb7JY9U+2k5KtldsuxgUMXEuy2eepcF2pS6h4FkVVdcBjKjeYBSJt\nswIDAQAB\n-----END PUBLIC KEY-----";
var privateKey = crypto_1.createPrivateKey({ key: ppk, format: 'pem', type: 'pkcs8', passphrase: '12345' });
var publicKey = crypto_1.createPublicKey({ key: pub, type: 'spki' });
var payload = utf8Encoder.encode("123abcdedfdf");
var enc = crypto_1.publicEncrypt(publicKey, payload);
var d = crypto_1.privateDecrypt(privateKey, enc);
console.log(utf8Decoder.decode(d));
// const salt = [79, 225, 136, 232, 158, 39, 68, 116, 152, 131, 219, 227, 70, 62, 222, 113];
// pbkdf2('12345', Buffer.from(salt), 10000, 128, 'sha256', (err, derivedKey) => {
//     if (err) throw err;
//     console.log(derivedKey.toString('base64'));  // '3745e48...aa39b34'
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY3J5cHRvYy5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbImNyeXB0b2MudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7QUFBQSxpQ0FhZ0I7QUFDaEIsNkJBQStCO0FBRS9CLElBQU0sWUFBWSxHQUFHLGFBQWEsQ0FBQztBQUNuQyxJQUFNLGVBQWUsR0FBRyxFQUFFLENBQUM7QUFDM0IsSUFBTSxTQUFTLEdBQUcsOEJBQThCLENBQUM7QUFDakQsSUFBTSxhQUFhLEdBQUcsQ0FBQyxDQUFDO0FBQ3hCLElBQU0sdUJBQXVCLEdBQUcsQ0FBQyxDQUFDO0FBQ2xDLElBQU0sUUFBUSxHQUFHLGVBQWUsQ0FBQztBQUNqQyxJQUFNLFNBQVMsR0FBRyxFQUFFLENBQUMsQ0FBQyxnQ0FBZ0M7QUFDdEQsSUFBTSxXQUFXLEdBQUcsQ0FBQyxHQUFHLEVBQUUsQ0FBQyxFQUFFLEdBQUcsRUFBRSxDQUFDLEVBQUUsRUFBRSxFQUFFLEVBQUUsRUFBRSxHQUFHLEVBQUUsRUFBRSxFQUFFLEVBQUUsRUFBRSxDQUFDLEVBQUUsR0FBRyxFQUFFLEdBQUcsRUFBRSxHQUFHLEVBQUUsR0FBRyxFQUFFLEVBQUUsRUFBRSxHQUFHLEVBQUUsRUFBRSxFQUFFLEVBQUUsRUFBRSxFQUFFLEVBQUUsR0FBRyxFQUFFLEdBQUcsRUFBRSxDQUFDLEVBQUUsR0FBRyxFQUFFLEdBQUcsRUFBRSxHQUFHLEVBQUUsR0FBRyxFQUFFLEdBQUcsRUFBRSxFQUFFLEVBQUUsRUFBRSxFQUFFLEdBQUcsRUFBRSxFQUFFLEVBQUUsR0FBRyxDQUFDLENBQUM7QUFDbEssSUFBTSxhQUFhLEdBQUcsQ0FBQyxFQUFFLEVBQUUsRUFBRSxFQUFFLEdBQUcsRUFBRSxHQUFHLEVBQUUsR0FBRyxFQUFFLEdBQUcsRUFBRSxFQUFFLEVBQUUsRUFBRSxFQUFFLEdBQUcsRUFBRSxFQUFFLEVBQUUsR0FBRyxFQUFFLEdBQUcsRUFBRSxFQUFFLEVBQUUsR0FBRyxFQUFFLEVBQUUsRUFBRSxHQUFHLENBQUMsQ0FBQTtB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