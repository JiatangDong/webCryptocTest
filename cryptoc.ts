import {
    createCipheriv,
    createDecipheriv,
    createHmac, 
    createPrivateKey,
    createPublicKey,
    generateKeyPair,
    privateDecrypt,
    publicEncrypt,
    randomBytes,
    KeyObject,
    RSAKeyPairOptions,
    pbkdf2
} from 'crypto';
import {promisify} from 'util';

const cbcAlgorithm = 'aes-256-cbc';
const aes256BlockSize = 16;
const algorithm = 'AEAD_AES_256_CBC_HMAC_SHA384';
const algorithmCode = 1;
const algorithmCodeByteLength = 1;
const ivLength = aes256BlockSize;
const tagLength = 24; // from half of sha384 (384/2/8)
const FIXED_ARRAY = [215, 4, 169, 9, 70, 78, 202, 51, 31, 6, 146, 226, 225, 115, 17, 158, 44, 65, 68, 137, 154, 4, 124, 226, 182, 177, 158, 61, 48, 150, 25, 205];
const FIXED_ARRAY16 = [78, 27, 238, 163, 112, 200, 84, 93, 183, 58, 101, 218, 37, 131, 14, 212]

const utf8Decoder = new TextDecoder();
const utf8Encoder = new TextEncoder();

function hmacSha256(cek: Buffer, type: string, algorithm: string): Buffer {
    const hmac = createHmac('sha256', cek);
    hmac.update(type);
    hmac.update(algorithm);
    hmac.update(cek.byteLength.toString());
    return hmac.digest();
}

function cipherKeyFromContentEncryptionKey(cek: Buffer, algorithm: string) : Buffer {
    return hmacSha256(cek, 'Microsoft Teams Vault Symmetric Encryption Key', algorithm);
}

function macKeyFromContentEncryptionKey(cek: Buffer, algorithm: string): Buffer {
    return hmacSha256(cek, 'Microsoft Teams Vault Message Authentication Code Key', algorithm);
}

export function generateSymmetric256Key(fixed: boolean = false): Buffer {
    if (fixed) {
        return Buffer.from(FIXED_ARRAY);
    }
    return randomBytes(256/8);
}

function messageAuthenticationCodeFromEncryptedSecret(macKey: Buffer, associatedData: Buffer, initializationVector: Buffer, encryptedSecret: Buffer): Buffer {
    const associatedDataLengthBits = Buffer.alloc(64/8);
    associatedDataLengthBits.writeBigUInt64BE(BigInt(associatedData.length*8), 0);

    const hmac = createHmac('sha384', macKey);
    hmac.update(associatedData);

    hmac.update(initializationVector);
    hmac.update(encryptedSecret);
    hmac.update(associatedDataLengthBits);

    return hmac.digest().slice(0, tagLength);
}

function encryptAndTag(cipherKey: Buffer, macKey: Buffer, associatedData: Buffer, initializationVector: Buffer, secret: Buffer): {tag, encryptedSecret} {
    const cipher = createCipheriv(cbcAlgorithm, cipherKey, initializationVector);
    let encryptedSecret = cipher.update(secret); // api automatically adds PKCS7 padding so no need to manually add
    encryptedSecret = Buffer.concat([encryptedSecret, cipher.final()]);

    const tag = messageAuthenticationCodeFromEncryptedSecret(macKey, associatedData, initializationVector, encryptedSecret);
    return {tag, encryptedSecret}
}


export function encryptSymmetric256(secret: Buffer, secretKey: Buffer) : Buffer {
    const associatedData = Buffer.from([algorithmCode]);
    const cipherKey = cipherKeyFromContentEncryptionKey(secretKey, algorithm);
    const macKey = macKeyFromContentEncryptionKey(secretKey, algorithm);
    // const initializationVector = randomBytes(ivLength);
    const initializationVector = Buffer.from(FIXED_ARRAY16);
    const result = encryptAndTag(cipherKey, macKey, associatedData, initializationVector, secret);
    let encryptedMessage = Buffer.concat([
        associatedData,
        initializationVector,
        result.encryptedSecret,
        result.tag]);
    return encryptedMessage;

}

function splitEncryptedMessage(encryptedMessage: Buffer) : {algorithmCode: number, tag: Buffer, initializationVector: Buffer, encryptedSecret: Buffer} {
    const ivStart = algorithmCodeByteLength;
    const encryptedSecretStart = ivStart + ivLength;
    const encryptedSecretEnd = encryptedMessage.length - tagLength;
    const tagStart = encryptedSecretEnd;

    const algorithmCode = encryptedMessage.readUInt8(0);
    const initializationVector = encryptedMessage.slice(ivStart, ivStart + ivLength);
    const encryptedSecret = encryptedMessage.slice(encryptedSecretStart, encryptedSecretEnd);
    const tag = encryptedMessage.slice(tagStart, tagStart + tagLength);
    return {algorithmCode, initializationVector, encryptedSecret, tag};
}

function isMessageAuthentic(
        macKey: Buffer,
        message: {algorithmCode: number, initializationVector: Buffer, encryptedSecret: Buffer, tag: Buffer},
        ): boolean {
    const associatedData = Buffer.from([message.algorithmCode]);
    const tag = messageAuthenticationCodeFromEncryptedSecret(macKey, associatedData, message.initializationVector, message.encryptedSecret);
    return (Buffer.compare(message.tag, tag) === 0);
}

function decryptMessage(
        message: {initializationVector: Buffer, encryptedSecret: Buffer},
        secretKey: Buffer) : Buffer {
    const cipherKey = cipherKeyFromContentEncryptionKey(secretKey, algorithm);
    const decipher = createDecipheriv(cbcAlgorithm, cipherKey, message.initializationVector);
    let secret = decipher.update(message.encryptedSecret);
    secret = Buffer.concat([secret, decipher.final()]);
    return secret;
}

export function decryptSymmetric256(encryptedMessage: Buffer, secretKey: Buffer) : Buffer {
    const message = splitEncryptedMessage(encryptedMessage);
    if (message.algorithmCode !== algorithmCode) throw "bad message type. this algorithm can only decode AEAD"

    const macKey = macKeyFromContentEncryptionKey(secretKey, algorithm);
    if (!isMessageAuthentic(macKey, message)) {
        throw "not able to authenticate";
    }

    const secret = decryptMessage(message, secretKey);
    return secret;
}

export function generateAsymmetric2048KeyPairAsync(passphrase: string) : Promise<{publicKey: string, privateKey: string}> {
    const options: RSAKeyPairOptions<'pem', 'pem'> = {
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

    const generateKeyPairAsync = promisify(generateKeyPair);
    return generateKeyPairAsync('rsa', options);
}

export function encryptUsingPublicKey(secret: Buffer, publicKeyAsString: string): Buffer {
    if (secret.length > 256/8) throw "RSA encryption is limited in the size of payload";

    const publicKey = createPublicKey({key: publicKeyAsString, format: 'pem', type: 'spki'});
    return publicEncrypt(publicKey, secret);
}

export function decryptUsingPrivateKey(encryptedSecret: Buffer, privateKey: KeyObject): Buffer {
    return privateDecrypt(privateKey, encryptedSecret);
}

export function decryptPrivateKey(passphrase: string, privateKeyAsString: string) : KeyObject {
    const privateKey = createPrivateKey({key: privateKeyAsString, format: 'pem', type: 'pkcs8', passphrase: passphrase});
    return privateKey;
}

function symmetricKeyTest() {
    const key = generateSymmetric256Key(true);
    console.log('Key (' + key.length + ' bytes): ' + key.toString('base64') + " " + key.toString('hex'));

    const cipherKey = cipherKeyFromContentEncryptionKey(key, algorithm);
    console.log('ENC_KEY (' + cipherKey.length + ' bytes): ' + cipherKey.toString('base64') + " " + cipherKey.toString('hex'));

    const macKey = macKeyFromContentEncryptionKey(key, algorithm);
    console.log('MAC_KEY (' + macKey.length + ' bytes): ' + macKey.toString('base64')+" "+ macKey.toString('hex'));

    const secrets = [
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
        // generateSymmetric256Key().toString('base64')
    ];

    for(var i = 0; i != secrets.length; ++i) {
        const encryptedPayload = encryptSymmetric256(Buffer.from(secrets[i]), key);
        const decryptedPayload = decryptSymmetric256(encryptedPayload, key);

        const message = splitEncryptedMessage(encryptedPayload);
        console.log('algorithmCode (1 byte): ' + message.algorithmCode.toString());
        console.log('initializationVector (' + message.initializationVector.length + " bytes): " + message.initializationVector.toString('base64') + " " + message.initializationVector.toString('hex'));
        console.log('encryptedSecret (' + message.encryptedSecret.length + " bytes): " + message.encryptedSecret.toString('base64') + " " + message.encryptedSecret.toString('hex'));
        console.log('tag (' + message.tag.length + " bytes): " + message.tag.toString('base64') + " " + message.tag.toString('hex'));
        console.log('concatenated payload ('+ encryptedPayload.length +' bytes):');
        // console.log(encryptedPayload.toString('base64'));
        console.log(encryptedPayload.toString('hex'));
        console.log(decryptedPayload.toString());
        console.log()
    }
}

function asymmetricKeyTestAsync() : Promise<void> {
    const secret = "ABCDEF";
    const passphrase = '12345';
    return generateAsymmetric2048KeyPairAsync(passphrase).then((keys)=>{
        console.log('public key:');
        console.log(keys.publicKey);
        console.log('private key:');
        console.log(keys.privateKey);
        console.log('private key passphrase: ' + passphrase);

        const encryptedPayload = encryptUsingPublicKey(Buffer.from(utf8Encoder.encode(secret)), keys.publicKey);
        console.log(encryptedPayload.toString('base64'));
        console.log(encryptedPayload.toString('hex'));
        const privateKey = decryptPrivateKey(passphrase, keys.privateKey);
        console.log('decrypted secret: ' + utf8Decoder.decode(decryptUsingPrivateKey(encryptedPayload, privateKey)));
        console.log('original secret:  ' + secret );
        console.log();
    });
}

function ietfTestCase() {
    console.log("Running")

    // verify against known implementation https://tools.ietf.org/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05#section-5.3
    const cipherKey = Buffer.from("18191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637", "hex");
    const macKey = Buffer.from("000102030405060708090a0b0c0d0e0f1011121314151617", 'hex');
    const associatedData = Buffer.from("546865207365636f6e64207072696e6369706c65206f662041756775737465204b6572636b686f666673", "hex");
    const initializationVector = Buffer.from("1af38c2dc2b96ffdd86694092341bc04", "hex");
    const secret = Buffer.from("41206369706865722073797374656d206d757374206e6f7420626520726571756972656420746f206265207365637265742c20616e64206974206d7573742062652061626c6520746f2066616c6c20696e746f207468652068616e6473206f662074686520656e656d7920776974686f757420696e636f6e76656e69656e6365", "hex");
    console.log(secret.toString());


    const associatedDataLengthBits = Buffer.alloc(8);
    associatedDataLengthBits.writeBigUInt64BE(BigInt(associatedData.length*8), 0);
    const expectedAssociatedDataLengthBits = Buffer.from("0000000000000150", "hex");
    if (expectedAssociatedDataLengthBits.compare(associatedDataLengthBits) !== 0) {
        console.log('  actual associated data length: ' + associatedDataLengthBits.toString('hex'));
        console.log('expected associated data length: ' + expectedAssociatedDataLengthBits.toString('hex'));
    }
    

    const result = encryptAndTag(cipherKey, macKey, associatedData, initializationVector, secret);

    const expectedSecret = Buffer.from("893129b0f4ee9eb18d75eda6f2aaa9f3607c98c4ba0444d34162170d8961884e58f27d4a35a5e3e3234aa99404f327f5c2d78e986e5749858b88bcddc2ba05218f195112d6ad48fa3b1e89aa7f20d596682f10b3648d3bb0c983c3185f59e36d28f647c1c13988de8ea0d821198c150977e28ca768080bc78c35faed69d8c0b7d9f506232198a489a1a6ae03a319fb30", "hex");
    if (expectedSecret.compare(result.encryptedSecret) !== 0) {
        console.log('  actual secret: ' + result.encryptedSecret.toString('base64'));
        console.log('expected secret: ' + expectedSecret.toString('base64'));
    }

    const expectedTag = Buffer.from("dd131d05ab3467dd056f8e882bad70637f1e9a541d9c23e7", "hex");
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

const ppk = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIODDAHfjJfzQCAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBAR4nD0EKPW8jf7m+QqJ+yqBIIE
0Gqfmez18vZyWbPBEnGeaqkWE1WWkmxO+z+ISuVqrzf/CCcUzp+JM7eK5yHwpz8d
ylzmfVXXlVWQjidFHBV0KlB4KymOpjiaEJKFk6DlJ6J4ilrNnpIRjdR5st7WHhTj
nWevgVmog+LgUwqJqtrH/g4xJJH0WS1dAJ/lMeaum0x4X1oXoHCHNsQQht8oesBC
KUBmzvu0kIEGaPICxOXby5MH3y2qepg8g2+5v4Wjs8NeIJEjvvqmxDfLNjzP+XMB
MkYp07OOFnLNuR28fCrhuG3ZoB6dNXDT64lonynT/3DY8iCB9Ff31ikJuHHkWAgV
mrxUZoXbUBdGeGZiTtYJl5t7KmyvUMvy5aOMS2Oqpc4asDrmPxWyhWWsFGx2Jc7y
VOTwtFyb44po5x+q81piNi7843TfUapT5bj47uUncV3FhSKOAdIrZebn1G0bTzsy
s1t0UOkkQ1BdWtP9R3qui6x9/yPrqR0LKMfDBg4N0Rj7IZLlFRsRPS/M5RWtKaTM
14KQX2d9dkGOtzni34ZnN1wj0Iv2ugKuHc8AafrUoyrTM7pfCxy/nlJWOjRAPPd+
TlZHm+lJJ+kr8zpc+6E7siNFbWiRZyfcxWR8RPkrazJwCdw+ChxmAdaF4uYpuge+
XCVkOliS40NSVcczGofuWa/1/czZ7x/UBxagOy7wbtuG/0JmnyKPmVXnbseIeZLO
BpjQyDGefRQpCQGRgqH17FIkMSK6oMvkbn1diAYGNXgLshsKgWmKO4ZNcJYQldix
omERWCNnEGVDxkkF/O225oWdq4Bh7zd/DwpkU4fNqQy2kaV0hLfDgNDPXUwqAjku
BqqdmJveMIrKkkviZ3/fyE0+bFdsPufBN3HikONSFuJWEMDhQOTULdsCt/SVyZJ8
npbCuarErDmv2BFf6eB/WFjwRQc1UtrNMxMN99kFmKxiwctF+v/FyHELiq0ZM/cB
GqCoaD3FsnfmxKmOJL/xQhZwcMBnoO4PzzEpIELvsGgddsMbPCmDkM+geoUA51oi
6d0wya0tAFDloD4lpz4Y+ztlDGCn517Bm3IRHMisi6xiDg125wxnWtlPUyj0bBGF
CnHnCYano6J++QeT1J1nv6kluTKHDPTc/GIVPbyIQsw6wxc3uzrNaUac5uk28E3G
sPYpR4TnYWRbr4E3MZF4fijY0AzN1VjztuYLVjEyzgOd9ySBQgjD6GAEXy6hI7N/
4BIvgyNXZEap+X2LhaZM44DIj1HRVk+apnwHzo1JkQl8hzW48aLnOElm3TIqlbkm
+zKeqZsv3C0mluvvLKZqTHcaq7RRqawv26rpNeGGlT9w5nVbjAV7w97ZXK+Nmw5Q
4y7zfp6PTip3BKY7OE6FLMWUIRe8UU9IlYAUBui/6ZTkNlwuTthSPcUl/YW/Zs8b
mcSSCNXRu4t15zHQKhK4PQFNxXGEvh4SYfuU8qwbTfA03BjbzJPRpgyHk8GVik9l
MSb908CT++deFxinjc42SOdsMsfLDq0rNR0/B0PiVj6n7tTXCB+ZJWoxpp8CsZZi
HEddx7R8MWvcWoxN0XM7mU1a6sI5dVi0QRHQUsiYKVdhNVOjZU9jGETy95xAZY6+
0oCcX52LSWbaF0aTiayEPvynQf3+rVz5DpPvcW5jg/V8
-----END ENCRYPTED PRIVATE KEY-----`

const pub = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuN2wrjziTzUHA0NfM6VU
Cuk6wJHIrjVNaFM3n9TlXkogSQk2kMQ94bQZJPdESQeeQiZAtdTBbI8Mzwfpt+nT
K5FX+WjvDhur2ZoQzpl+2BQOXAw5y0nAT7jZHT45BdGd4Hmlv+PkKEj7VYV6euHY
mE0QYWdRZn63esjj2GJHJRyr0uEWzXbUqrYN4MH1TvhyE8uk3axOVwEO9TPHOnAq
FQO2AriSETtZnvxaGUxWMtE3ykK8XlWB0NZ5sH+X5QeBFX/UqRi7glNR5yBkI0D4
M3C6RKkV9Eopb7JY9U+2k5KtldsuxgUMXEuy2eepcF2pS6h4FkVVdcBjKjeYBSJt
swIDAQAB
-----END PUBLIC KEY-----`

const privateKey = createPrivateKey({key: ppk, format: 'pem', type: 'pkcs8', passphrase: '12345'});
const publicKey = createPublicKey({key: pub, type: 'spki'})
const payload = utf8Encoder.encode("123abcdedfdf")

const enc = publicEncrypt(publicKey, payload)
const d = privateDecrypt(privateKey, enc)
console.log(utf8Decoder.decode(d))

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
