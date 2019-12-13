const aes256BlockSize = 16;
const algorithm = 'AEAD_AES_256_CBC_HMAC_SHA384';
const algorithmCode = 1;
const algorithmCodeByteLength = 1;
const ivLength = aes256BlockSize;
const tagLength = 24; // from half of sha384 (384/2/8)

const FIXED_ARRAY = [215, 4, 169, 9, 70, 78, 202, 51, 31, 6, 146, 226, 225, 115, 17, 158, 44, 65, 68, 137, 154, 4, 124, 226, 182, 177, 158, 61, 48, 150, 25, 205];
const FIXED_ARRAY16 = [78, 27, 238, 163, 112, 200, 84, 93, 183, 58, 101, 218, 37, 131, 14, 212]

async function hmacSha256Async(cek: Uint8Array, type: string, algorithm: string): Promise<ArrayBuffer> {
    const utf8Encoder = new TextEncoder();
    const typeBytes = utf8Encoder.encode(type);
    const algorithmBytes = utf8Encoder.encode(algorithm);
    const cekLengthBytes = utf8Encoder.encode(cek.byteLength.toString());
    const buffer = new Uint8Array(typeBytes.length + algorithmBytes.length + cekLengthBytes.length);
    buffer.set(typeBytes);
    buffer.set(algorithmBytes, typeBytes.byteLength);
    buffer.set(cekLengthBytes, typeBytes.byteLength + algorithmBytes.byteLength);

    const key = await crypto.subtle.importKey('raw', cek, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const crytoPromise = crypto.subtle.sign('HMAC', key, buffer);
    return await crytoPromise;
}

function cipherKeyFromContentEncryptionKeyAsync(cek: Uint8Array, algorithm: string) : PromiseLike<ArrayBuffer> {
    return hmacSha256Async(cek, 'Microsoft Teams Vault Symmetric Encryption Key', algorithm);
}

function macKeyFromContentEncryptionKeyAsync(cek: Uint8Array, algorithm: string): PromiseLike<ArrayBuffer> {
    return hmacSha256Async(cek, 'Microsoft Teams Vault Message Authentication Code Key', algorithm);
}

function buf2hex(buf: any): string {
    return Array.prototype.map.call(new Uint8Array(buf), x=>(('00'+x.toString(16)).slice(-2))).join('');
}

/*export*/ function generateSymmetric256Key(fixedKey = null): Uint8Array {
    var buffer = new Uint8Array(256/8);
    if (fixedKey != null) {
        buffer = new Uint8Array(fixedKey);
    } else {
        crypto.getRandomValues(buffer);
    }
    return buffer;
}

function messageData(algorithmCode: number, initializationVector: Uint8Array, encryptedSecret: Uint8Array):Uint8Array {
    const associatedDataLengthBits = new Uint8Array(8); // encoded as big endian
    associatedDataLengthBits[7] = 8;
    const data = new Uint8Array(
        algorithmCodeByteLength + 
        initializationVector.byteLength +
        encryptedSecret.byteLength +
        associatedDataLengthBits.byteLength);
    data[0] = algorithmCode;

    data.set(initializationVector, algorithmCodeByteLength);
    data.set(encryptedSecret, algorithmCodeByteLength + initializationVector.byteLength);
    data.set(associatedDataLengthBits, algorithmCodeByteLength + initializationVector.byteLength + encryptedSecret.byteLength);
    return data;
}

async function encryptAndTagAsync(rawCipherKey: ArrayBuffer, rawMacKey: ArrayBuffer, algorithmCode: number, initializationVector: Uint8Array, secret: Uint8Array)
        : Promise<{tag: Uint8Array, data: Uint8Array}> {
    if (algorithmCode != 1) {
        throw 'invalid algorithm code. Only 1 is supported';
    }
    const aesParams : AesCbcParams = {
        name: 'AES-CBC',
        iv: initializationVector
    };
    const cipherKey = await crypto.subtle.importKey('raw', rawCipherKey, { name: 'AES-CBC', length: 256 }, false, ['encrypt']);
    const encryptedSecret = await crypto.subtle.encrypt(aesParams, cipherKey, secret);
    const data = messageData(algorithmCode, initializationVector, new Uint8Array(encryptedSecret));
    const macKey = await crypto.subtle.importKey('raw', rawMacKey, { name: 'HMAC', hash: 'SHA-384' }, false, ['sign']);
    const tag = await crypto.subtle.sign('HMAC', macKey, data);
    return {
        data: data.slice(0, -8),
        tag: new Uint8Array(tag.slice(0, tagLength))
    };
}

async function encryptSymmetric256Async(secret: Uint8Array, secretKey: Uint8Array) : Promise<Uint8Array> {
    const rawCipherKey = await cipherKeyFromContentEncryptionKeyAsync(secretKey, algorithm);
    const rawMacKey = await macKeyFromContentEncryptionKeyAsync(secretKey, algorithm);
    // const initializationVector = new Uint8Array(ivLength);
    // crypto.getRandomValues(initializationVector);
    const initializationVector = new Uint8Array(FIXED_ARRAY16);
    const result = await encryptAndTagAsync(rawCipherKey, rawMacKey, algorithmCode, initializationVector, secret);
    const buffer = new Uint8Array(result.data.byteLength + result.tag.byteLength);
    buffer.set(result.data);
    buffer.set(result.tag, result.data.byteLength);
    return buffer;
}

function splitEncryptedMessage(encryptedMessage: Uint8Array)
        : {algorithmCode: number, tag: Uint8Array, initializationVector: Uint8Array, encryptedSecret: Uint8Array} {
    const ivStart = algorithmCodeByteLength;
    const encryptedSecretStart = ivStart + ivLength;
    const encryptedSecretEnd = encryptedMessage.length - tagLength;
    const tagStart = encryptedSecretEnd;

    const algorithmCode = encryptedMessage[0];
    const initializationVector = encryptedMessage.slice(ivStart, ivStart + ivLength);
    const encryptedSecret = encryptedMessage.slice(encryptedSecretStart, encryptedSecretEnd);
    const tag = encryptedMessage.slice(tagStart, tagStart + tagLength);
    return { algorithmCode, initializationVector, encryptedSecret, tag };
}

async function decryptMessageAsync(
        message: {initializationVector: Uint8Array, encryptedSecret: Uint8Array},
        secretKey: Uint8Array) : Promise<ArrayBuffer> {
    const rawCipherKey = await cipherKeyFromContentEncryptionKeyAsync(secretKey, algorithm);
    const cipherKey = await crypto.subtle.importKey('raw', rawCipherKey, { name: 'AES-CBC', length: 256 }, false, ['decrypt']);
    const aesParams: AesCbcParams = {
        name: 'AES-CBC',
        iv: message.initializationVector
    };
    return crypto.subtle.decrypt(aesParams, cipherKey, message.encryptedSecret);
}

function equalArray<T>(a: ArrayLike<T>, b: ArrayLike<T>) : boolean
{
    if (a.length !== b.length) return false;
    for(let i = 0; i !== a.length; ++i)
    {
        if (a[i] != b[i]) return false;
    }
    return true;
}

/*export*/ async function decryptSymmetric256Async(encryptedMessage: Uint8Array, secretKey: Uint8Array) : Promise<ArrayBuffer> {
    const message = splitEncryptedMessage(encryptedMessage);
    if (encryptedMessage[0] !== algorithmCode) {
        throw "bad message type. this algorithm can only decode AEAD_AES_256_CBC_HMAC_SHA384";
    }

    const rawMacKey = await macKeyFromContentEncryptionKeyAsync(secretKey, algorithm);
    const macKey = await crypto.subtle.importKey('raw', rawMacKey, { name: 'HMAC', hash: 'SHA-384' }, false, ['sign']);
    const data = messageData(message.algorithmCode, message.initializationVector, message.encryptedSecret);
    const signature = (await crypto.subtle.sign('HMAC', macKey, data)).slice(0, tagLength); // this is not correct


    const isMessageAuthentic = equalArray(message.tag, new Uint8Array(signature));
    if (!isMessageAuthentic) {
        throw "not able to authenticate";
    }
    return decryptMessageAsync(message, secretKey);
}

function Uint8ArrayFromHex(s: String): Uint8Array{
    const matcher = s.match(/[0-9a-f]{2}/gi);
    if (matcher) {
        return new Uint8Array(matcher.map(hexDigit => parseInt(hexDigit, 16)));
    }
    return new Uint8Array(0);
}

// function Base64FromArrayBuffer(a: ArrayBuffer): string {
//     return Base64FromUint8Array(new Uint8Array(a));
// }

// function Base64FromUint8Array(a: Uint8Array): string {
//     return btoa(String.fromCharCode(...a));
// }

function Uint8ArrayFromBase64(s: string): Uint8Array {
    const b = atob(s);
    const buffer = new Uint8Array(b.length);
    Array.prototype.forEach.call(buffer, (_: any, i : number, a : any[]) => a[i] = b.charCodeAt(i));
    return buffer;
}

async function symmetricKeyTestAsync() : Promise<void> {

    const key = generateSymmetric256Key(FIXED_ARRAY);
    console.log('Key (' + key.length + ' bytes): ' + buf2hex(key));

    const cipherKey = await cipherKeyFromContentEncryptionKeyAsync(key, algorithm);
    console.log('ENC_KEY (' + cipherKey.byteLength + ' bytes): ' + buf2hex(cipherKey));

    const macKey = await macKeyFromContentEncryptionKeyAsync(key, algorithm);
    console.log('MAC_KEY (' + macKey.byteLength + ' bytes): ' + buf2hex(macKey));

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

    const utf8Decoder = new TextDecoder();
    const utf8Encoder = new TextEncoder();
    for(var i = 0; i != secrets.length; ++i) {
        const buf = utf8Encoder.encode(secrets[i]);
        const encryptedPayload = await encryptSymmetric256Async(buf, key);
        const decryptedPayload = await decryptSymmetric256Async(encryptedPayload, key);
        const decryptedSecret = utf8Decoder.decode(decryptedPayload)

        console.log("-------------------");
        console.log("secret:", secrets[i]);
        console.log("encryptedPayload:", buf2hex(encryptedPayload));
        console.log("decryptedPayload:", decryptedSecret);
        console.log("success:", secrets[i] == decryptedSecret);


        // const message = splitEncryptedMessage(encryptedPayload);
        // console.log('algorithmCode (1 byte): ' + message.algorithmCode.toString());
        // console.log('initializationVector (' + message.initializationVector.length + " bytes): " + message.initializationVector.toString('base64') + " " + message.initializationVector.toString('hex'));
        // console.log('encryptedSecret (' + message.encryptedSecret.length + " bytes): " + message.encryptedSecret.toString('base64') + " " + message.encryptedSecret.toString('hex'));
        // console.log('tag (' + message.tag.length + " bytes): " + message.tag.toString('base64') + " " + message.tag.toString('hex'));
        // console.log('concatenated payload ('+ encryptedPayload.length +' bytes):');
        // console.log(encryptedPayload.toString('base64'));
        // console.log(encryptedPayload.toString('hex'));
        // console.log()
    }
}

symmetricKeyTestAsync();
