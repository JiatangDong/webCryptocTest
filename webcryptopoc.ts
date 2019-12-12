const aes256BlockSize = 16;
const algorithm = 'AEAD_AES_256_CBC_HMAC_SHA384';
const algorithmCode = 1;
const algorithmCodeByteLength = 1;
const ivLength = aes256BlockSize;
const tagLength = 24; // from half of sha384 (384/2/8)

const FIXED_ARRAY = [98,183,249,18,137,227,35,73,241,243,134,94,109,227,127,115,128,55,115,66,163,238,63,239,250,236,168,247,21,10,201,134];
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
        data,
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
        // '',
        '1',
        // '22',
        // '333',
        // '4444',
        // '55555',
        // '666666',
        // '7777777',
        // '88888888',
        // '999999999',
        // 'aaaaaaaaaa',
        // 'bbbbbbbbbbb',
        // 'cccccccccccc',
        // 'ddddddddddddd',
        // 'eeeeeeeeeeeeee',
        // 'fffffffffffffff',
        // '0000000000000000',
        // generateSymmetric256Key().toString('base64')
    ];

    const utf8Decoder = new TextDecoder();
    const utf8Encoder = new TextEncoder();
    for(var i = 0; i != secrets.length; ++i) {
        const buf = utf8Encoder.encode(secrets[i]);
        const encryptedPayload = await encryptSymmetric256Async(buf, key);
        console.log(buf2hex(encryptedPayload));
        const decryptedPayload = await decryptSymmetric256Async(encryptedPayload, key);
        console.log(decryptedPayload);
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

    // const secrets = [
    //     { plaintext: 'some seriously secret stuff', encrypted: 'AYlapAevhHinapEOd2cjh97AnJ83RPcXxUM26l5wzvsZXFEaYLe8d8UyedvLzGm1ohotReGXh7le840d3Y7nm7Qg5D2dqTR0Cg==' },
    //     { plaintext: '', encrypted: 'AVHxOUWDSThDb4iyEAQIbaVeCUsUQhQAq6GdWdfEcN1d6fAqrKsMooFNOC5NIC4CS13LXJeXHeOe' },
    //     { plaintext: '1', encrypted: 'ATBzEapyo/g2j/ivm6AjuBDHbhUfmDxUZxltKDvMlFLd3tw+h1EcTEvLAK5HlY0R2yIN2eaiBJE2' },
    //     { plaintext: '22', encrypted: 'AQCT/AyZibVfyhaObFOAUPOK2G8xxJxdrI0s42VVYDVU36rD7L5+m8q94EtvujyqkPJrhS6BkBKI' },
    //     { plaintext: '333', encrypted: 'AaQaxBLrxE7J7QuAvnFlrOI6W2OMgoAHehgrG6+gLk9xafcJFkZcbLMxr+yZqXqW2UxXnA25r2q+' },
    //     { plaintext: '4444', encrypted: 'AbwZFNkUewWFCaeLN8qhLPjRaOGKmETC9/YHBNfkFhSVsaa7eCKg4J5qbWjJ4s5jOdxz/JQ66G4W' },
    //     { plaintext: '55555', encrypted: 'ASG2Ggh8Kr5eAJnz69gu9Ww0bU/Y12+kjDun17+hl0ijPmBoL00CQhsHkVnaEbHkMc+O20OLl6gW' },
    //     { plaintext: '666666', encrypted: 'ASmtrK2fTwWn9Ye/K1z74kcuoUaxRJrykdHL6WtwyYHM2iXliP9aDvD445T3Oz3i6dXiDEQGICDk' },
    //     { plaintext: '7777777', encrypted: 'Af+L8OyKDdZMTbzzveOKkMACf7amfNnvalQobZqLTtivBzCIM00THUZlXA8gCIMj7fE6lEBdscrH' },
    //     { plaintext: '88888888', encrypted: 'AdyTnmzfmE/dt+2s5VDukTsD7fJz0uapwHczUzMCWFXb6iXGLoCuzW38WsxdnY4DuRcQ3nsG7Nj1' },
    //     { plaintext: '999999999', encrypted: 'AZiUEsBkuZPXetwSHNdTNX0Q+UsGFPD8SelHwM9/gh4EpmT2cD68umVlAz1/WHUEoEXS/gcYr3TR' },
    //     { plaintext: 'aaaaaaaaaa', encrypted: 'ARyRIRAlV8QCiShwuXLtekL03eDg0wWy+Y3mSiLoAZ4JnoH0OHo7N9wE3kNWM8Q3UcR3LXTR6pI5' },
    //     { plaintext: 'bbbbbbbbbbb', encrypted: 'AQNM90BU7pTXBG+gzGI8Ev1OBEz1rOe2kEP9Uslf09Ttpd8GlIASkQ47QV+y3BlmmIAQhW56TWIj' },
    //     { plaintext: 'cccccccccccc', encrypted: 'AfBs+z4d0pxqhWaSY0DkGhimucwa5kBWVdRTM+G1FU3VD4mobvkfa68cpK0WkCmGqiG2mj9mmPD7' },
    //     { plaintext: 'ddddddddddddd', encrypted: 'AfMCgcvDfaUpfllQXt1nMo6ugSUQfj5J6FirtlqeTrVsx3ZaYAnMtSrJZOVWfsoqzf8v513aZo4b' },
    //     { plaintext: 'eeeeeeeeeeeeee', encrypted: 'AZETlLelS/G1D9Q7H2ntGmQn+q2ejvZ+OVOhJQ/tNS/XEmpC5huCsf5MkLL7Ln/WP+e2I7W/k8Vs' },
    //     { plaintext: 'fffffffffffffff', encrypted: 'AdiJSL7O5/qetzlYLXMBDSuW1YaN2y7Ujb37O4SE+y6LWbpMdMwWD8719x6Hj/6nJiFdzf1t/XxP' },
    //     { plaintext: '0000000000000000', encrypted: 'AYMR7MOQEtFER3VUUk68wTxoWMg+N372smULrlSnMxeMyHc95tiN1N1Ch80O85bPhq03a/b3e0zhs+yxLNiBjBbSQN7onYn/BA==' },
    //     { plaintext: '97Ahhtgu6RPXFpklQ/lkYS92KmqFO4iPXDBWwTJJdWY=', encrypted: 'AcL76MT/JcYwnGFrIcuI+QYY4D6WEEjFDsLuk/YEsnBiULyIbP5SeD4JG8CdjGjBGD0nCJOVaVYYYd+4ZE2HsukofPJloBIMyuZyO207bxuHKb9n+Nuu5fo=' },
    // ];
    // const utf8Decoder = new TextDecoder();
    // const utf8Encoder = new TextEncoder();
    // for (var i = 0; i != secrets.length; ++i) {
    //     const rawPlaintext = await decryptSymmetric256Async(Uint8ArrayFromBase64(secrets[i].encrypted), key);
    //     const plaintext = utf8Decoder.decode(rawPlaintext);
    //     if (plaintext !== secrets[i].plaintext) {
    //         const message = splitEncryptedMessage(Uint8ArrayFromBase64(secrets[i].encrypted));
    //         console.log('algorithmCode (1 byte): ' + message.algorithmCode.toString());
    //         console.log('initializationVector (' + message.initializationVector.length + " bytes): " + message.initializationVector);
    //         console.log('encryptedSecret (' + message.encryptedSecret.length + " bytes): " + message.encryptedSecret);
    //         console.log('tag (' + message.tag.length + " bytes): " + message.tag);
    //         console.log('expected: ' + secrets[i].plaintext);
    //         console.log('actual: ' + plaintext);
    //         throw 'plaintext <' + secrets[i].plaintext + '> was not correctly decrypted';
    //     }

    //     const encryptedPayload = await encryptSymmetric256Async(utf8Encoder.encode(plaintext), key);
    //     const rawRoundtrip = await decryptSymmetric256Async(Uint8ArrayFromBase64(secrets[i].encrypted), key);
    //     const roundtrip = utf8Decoder.decode(rawRoundtrip);
    //     if (plaintext !== roundtrip) {
    //         const message_1 = splitEncryptedMessage(new Uint8Array(encryptedPayload));
    //         console.log('algorithmCode (1 byte): ' + message_1.algorithmCode.toString());
    //         console.log('initializationVector (' + message_1.initializationVector.length + " bytes): " + message_1.initializationVector);
    //         console.log('encryptedSecret (' + message_1.encryptedSecret.length + " bytes): " + message_1.encryptedSecret);
    //         console.log('tag (' + message_1.tag.length + " bytes): " + message_1.tag);
    //         console.log('expected: ' + plaintext);
    //         console.log('actual: ' + roundtrip);
    //         throw 'plaintext <' + plaintext + '> was not correctly encrypted';
    //     }
    // }
    // console.log('finished symmetric tests')
}

symmetricKeyTestAsync();
