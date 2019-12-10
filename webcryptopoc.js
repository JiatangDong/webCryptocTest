var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var __read = (this && this.__read) || function (o, n) {
    var m = typeof Symbol === "function" && o[Symbol.iterator];
    if (!m) return o;
    var i = m.call(o), r, ar = [], e;
    try {
        while ((n === void 0 || n-- > 0) && !(r = i.next()).done) ar.push(r.value);
    }
    catch (error) { e = { error: error }; }
    finally {
        try {
            if (r && !r.done && (m = i["return"])) m.call(i);
        }
        finally { if (e) throw e.error; }
    }
    return ar;
};
var __spread = (this && this.__spread) || function () {
    for (var ar = [], i = 0; i < arguments.length; i++) ar = ar.concat(__read(arguments[i]));
    return ar;
};
var aes256BlockSize = 16;
var algorithm = 'AEAD_AES_256_CBC_HMAC_SHA384';
var algorithmCode = 1;
var algorithmCodeByteLength = 1;
var ivLength = aes256BlockSize;
var tagLength = 24; // from half of sha384 (384/2/8)
var FIXED_ARRAY = [98, 183, 249, 18, 137, 227, 35, 73, 241, 243, 134, 94, 109, 227, 127, 115, 128, 55, 115, 66, 163, 238, 63, 239, 250, 236, 168, 247, 21, 10, 201, 134];
function hmacSha256Async(cek, type, algorithm) {
    return __awaiter(this, void 0, void 0, function () {
        var utf8Encoder, typeBytes, algorithmBytes, cekLengthBytes, buffer, key;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    utf8Encoder = new TextEncoder();
                    typeBytes = utf8Encoder.encode(type);
                    algorithmBytes = utf8Encoder.encode(algorithm);
                    cekLengthBytes = utf8Encoder.encode(cek.byteLength.toString());
                    buffer = new Uint8Array(typeBytes.length + algorithmBytes.length + cekLengthBytes.length);
                    buffer.set(typeBytes);
                    buffer.set(algorithmBytes, typeBytes.byteLength);
                    buffer.set(cekLengthBytes, typeBytes.byteLength + algorithmBytes.byteLength);
                    return [4 /*yield*/, crypto.subtle.importKey('raw', cek, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])];
                case 1:
                    key = _a.sent();
                    return [4 /*yield*/, crypto.subtle.sign('HMAC', key, buffer)];
                case 2: return [2 /*return*/, _a.sent()];
            }
        });
    });
}
function cipherKeyFromContentEncryptionKeyAsync(cek, algorithm) {
    return hmacSha256Async(cek, 'Microsoft Teams Vault Symmetric Encryption Key', algorithm);
}
function macKeyFromContentEncryptionKeyAsync(cek, algorithm) {
    return hmacSha256Async(cek, 'Microsoft Teams Vault Message Authentication Code Key', algorithm);
}
function buf2hex(buf) {
    return Array.prototype.map.call(new Uint8Array(buf), function (x) { return (('00' + x.toString(16)).slice(-2)); }).join('');
}
/*export*/ function generateSymmetric256Key(fixedKey) {
    if (fixedKey === void 0) { fixedKey = null; }
    var buffer = new Uint8Array(256 / 8);
    if (fixedKey != null) {
        buffer = new Uint8Array(fixedKey);
    }
    else {
        crypto.getRandomValues(buffer);
    }
    return buffer;
}
function messageData(algorithmCode, initializationVector, encryptedSecret) {
    var associatedDataLengthBits = new Uint8Array(8); // encoded as big endian
    associatedDataLengthBits[7] = 8;
    var data = new Uint8Array(algorithmCodeByteLength +
        initializationVector.byteLength +
        encryptedSecret.byteLength +
        associatedDataLengthBits.byteLength);
    data[0] = algorithmCode;
    data.set(initializationVector, algorithmCodeByteLength);
    data.set(encryptedSecret, algorithmCodeByteLength + initializationVector.byteLength);
    data.set(associatedDataLengthBits, algorithmCodeByteLength + initializationVector.byteLength + encryptedSecret.byteLength);
    return data;
}
function encryptAndTagAsync(rawCipherKey, rawMacKey, algorithmCode, initializationVector, secret) {
    return __awaiter(this, void 0, void 0, function () {
        var aesParams, cipherKey, encryptedSecret, data, macKey, tag;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    if (algorithmCode != 1) {
                        throw 'invalid algorithm code. Only 1 is supported';
                    }
                    aesParams = {
                        name: 'AES-CBC',
                        iv: initializationVector
                    };
                    return [4 /*yield*/, crypto.subtle.importKey('raw', rawCipherKey, { name: 'AES-CBC', length: 256 }, false, ['encrypt'])];
                case 1:
                    cipherKey = _a.sent();
                    return [4 /*yield*/, crypto.subtle.encrypt(aesParams, cipherKey, secret)];
                case 2:
                    encryptedSecret = _a.sent();
                    data = messageData(algorithmCode, initializationVector, new Uint8Array(encryptedSecret));
                    return [4 /*yield*/, crypto.subtle.importKey('raw', rawMacKey, { name: 'HMAC', hash: 'SHA-384' }, false, ['sign'])];
                case 3:
                    macKey = _a.sent();
                    return [4 /*yield*/, crypto.subtle.sign('HMAC', macKey, data)];
                case 4:
                    tag = _a.sent();
                    return [2 /*return*/, {
                            data: data,
                            tag: new Uint8Array(tag.slice(0, tagLength))
                        }];
            }
        });
    });
}
/*export*/ function encryptSymmetric256Async(secret, secretKey) {
    return __awaiter(this, void 0, void 0, function () {
        var rawCipherKey, rawMacKey, initializationVector, result, buffer;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, cipherKeyFromContentEncryptionKeyAsync(secretKey, algorithm)];
                case 1:
                    rawCipherKey = _a.sent();
                    return [4 /*yield*/, macKeyFromContentEncryptionKeyAsync(secretKey, algorithm)];
                case 2:
                    rawMacKey = _a.sent();
                    initializationVector = new Uint8Array(ivLength);
                    crypto.getRandomValues(initializationVector);
                    return [4 /*yield*/, encryptAndTagAsync(rawCipherKey, rawMacKey, algorithmCode, initializationVector, secret)];
                case 3:
                    result = _a.sent();
                    buffer = new Uint8Array(result.data.byteLength + result.tag.byteLength);
                    buffer.set(result.data);
                    buffer.set(result.tag, result.data.byteLength);
                    return [2 /*return*/, buffer];
            }
        });
    });
}
function splitEncryptedMessage(encryptedMessage) {
    var ivStart = algorithmCodeByteLength;
    var encryptedSecretStart = ivStart + ivLength;
    var encryptedSecretEnd = encryptedMessage.length - tagLength;
    var tagStart = encryptedSecretEnd;
    var algorithmCode = encryptedMessage[0];
    var initializationVector = encryptedMessage.slice(ivStart, ivStart + ivLength);
    var encryptedSecret = encryptedMessage.slice(encryptedSecretStart, encryptedSecretEnd);
    var tag = encryptedMessage.slice(tagStart, tagStart + tagLength);
    return { algorithmCode: algorithmCode, initializationVector: initializationVector, encryptedSecret: encryptedSecret, tag: tag };
}
function decryptMessageAsync(message, secretKey) {
    return __awaiter(this, void 0, void 0, function () {
        var rawCipherKey, cipherKey, aesParams;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, cipherKeyFromContentEncryptionKeyAsync(secretKey, algorithm)];
                case 1:
                    rawCipherKey = _a.sent();
                    return [4 /*yield*/, crypto.subtle.importKey('raw', rawCipherKey, { name: 'AES-CBC', length: 256 }, false, ['decrypt'])];
                case 2:
                    cipherKey = _a.sent();
                    aesParams = {
                        name: 'AES-CBC',
                        iv: message.initializationVector
                    };
                    return [2 /*return*/, crypto.subtle.decrypt(aesParams, cipherKey, message.encryptedSecret)];
            }
        });
    });
}
function equalArray(a, b) {
    if (a.length !== b.length)
        return false;
    for (var i = 0; i !== a.length; ++i) {
        if (a[i] != b[i])
            return false;
    }
    return true;
}
/*export*/ function decryptSymmetric256Async(encryptedMessage, secretKey) {
    return __awaiter(this, void 0, void 0, function () {
        var message, rawMacKey, macKey, data, signature, isMessageAuthentic;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    message = splitEncryptedMessage(encryptedMessage);
                    if (encryptedMessage[0] !== algorithmCode)
                        throw "bad message type. this algorithm can only decode AEAD_AES_256_CBC_HMAC_SHA384";
                    return [4 /*yield*/, macKeyFromContentEncryptionKeyAsync(secretKey, algorithm)];
                case 1:
                    rawMacKey = _a.sent();
                    return [4 /*yield*/, crypto.subtle.importKey('raw', rawMacKey, { name: 'HMAC', hash: 'SHA-384' }, false, ['sign'])];
                case 2:
                    macKey = _a.sent();
                    data = messageData(message.algorithmCode, message.initializationVector, message.encryptedSecret);
                    return [4 /*yield*/, crypto.subtle.sign('HMAC', macKey, data)];
                case 3:
                    signature = (_a.sent()).slice(0, tagLength);
                    isMessageAuthentic = equalArray(message.tag, new Uint8Array(signature));
                    if (!isMessageAuthentic) {
                        throw "not able to authenticate";
                    }
                    return [2 /*return*/, decryptMessageAsync(message, secretKey)];
            }
        });
    });
}
function Uint8ArrayFromHex(s) {
    var matcher = s.match(/[0-9a-f]{2}/gi);
    if (matcher) {
        return new Uint8Array(matcher.map(function (hexDigit) { return parseInt(hexDigit, 16); }));
    }
    return new Uint8Array(0);
}
function Base64FromArrayBuffer(a) {
    return Base64FromUint8Array(new Uint8Array(a));
}
function Base64FromUint8Array(a) {
    return btoa(String.fromCharCode.apply(String, __spread(a)));
}
function Uint8ArrayFromBase64(s) {
    var b = atob(s);
    var buffer = new Uint8Array(b.length);
    Array.prototype.forEach.call(buffer, function (_, i, a) { return a[i] = b.charCodeAt(i); });
    return buffer;
}
function symmetricKeyTestAsync() {
    return __awaiter(this, void 0, void 0, function () {
        var key, cipherKey, macKey, secrets, utf8Decoder, utf8Encoder, i, rawPlaintext, plaintext, message, encryptedPayload, rawRoundtrip, roundtrip, message_1;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    key = generateSymmetric256Key(FIXED_ARRAY);
                    console.log('Key (' + key.length + ' bytes): ' + buf2hex(key));
                    return [4 /*yield*/, cipherKeyFromContentEncryptionKeyAsync(key, algorithm)];
                case 1:
                    cipherKey = _a.sent();
                    console.log('Key (' + cipherKey.byteLength + ' bytes): ' + buf2hex(cipherKey));
                    if (Base64FromArrayBuffer(cipherKey) !== 'hWf9EsSbSLvhzJ4kdxcNLF4Pq8XUYqajWLtGqhUL2SQ=') {
                        console.log('Expected: hWf9EsSbSLvhzJ4kdxcNLF4Pq8XUYqajWLtGqhUL2SQ=');
                        console.log('Actual:   ' + Base64FromArrayBuffer(cipherKey));
                        throw 'cipherKey was not correctly generated';
                    }
                    return [4 /*yield*/, macKeyFromContentEncryptionKeyAsync(key, algorithm)];
                case 2:
                    macKey = _a.sent();
                    if (Base64FromArrayBuffer(macKey) !== '6qmPn/wi9cDf3XQL66lNEPonYxAx7A95gavk9oODOWQ=') {
                        console.log('Expected: 6qmPn/wi9cDf3XQL66lNEPonYxAx7A95gavk9oODOWQ=');
                        console.log('Actual:   ' + Base64FromArrayBuffer(macKey));
                        throw 'macKey was not correctly generated';
                    }
                    secrets = [
                        { plaintext: 'some seriously secret stuff', encrypted: 'AYlapAevhHinapEOd2cjh97AnJ83RPcXxUM26l5wzvsZXFEaYLe8d8UyedvLzGm1ohotReGXh7le840d3Y7nm7Qg5D2dqTR0Cg==' },
                        { plaintext: '', encrypted: 'AVHxOUWDSThDb4iyEAQIbaVeCUsUQhQAq6GdWdfEcN1d6fAqrKsMooFNOC5NIC4CS13LXJeXHeOe' },
                        { plaintext: '1', encrypted: 'ATBzEapyo/g2j/ivm6AjuBDHbhUfmDxUZxltKDvMlFLd3tw+h1EcTEvLAK5HlY0R2yIN2eaiBJE2' },
                        { plaintext: '22', encrypted: 'AQCT/AyZibVfyhaObFOAUPOK2G8xxJxdrI0s42VVYDVU36rD7L5+m8q94EtvujyqkPJrhS6BkBKI' },
                        { plaintext: '333', encrypted: 'AaQaxBLrxE7J7QuAvnFlrOI6W2OMgoAHehgrG6+gLk9xafcJFkZcbLMxr+yZqXqW2UxXnA25r2q+' },
                        { plaintext: '4444', encrypted: 'AbwZFNkUewWFCaeLN8qhLPjRaOGKmETC9/YHBNfkFhSVsaa7eCKg4J5qbWjJ4s5jOdxz/JQ66G4W' },
                        { plaintext: '55555', encrypted: 'ASG2Ggh8Kr5eAJnz69gu9Ww0bU/Y12+kjDun17+hl0ijPmBoL00CQhsHkVnaEbHkMc+O20OLl6gW' },
                        { plaintext: '666666', encrypted: 'ASmtrK2fTwWn9Ye/K1z74kcuoUaxRJrykdHL6WtwyYHM2iXliP9aDvD445T3Oz3i6dXiDEQGICDk' },
                        { plaintext: '7777777', encrypted: 'Af+L8OyKDdZMTbzzveOKkMACf7amfNnvalQobZqLTtivBzCIM00THUZlXA8gCIMj7fE6lEBdscrH' },
                        { plaintext: '88888888', encrypted: 'AdyTnmzfmE/dt+2s5VDukTsD7fJz0uapwHczUzMCWFXb6iXGLoCuzW38WsxdnY4DuRcQ3nsG7Nj1' },
                        { plaintext: '999999999', encrypted: 'AZiUEsBkuZPXetwSHNdTNX0Q+UsGFPD8SelHwM9/gh4EpmT2cD68umVlAz1/WHUEoEXS/gcYr3TR' },
                        { plaintext: 'aaaaaaaaaa', encrypted: 'ARyRIRAlV8QCiShwuXLtekL03eDg0wWy+Y3mSiLoAZ4JnoH0OHo7N9wE3kNWM8Q3UcR3LXTR6pI5' },
                        { plaintext: 'bbbbbbbbbbb', encrypted: 'AQNM90BU7pTXBG+gzGI8Ev1OBEz1rOe2kEP9Uslf09Ttpd8GlIASkQ47QV+y3BlmmIAQhW56TWIj' },
                        { plaintext: 'cccccccccccc', encrypted: 'AfBs+z4d0pxqhWaSY0DkGhimucwa5kBWVdRTM+G1FU3VD4mobvkfa68cpK0WkCmGqiG2mj9mmPD7' },
                        { plaintext: 'ddddddddddddd', encrypted: 'AfMCgcvDfaUpfllQXt1nMo6ugSUQfj5J6FirtlqeTrVsx3ZaYAnMtSrJZOVWfsoqzf8v513aZo4b' },
                        { plaintext: 'eeeeeeeeeeeeee', encrypted: 'AZETlLelS/G1D9Q7H2ntGmQn+q2ejvZ+OVOhJQ/tNS/XEmpC5huCsf5MkLL7Ln/WP+e2I7W/k8Vs' },
                        { plaintext: 'fffffffffffffff', encrypted: 'AdiJSL7O5/qetzlYLXMBDSuW1YaN2y7Ujb37O4SE+y6LWbpMdMwWD8719x6Hj/6nJiFdzf1t/XxP' },
                        { plaintext: '0000000000000000', encrypted: 'AYMR7MOQEtFER3VUUk68wTxoWMg+N372smULrlSnMxeMyHc95tiN1N1Ch80O85bPhq03a/b3e0zhs+yxLNiBjBbSQN7onYn/BA==' },
                        { plaintext: '97Ahhtgu6RPXFpklQ/lkYS92KmqFO4iPXDBWwTJJdWY=', encrypted: 'AcL76MT/JcYwnGFrIcuI+QYY4D6WEEjFDsLuk/YEsnBiULyIbP5SeD4JG8CdjGjBGD0nCJOVaVYYYd+4ZE2HsukofPJloBIMyuZyO207bxuHKb9n+Nuu5fo=' },
                    ];
                    utf8Decoder = new TextDecoder();
                    utf8Encoder = new TextEncoder();
                    i = 0;
                    _a.label = 3;
                case 3:
                    if (!(i != secrets.length)) return [3 /*break*/, 8];
                    return [4 /*yield*/, decryptSymmetric256Async(Uint8ArrayFromBase64(secrets[i].encrypted), key)];
                case 4:
                    rawPlaintext = _a.sent();
                    plaintext = utf8Decoder.decode(rawPlaintext);
                    if (plaintext !== secrets[i].plaintext) {
                        message = splitEncryptedMessage(Uint8ArrayFromBase64(secrets[i].encrypted));
                        console.log('algorithmCode (1 byte): ' + message.algorithmCode.toString());
                        console.log('initializationVector (' + message.initializationVector.length + " bytes): " + message.initializationVector);
                        console.log('encryptedSecret (' + message.encryptedSecret.length + " bytes): " + message.encryptedSecret);
                        console.log('tag (' + message.tag.length + " bytes): " + message.tag);
                        console.log('expected: ' + secrets[i].plaintext);
                        console.log('actual: ' + plaintext);
                        throw 'plaintext <' + secrets[i].plaintext + '> was not correctly decrypted';
                    }
                    return [4 /*yield*/, encryptSymmetric256Async(utf8Encoder.encode(plaintext), key)];
                case 5:
                    encryptedPayload = _a.sent();
                    return [4 /*yield*/, decryptSymmetric256Async(Uint8ArrayFromBase64(secrets[i].encrypted), key)];
                case 6:
                    rawRoundtrip = _a.sent();
                    roundtrip = utf8Decoder.decode(rawRoundtrip);
                    if (plaintext !== roundtrip) {
                        message_1 = splitEncryptedMessage(new Uint8Array(encryptedPayload));
                        console.log('algorithmCode (1 byte): ' + message_1.algorithmCode.toString());
                        console.log('initializationVector (' + message_1.initializationVector.length + " bytes): " + message_1.initializationVector);
                        console.log('encryptedSecret (' + message_1.encryptedSecret.length + " bytes): " + message_1.encryptedSecret);
                        console.log('tag (' + message_1.tag.length + " bytes): " + message_1.tag);
                        console.log('expected: ' + plaintext);
                        console.log('actual: ' + roundtrip);
                        throw 'plaintext <' + plaintext + '> was not correctly encrypted';
                    }
                    _a.label = 7;
                case 7:
                    ++i;
                    return [3 /*break*/, 3];
                case 8:
                    console.log('finished symmetric tests');
                    return [2 /*return*/];
            }
        });
    });
}
symmetricKeyTestAsync();
