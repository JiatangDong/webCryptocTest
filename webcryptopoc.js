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
var saltLength = 32;
var tagLength = 24; // from half of sha384 (384/2/8)
var utf8Decoder = new TextDecoder();
var utf8Encoder = new TextEncoder();
var FIXED_ARRAY32 = [215, 4, 169, 9, 70, 78, 202, 51, 31, 6, 146, 226, 225, 115, 17, 158, 44, 65, 68, 137, 154, 4, 124, 226, 182, 177, 158, 61, 48, 150, 25, 205];
function generateRandomVector() {
    var buffer = new Uint8Array(ivLength);
    crypto.getRandomValues(buffer);
    return buffer;
}
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
/*export*/ function generateSymmetric256Key() {
    var buffer = new Uint8Array(256 / 8);
    crypto.getRandomValues(buffer);
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
    var persistDataByteLength = algorithmCodeByteLength + initializationVector.byteLength + encryptedSecret.byteLength;
    data.set(associatedDataLengthBits, persistDataByteLength);
    return { data: data, persistDataByteLength: persistDataByteLength };
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
                    return [4 /*yield*/, crypto.subtle.sign('HMAC', macKey, data.data)];
                case 4:
                    tag = _a.sent();
                    return [2 /*return*/, {
                            data: data.data,
                            dataByteLength: data.persistDataByteLength,
                            tag: new Uint8Array(tag.slice(0, tagLength))
                        }];
            }
        });
    });
}
/*export*/ function encryptSymmetric256Async(secret, secretKey, initializationVector) {
    return __awaiter(this, void 0, void 0, function () {
        var rawCipherKey, rawMacKey, result, buffer;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, cipherKeyFromContentEncryptionKeyAsync(secretKey, algorithm)];
                case 1:
                    rawCipherKey = _a.sent();
                    return [4 /*yield*/, macKeyFromContentEncryptionKeyAsync(secretKey, algorithm)];
                case 2:
                    rawMacKey = _a.sent();
                    if (!initializationVector) {
                        initializationVector = new Uint8Array(ivLength);
                        crypto.getRandomValues(initializationVector);
                    }
                    return [4 /*yield*/, encryptAndTagAsync(rawCipherKey, rawMacKey, algorithmCode, initializationVector, secret)];
                case 3:
                    result = _a.sent();
                    buffer = new Uint8Array(result.dataByteLength + result.tag.byteLength);
                    buffer.set(result.data);
                    buffer.set(result.tag, result.dataByteLength);
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
                    return [4 /*yield*/, crypto.subtle.sign('HMAC', macKey, data.data)];
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
function isFreeformAsciiChar(char) {
    return 0x20 <= char && char <= 0x7e;
}
function splitPasswordEncryptedMessage(passwordEncryptedMessage) {
    var saltStart = algorithmCodeByteLength;
    var iterationsStart = saltStart + saltLength;
    var encryptedMessageStart = iterationsStart + 4;
    var algorithmCode = passwordEncryptedMessage[0];
    var salt = passwordEncryptedMessage.slice(saltStart, saltStart + saltLength);
    var iterationsBigEndian = passwordEncryptedMessage.slice(iterationsStart, iterationsStart + 4);
    var iterations = numberFromUint8ArrayBigEndian(iterationsBigEndian);
    var encryptedMessage = passwordEncryptedMessage.slice(encryptedMessageStart);
    return { algorithmCode: algorithmCode, iterations: iterations, salt: salt, encryptedMessage: encryptedMessage };
}
function passwordEncryptAsync(passphrase, secret, iterations, salt) {
    return __awaiter(this, void 0, void 0, function () {
        var passwordDerivedEncryptionKey, iterationsBytesBigEndian, encryptedSecretMessage, result;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    if (iterations === undefined) {
                        iterations = 1000000;
                    }
                    if (salt === undefined) {
                        salt = generateSymmetric256Key();
                    }
                    return [4 /*yield*/, symmetric256KeyFromAsciiPassphraseAsync(passphrase, iterations, salt)];
                case 1:
                    passwordDerivedEncryptionKey = _a.sent();
                    iterationsBytesBigEndian = bigEndianUint8ArrayFromUint32(iterations);
                    return [4 /*yield*/, encryptSymmetric256Async(secret, new Uint8Array(passwordDerivedEncryptionKey))];
                case 2:
                    encryptedSecretMessage = _a.sent();
                    result = new Uint8Array(1 + salt.length + iterationsBytesBigEndian.length + encryptedSecretMessage.length);
                    result[0] = 1;
                    result.set(salt, 1);
                    result.set(iterationsBytesBigEndian, 1 + salt.length);
                    result.set(encryptedSecretMessage, 1 + salt.length + iterationsBytesBigEndian.length);
                    return [2 /*return*/, result];
            }
        });
    });
}
function symmetric256KeyFromAsciiPassphraseAsync(passphrase, iterations, salt) {
    return __awaiter(this, void 0, void 0, function () {
        var i, textEncoder, passKey, key;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    for (i = 0; i !== passphrase.length; ++i) {
                        if (!isFreeformAsciiChar(passphrase.charCodeAt(i))) {
                            throw 'invalid character in passphrase';
                        }
                    }
                    textEncoder = new TextEncoder();
                    return [4 /*yield*/, crypto.subtle.importKey('raw', textEncoder.encode(passphrase), 'PBKDF2', false, ['deriveBits'])];
                case 1:
                    passKey = _a.sent();
                    return [4 /*yield*/, crypto.subtle.deriveBits({
                            name: 'PBKDF2',
                            hash: 'SHA-256',
                            salt: salt,
                            iterations: iterations
                        }, passKey, 256)];
                case 2:
                    key = _a.sent();
                    return [2 /*return*/, key];
            }
        });
    });
}
/*export*/ function generateAsymmetric4096KeyPairAsync() {
    return __awaiter(this, void 0, void 0, function () {
        var keypair, publicKeyString, _a, privateKeyString, _b;
        return __generator(this, function (_c) {
            switch (_c.label) {
                case 0: return [4 /*yield*/, crypto.subtle.generateKey({
                        name: 'RSA-OAEP',
                        modulusLength: 4096,
                        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                        hash: 'SHA-256'
                    }, true, ['encrypt', 'decrypt'])];
                case 1:
                    keypair = _c.sent();
                    _a = base64FromArrayBuffer;
                    return [4 /*yield*/, crypto.subtle.exportKey('spki', keypair.publicKey)];
                case 2:
                    publicKeyString = _a.apply(void 0, [_c.sent()]);
                    _b = base64FromArrayBuffer;
                    return [4 /*yield*/, crypto.subtle.exportKey('pkcs8', keypair.privateKey)];
                case 3:
                    privateKeyString = _b.apply(void 0, [_c.sent()]);
                    return [2 /*return*/, { publicKey: publicKeyString, privateKey: privateKeyString }];
            }
        });
    });
}
function importRsa4096KeyAsync(format, usage, key) {
    return crypto.subtle.importKey(format, key, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, [usage]);
}
function importRsa4096PublicKeyAsync(key) {
    return importRsa4096KeyAsync('spki', 'encrypt', key);
}
function importBase64EncodedRsa4096PublicKeyAsync(keyBase64) {
    var key = uint8ArrayFromBase64(keyBase64);
    return importRsa4096PublicKeyAsync(key);
}
function importRsa4096PrivateKeyAsync(key) {
    return importRsa4096KeyAsync('pkcs8', 'decrypt', key);
}
/*export*/ function encryptUsingPublicKeyAsync(secret, keyBase64) {
    return __awaiter(this, void 0, void 0, function () {
        var publicKey, encryptedSecret;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    if (secret.length > 256 / 8)
                        throw "RSA encryption is limited in the size of payload";
                    return [4 /*yield*/, importBase64EncodedRsa4096PublicKeyAsync(keyBase64)];
                case 1:
                    publicKey = _a.sent();
                    return [4 /*yield*/, crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, secret)];
                case 2:
                    encryptedSecret = _a.sent();
                    return [2 /*return*/, encryptedSecret];
            }
        });
    });
}
/*export*/ function decryptUsingPrivateKeyAsync(encryptedSecret, key) {
    return __awaiter(this, void 0, void 0, function () {
        var privateKey, secret;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, importRsa4096PrivateKeyAsync(key)];
                case 1:
                    privateKey = _a.sent();
                    return [4 /*yield*/, crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, encryptedSecret)];
                case 2:
                    secret = _a.sent();
                    return [2 /*return*/, secret];
            }
        });
    });
}
function uint8ArrayFromHex(s) {
    var matcher = s.match(/[0-9a-f]{2}/gi);
    if (matcher) {
        return new Uint8Array(matcher.map(function (hexDigit) { return parseInt(hexDigit, 16); }));
    }
    return new Uint8Array(0);
}
function hexFromArrayBuffer(a) {
    return hexFromUint8Array(new Uint8Array(a));
}
function hexFromUint8Array(a) {
    return a.reduce(function (previous, current) {
        var hex = current.toString(16);
        return previous + ((hex.length == 1) ? '0' + hex : hex);
    }, "");
}
function base64FromArrayBuffer(a) {
    return base64FromUint8Array(new Uint8Array(a));
}
function base64FromUint8Array(a) {
    return btoa(String.fromCharCode.apply(String, __spread(a)));
}
function uint8ArrayFromBase64(s) {
    var b = atob(s);
    var buffer = new Uint8Array(b.length);
    Array.prototype.forEach.call(buffer, function (_, i, a) { return a[i] = b.charCodeAt(i); });
    return buffer;
}
function symmetricKeyTestAsync() {
    return __awaiter(this, void 0, void 0, function () {
        var key, cipherKey, macKey, secrets, utf8Decoder, utf8Encoder, i, encryptedComponents, encryptedPayload, encryptedPayloadbase64, rawExpected, expectedMessage, actualMessage, rawPlaintext, plaintext, message, rawRoundtrip, roundtrip, message_1;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    key = uint8ArrayFromHex('d704a909464eca331f0692e2e173119e2c4144899a047ce2b6b19e3d309619cd');
                    return [4 /*yield*/, cipherKeyFromContentEncryptionKeyAsync(key, algorithm)];
                case 1:
                    cipherKey = _a.sent();
                    if (base64FromArrayBuffer(cipherKey) !== 'hWf9EsSbSLvhzJ4kdxcNLF4Pq8XUYqajWLtGqhUL2SQ=') {
                        console.log('Expected: hWf9EsSbSLvhzJ4kdxcNLF4Pq8XUYqajWLtGqhUL2SQ=');
                        console.log('Actual:   ' + base64FromArrayBuffer(cipherKey));
                        throw 'cipherKey was not correctly generated';
                    }
                    return [4 /*yield*/, macKeyFromContentEncryptionKeyAsync(key, algorithm)];
                case 2:
                    macKey = _a.sent();
                    if (base64FromArrayBuffer(macKey) !== '6qmPn/wi9cDf3XQL66lNEPonYxAx7A95gavk9oODOWQ=') {
                        console.log('Expected: 6qmPn/wi9cDf3XQL66lNEPonYxAx7A95gavk9oODOWQ=');
                        console.log('Actual:   ' + base64FromArrayBuffer(macKey));
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
                        { plaintext: 'Il faut qu’il n’exige pas le secret, et qu’il puisse sans inconvénient tomber entre les mains de l’ennemi.',
                            encrypted: 'AcL76MT/JcYwnGFrIcuI+QYEEuqIfzfNENAt/5KBmX4VV1N+qo/+Hfkxvsdbc28JLFTVK5q0QAWllS6PqOjxZWm6ZiRSpBDwkS1RoRI2JQ6B0VdrZuQgGadHEbAzm1+wmhdoAPdKjriYmNBp9fZIYQTwfWZ9+S2dlahpH4DLSyajvo5hHXKUiWxlTbh+VlCzi8Ozx79oAxeq6uIVqRWJHec5CJh1Owpp9w==' },
                        { plaintext: 'Afterall, hello. 后来，你好? 後來，妳好嗎？',
                            encrypted: 'AVc2fbe8c4ff25c6309c614rfGsXal/Vi08VLO0jkIg/z7Ul4pK19kcp0DVJQd0N+kuySQNtjW+BYo/F0+oQWwo1pJ6G7PiKPAvrEhJHsDWuLUc4MpvcaxqJdFWJzZy5xJWue3+n6OAd' }
                    ];
                    utf8Decoder = new TextDecoder();
                    utf8Encoder = new TextEncoder();
                    i = 0;
                    _a.label = 3;
                case 3:
                    if (!(i != secrets.length)) return [3 /*break*/, 8];
                    encryptedComponents = splitEncryptedMessage(uint8ArrayFromBase64(secrets[i].encrypted));
                    return [4 /*yield*/, encryptSymmetric256Async(utf8Encoder.encode(secrets[i].plaintext), key, encryptedComponents.initializationVector)];
                case 4:
                    encryptedPayload = _a.sent();
                    encryptedPayloadbase64 = base64FromUint8Array(encryptedPayload);
                    if (encryptedPayloadbase64 !== secrets[i].encrypted) {
                        rawExpected = uint8ArrayFromBase64(secrets[i].encrypted);
                        expectedMessage = splitEncryptedMessage(rawExpected);
                        actualMessage = splitEncryptedMessage(encryptedPayload);
                        if (expectedMessage.algorithmCode !== actualMessage.algorithmCode) {
                            console.log('expected algorithmCode (1 byte): ' + expectedMessage.algorithmCode.toString());
                            console.log('actual algorithmCode (1 byte): ' + actualMessage.algorithmCode.toString());
                        }
                        if (hexFromUint8Array(expectedMessage.initializationVector) !== hexFromUint8Array(actualMessage.initializationVector)) {
                            console.log('expected initializationVector (' + expectedMessage.initializationVector.length + " bytes): " + hexFromUint8Array(expectedMessage.initializationVector));
                            console.log('actual initializationVector (' + actualMessage.initializationVector.length + " bytes): " + hexFromUint8Array(actualMessage.initializationVector));
                        }
                        if (hexFromUint8Array(expectedMessage.encryptedSecret) !== hexFromUint8Array(actualMessage.encryptedSecret)) {
                            console.log('expected encryptedSecret (' + expectedMessage.encryptedSecret.length + " bytes): " + hexFromUint8Array(expectedMessage.encryptedSecret));
                            console.log('actual encryptedSecret (' + actualMessage.encryptedSecret.length + " bytes): " + hexFromUint8Array(actualMessage.encryptedSecret));
                        }
                        if (hexFromUint8Array(expectedMessage.tag) !== hexFromUint8Array(actualMessage.tag)) {
                            console.log('expected tag (' + expectedMessage.tag.length + " bytes): " + hexFromUint8Array(expectedMessage.tag));
                            console.log('actual tag (' + actualMessage.tag.length + " bytes): " + hexFromUint8Array(actualMessage.tag));
                        }
                        console.log('expected: ' + hexFromUint8Array(rawExpected) + " " + secrets[i].encrypted);
                        console.log('actual:   ' + hexFromUint8Array(encryptedPayload) + " " + base64FromUint8Array(encryptedPayload));
                        throw 'plaintext <' + secrets[i].plaintext + '> was not correctly encrypted';
                    }
                    return [4 /*yield*/, decryptSymmetric256Async(uint8ArrayFromBase64(secrets[i].encrypted), key)];
                case 5:
                    rawPlaintext = _a.sent();
                    plaintext = utf8Decoder.decode(rawPlaintext);
                    if (plaintext !== secrets[i].plaintext) {
                        message = splitEncryptedMessage(uint8ArrayFromBase64(secrets[i].encrypted));
                        console.log('algorithmCode (1 byte): ' + message.algorithmCode.toString());
                        console.log('initializationVector (' + message.initializationVector.length + " bytes): " + message.initializationVector);
                        console.log('encryptedSecret (' + message.encryptedSecret.length + " bytes): " + message.encryptedSecret);
                        console.log('tag (' + message.tag.length + " bytes): " + message.tag);
                        console.log('expected: ' + secrets[i].plaintext);
                        console.log('actual: ' + plaintext);
                        throw 'plaintext <' + secrets[i].plaintext + '> was not correctly decrypted';
                    }
                    return [4 /*yield*/, decryptSymmetric256Async(encryptedPayload, key)];
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
                        throw 'plaintext <' + plaintext + '> was not correctly round-tripped';
                    }
                    _a.label = 7;
                case 7:
                    ++i;
                    return [3 /*break*/, 3];
                case 8: return [2 /*return*/];
            }
        });
    });
}
function asymmetricKeyTestAsync() {
    return __awaiter(this, void 0, void 0, function () {
        var expectedVaultKey, hexVaultKey, vaultKeyEncrypted4096, pemEncodedPublicKey4096, pemEncodedPrivateKey4096, clientKeyPassphrase, passwordEncryptedPrivateKey4096, passwordEncryptedParts, encryptionKeyForPrivateKey4096, decryptedPrivateKey4096, base64DecodedPrivateKey4096, decryptedVaultKey4096, hexDecryptedVaultKey4096, encryptedPayload4096, decryptedRoundTrip4096, hexDecryptedPayload4096, iosExpected, utf8Encoder, iosHex, iosEncrypted4096, iosPemEncodedPublicKey4096, iosPrivateKey4096, iosDecryptedVaultKey4096, iosHexDecryptedVaultKey4096, iosEncryptedPayload4096, iosDecryptedRoundTrip4096, iosHexDecryptedPayload4096;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    expectedVaultKey = uint8ArrayFromBase64('1MPHlvM4HXDE4e1eBUOPhD0d+1UtZb//KcN9kyYDkR4=');
                    hexVaultKey = hexFromUint8Array(expectedVaultKey);
                    vaultKeyEncrypted4096 = uint8ArrayFromBase64('m0REJ6JE0+IsTmFQqFYKSSezTGvBbnKGdxsC9ok5xrvbKRbrIDFyKzbjHiB0Vag2D3mjUD+/hTBHIpc+Ab1YUuW7OTsYAMjjgEpdgfvjH2Uy5Ze1mjwK5i3VsgdCnTY8RBoKyCtREOlwIYMPkFl3TY0O7mynEOGYQZBtd31NuvFQWtkWGmDiHCfCp1+M9NexKsKR4w0lF++Q178DJfwzw9Pgw7mz8KpCYdykJYH7mM+Pxl7VuxS0hMt3oZs7UzURYTEdaKfwrrJcstsljf+0N5VkS5acCHhbNC647JzLrVAS+dI4qdcQvfG3hEzjgayPe9bc3OUx01+g6mKn1zY9auvcPa+5sandfUb/rsWKoilUZeOnQOCWtj5vX5Johh7blpWVtNYc/woeBXZixOaxLbaLq53TZopmVjjMWuCiV6FvAwLKN8RSaxL/eK4D0wkNWv0JsoLTqzm2BItLXQ9GtgXpx3LAv33arCfwoTA7l74Rvst0Kn2L7bjLA5r7ffWRm73tjPKfjT3DSbEaUoVRQDKmZbGC02+VwU6dBQcg23VlYQfd+yHC6Inpd5FQW039cnR0xUnvYQ4+BqCXKPEoV/P4fKAJMMm1fHNyw4yf9Ri/OIOeHyfehvbSvK4hrh7ZXyzB5IBovYXN68pwBx/BJOigm2QK9YjsD34qcwWacRw=');
                    pemEncodedPublicKey4096 = 'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA22v4cluKApRpV5jYxc6Z2K2fwAzLrSHrfApHaGwrHmBlFsPMIzlypskRc+4wzu75+wMcGUfEOZuK9+CCF8RS6sbfKLdv/R12aoRY9HcFSD19TRtx85wzrMFVxTGahD7uaXTyacRwe6kFT1busfG4mIbjBGqGCF0II9TkOgkd9LXPpg1id3co2GtL4UPl+BIPrTuQomgu1E2DRzdckxc7DBVVBrT20HOrw6elESHRxZ0QE5TefvZLMX7w0tJIt02pGoR1NkAYMJHMofDRwjkk7RxREQE7cF1vrGvxY/jy5uhPgypuJNx037Ryoejb6/rFB/5xRZ15hp8o9Ou7JySwl+nBXrVvcz1EPQ5nnIoZ1RX7mHfhR9s1MSCSdSnf74Q9OpHU/dzTx03YUKvgV8Se1gyi/NGWfwJOAilOizZMndn2lM/SwLglIeSt03ZCmkPKguiV0PwIQGOKr2x1yBKeEDBIoYfKGH86Gp7Dqg3ICOKktKcy7lt/KsHeDb2bmFes5GJD9pAey19AFQx2E8t2Yr/OOzYgktz0MZ0TPt4qOPiFIxo0iDS3qSoOdZ1ocjpL+5sCb13uXnlwuGoSvGQZ5aVOdCiz9x1JzjZ7EufhNlbwRIKUFmubVhfA2VAszJdLCYpDCJ/Tr1YnJtVVGgJEAJ1YY4yo1HGmdMgNWvubHQ0CAwEAAQ==';
                    pemEncodedPrivateKey4096 = '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';
                    clientKeyPassphrase = 'OQEGZP-F5BALU-2P3N6X-OQKXRI';
                    passwordEncryptedPrivateKey4096 = uint8ArrayFromBase64('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');
                    passwordEncryptedParts = splitPasswordEncryptedMessage(passwordEncryptedPrivateKey4096);
                    if (passwordEncryptedParts.algorithmCode !== 0x1) {
                        console.log('bad algorithm code');
                    }
                    return [4 /*yield*/, symmetric256KeyFromAsciiPassphraseAsync(clientKeyPassphrase, passwordEncryptedParts.iterations, passwordEncryptedParts.salt)];
                case 1:
                    encryptionKeyForPrivateKey4096 = _a.sent();
                    return [4 /*yield*/, decryptSymmetric256Async(passwordEncryptedParts.encryptedMessage, new Uint8Array(encryptionKeyForPrivateKey4096))];
                case 2:
                    decryptedPrivateKey4096 = _a.sent();
                    base64DecodedPrivateKey4096 = base64FromArrayBuffer(decryptedPrivateKey4096);
                    if (pemEncodedPrivateKey4096 !== base64DecodedPrivateKey4096) {
                        console.log('decrypting private key 4096 failed');
                        console.log('expected: ' + pemEncodedPrivateKey4096);
                        console.log('actual:   ' + base64DecodedPrivateKey4096);
                    }
                    return [4 /*yield*/, decryptUsingPrivateKeyAsync(vaultKeyEncrypted4096, decryptedPrivateKey4096)];
                case 3:
                    decryptedVaultKey4096 = _a.sent();
                    hexDecryptedVaultKey4096 = hexFromArrayBuffer(decryptedVaultKey4096);
                    if (hexVaultKey !== hexDecryptedVaultKey4096) {
                        console.log('decrypting using private key 4096 failed');
                        console.log('expected: ' + hexVaultKey);
                        console.log('actual:   ' + hexDecryptedVaultKey4096);
                    }
                    return [4 /*yield*/, encryptUsingPublicKeyAsync(expectedVaultKey, pemEncodedPublicKey4096)];
                case 4:
                    encryptedPayload4096 = _a.sent();
                    return [4 /*yield*/, decryptUsingPrivateKeyAsync(encryptedPayload4096, decryptedPrivateKey4096)];
                case 5:
                    decryptedRoundTrip4096 = _a.sent();
                    hexDecryptedPayload4096 = hexFromArrayBuffer(decryptedRoundTrip4096);
                    if (hexVaultKey !== hexDecryptedPayload4096) {
                        console.log('round trip encrypt using public key, decrypt using private key 4096 failed');
                        console.log('expected: ' + hexVaultKey);
                        console.log('actual:   ' + hexDecryptedPayload4096);
                    }
                    iosExpected = uint8ArrayFromBase64('SGVsbG8sIFdvcmxkIQ==');
                    utf8Encoder = new TextEncoder();
                    iosHex = hexFromUint8Array(utf8Encoder.encode('Hello, World!'));
                    iosEncrypted4096 = uint8ArrayFromBase64('mrBIDqVaNbyeQt+vBHii/NGGaNnoYjKMXQogiJO42GkVeQEYmgJVGsa/TVMepXMCJJrsZ4o2K8UI5H28haczm1bsytZw/X/kF+A32P5IMMDVC2WpW9O5JWmjo0kNXXB9nl3CfXLfBDh/qDATJVSPFqL80G1LcyAYqLYceiuEHn7+uEmcmwf/3oDOWkg2HhxcZfRX8Yys1m2qVgY00d2i2x8Wg5oIVEGx50B58ZpGoDEIFbV06DUeds2sKKs8jA0hygxis/URpxMNQBSmFc0cejht8WS/v7UWbsbAm+iHOlCr5GxDPXnLhp8b0a4lYGG4HSlEIdAQ3YN4iFC1F9O032QCt3jMY4n/ejEVtqhsan58/v2EZpnsVD/0/JcGu00zIvZk3RPvxjOvQ0ux6b2h1BKeMZ/xnKn1xQGSCJvThHrxsVofeQshgzuItuGvS1bHuBZmoRKnlOa1ZQO0F4NEECV8bOz8dtjI0Apd9tZXXk4qU+KM/kgaHCo3IFVJWcTJeDa179G5BcOgFxiGH1vEsc/AZAFHPbmZrZonoNFdr+pkH2kPsgWWTKtY58zW9SNYdasq1pTjWdjUevJ7LChgbyKgVh2XWEM87W6+GDle3whN2QGaC2igMQ2tt8dxL75GfkzBPIF72SE75m3ptMAT1nNvL8vJjtiz+nAVpEYpiXs=');
                    iosPemEncodedPublicKey4096 = 'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAy9jnGx8ULYXbUpWgTYWcZs++JaCSI2s81cbihKZ08JJI2RbVZFxScAfrz+3Q8FBrnGdyHeJZPmSJoFd7bBLzVHKK2zjCBcZzqxHTTdNTS4PXMDaZAizuu/LpHjhpuEgfOyk0mMV8O4KIk5Mdjct6GB85TB8GV9F5yGTrvu6Jebom6QqjwlwHSWGbUzBUgGGa/0Ayt+EzH8pRSBvF2i0DN45fl81VBcQ5grDwRT1+ijqdaM6VW5e63nkR67iGgS5FM2+JYbKje+KmGWYwmjvYAR1c5tC/wWriTttpO+PCMDlmdjv0hF8imYPVoTFuPWORpwrxrCLwwx+DMxKiSHHR4mWz3ODSuJAYRvxDsdZ2+z1cEfhlmtN3d3Cg4UHt9Wlf9g31mDNmmBtYeeHAAgFAG0ddptr0NQQYJfDMouIW8nINeeDdshh1VvtYwCbX5JzXReWZlPVjnmKnmNyoFbpiR1sCp1xWg7H7FLREyHOyHkRsgcSZ0im3h3EWZavXrRXYzvxhQoIpAPlMAh407enDM1DQIvfKEH1K+sgpPKxVh3Q6CnpuYue5TslLEJDQB70+cLc2lJ3d5WJeEnPfgb4EpZ8EgfVGitxahOU/p8yDVIJ4pPWny5VZw06QjVtNJDOSePlDfqGV7GfwGo5EIFUopYeFLHfgyjnZMHWQZsEKUp0CAwEAAQ==';
                    iosPrivateKey4096 = uint8ArrayFromBase64('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');
                    return [4 /*yield*/, decryptUsingPrivateKeyAsync(iosEncrypted4096, iosPrivateKey4096)];
                case 6:
                    iosDecryptedVaultKey4096 = _a.sent();
                    iosHexDecryptedVaultKey4096 = hexFromArrayBuffer(iosDecryptedVaultKey4096);
                    if (iosHex !== iosHexDecryptedVaultKey4096) {
                        console.log('decrypting using ios private key 4096 failed');
                        console.log('expected: ' + iosHex);
                        console.log('actual:   ' + iosHexDecryptedVaultKey4096);
                    }
                    return [4 /*yield*/, encryptUsingPublicKeyAsync(iosExpected, iosPemEncodedPublicKey4096)];
                case 7:
                    iosEncryptedPayload4096 = _a.sent();
                    return [4 /*yield*/, decryptUsingPrivateKeyAsync(iosEncryptedPayload4096, iosPrivateKey4096)];
                case 8:
                    iosDecryptedRoundTrip4096 = _a.sent();
                    iosHexDecryptedPayload4096 = hexFromArrayBuffer(iosDecryptedRoundTrip4096);
                    if (iosHex !== iosHexDecryptedPayload4096) {
                        console.log('round trip encrypt using ios public key, decrypt using private key 4096 failed');
                        console.log('expected: ' + iosHex);
                        console.log('actual:   ' + iosHexDecryptedPayload4096);
                    }
                    return [2 /*return*/];
            }
        });
    });
}
function symmetricKeyGenerationTest() {
    var symmetric256Key = generateSymmetric256Key();
    console.log('symmetric 256 bit key: ' + hexFromUint8Array(symmetric256Key));
}
function bigEndianUint8ArrayFromUint32(n) {
    if (n < 0 || 0xffffffff < n) {
        throw 'number does not fit in uint32';
    }
    var result = new Uint8Array(4);
    result[3] = n & 0xff;
    result[2] = (n >> 8) & 0xff;
    result[1] = (n >> 16) & 0xff;
    result[0] = (n >> 24) & 0xff;
    return result;
}
function numberFromUint8ArrayBigEndian(a) {
    return a[0] << 24 | a[1] << 16 | a[2] << 8 | a[3];
}
function asymmetricKeyGenerationTestAsync() {
    return __awaiter(this, void 0, void 0, function () {
        var keys, publicKey, privateKey, clientKey, iterations, salt, iterationsBytesBigEndian, passwordEncryptedPrivateKey, passwordEncryptedPrivateKeyParts, decryptionKey, decryptedPrivateKey;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, generateAsymmetric4096KeyPairAsync()];
                case 1:
                    keys = _a.sent();
                    console.log('public key');
                    console.log(keys.publicKey);
                    return [4 /*yield*/, importRsa4096PublicKeyAsync(uint8ArrayFromBase64(keys.publicKey))];
                case 2:
                    publicKey = _a.sent();
                    console.log(publicKey.algorithm);
                    console.log(publicKey.type);
                    console.log(publicKey.usages);
                    console.log('private key');
                    console.log(keys.privateKey);
                    return [4 /*yield*/, importRsa4096PrivateKeyAsync(uint8ArrayFromBase64(keys.privateKey))];
                case 3:
                    privateKey = _a.sent();
                    console.log(privateKey.algorithm);
                    console.log(privateKey.type);
                    console.log(privateKey.usages);
                    clientKey = generateClientKey();
                    iterations = 1000000;
                    salt = generateSymmetric256Key();
                    console.log("clientKey: " + clientKey);
                    iterationsBytesBigEndian = bigEndianUint8ArrayFromUint32(iterations);
                    console.log("iterations: " + iterations + " " + hexFromUint8Array(iterationsBytesBigEndian));
                    console.log("salt: " + base64FromUint8Array(salt) + " " + hexFromUint8Array(salt));
                    return [4 /*yield*/, passwordEncryptAsync(clientKey, uint8ArrayFromBase64(keys.privateKey), iterations, salt)];
                case 4:
                    passwordEncryptedPrivateKey = _a.sent();
                    console.log('encrypted with clientKey as passphrase:');
                    console.log(base64FromUint8Array(passwordEncryptedPrivateKey));
                    console.log(hexFromUint8Array(passwordEncryptedPrivateKey));
                    passwordEncryptedPrivateKeyParts = splitPasswordEncryptedMessage(passwordEncryptedPrivateKey);
                    if (!equalArray(salt, passwordEncryptedPrivateKeyParts.salt)) {
                        throw 'bad salt';
                    }
                    if (iterations !== passwordEncryptedPrivateKeyParts.iterations) {
                        throw 'bad iterations';
                    }
                    if (passwordEncryptedPrivateKeyParts.algorithmCode !== 1) {
                        throw 'bad algorithm code';
                    }
                    return [4 /*yield*/, symmetric256KeyFromAsciiPassphraseAsync(clientKey, iterations, salt)];
                case 5:
                    decryptionKey = _a.sent();
                    return [4 /*yield*/, decryptSymmetric256Async(passwordEncryptedPrivateKeyParts.encryptedMessage, new Uint8Array(decryptionKey))];
                case 6:
                    decryptedPrivateKey = _a.sent();
                    if (keys.privateKey !== base64FromArrayBuffer(decryptedPrivateKey)) {
                        throw 'bad roundtrip';
                    }
                    return [2 /*return*/];
            }
        });
    });
}
function hexFromArrayBufferTest() {
    var bytes = new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
    var hexFromArray = hexFromArrayBuffer(bytes.buffer);
    var expectedHex = '0123456789abcdef';
    if (hexFromArray !== expectedHex) {
        console.log('could not convert from uint8Array to hex');
        console.log('actual:   ' + hexFromArray);
        console.log('expected: ' + expectedHex);
    }
}
function hexFromUint8ArrayTest() {
    var bytes = new Uint8Array([0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xa0]);
    var hexFromArray = hexFromUint8Array(bytes);
    var expectedHex = '000123456789abcdefa0';
    if (hexFromArray !== expectedHex) {
        console.log('could not convert from uint8Array to hex');
        console.log('actual:   ' + hexFromArray);
        console.log('expected: ' + expectedHex);
    }
}
function roundTripHexAndUint8ArrayTest() {
    var expectedHex = 'd704a909464eca331f0692e2e173119e2c4144899a047ce2b6b19e3d309619cd';
    var arrayFromHex = uint8ArrayFromHex(expectedHex);
    var hexFromArray = hexFromUint8Array(arrayFromHex);
    if (hexFromArray !== expectedHex) {
        console.log('could not round-trip hex to uint8Array');
        console.log('actual:   ' + hexFromArray);
        console.log('expected: ' + expectedHex);
    }
}
function roundTripBase64AndUint8ArrayTest() {
    var expectedBase64 = '1wSpCUZOyjMfBpLi4XMRnixBRImaBHzitrGePTCWGc0=';
    var arrayFromBase64 = uint8ArrayFromBase64(expectedBase64);
    var base64FromArray = base64FromUint8Array(arrayFromBase64);
    if (base64FromArray !== expectedBase64) {
        console.log('could not round-trip base64 to uint8Array');
        console.log('actual:   ' + base64FromArray);
        console.log('expected: ' + expectedBase64);
    }
}
function roundTripHexThroughBase64Test() {
    {
        var expectedHex = 'd704a909464eca331f0692e2e173119e2c4144899a047ce2b6b19e3d309619cd';
        var arrayFromHex = uint8ArrayFromHex(expectedHex);
        var base64FromArray = base64FromUint8Array(arrayFromHex);
        var arrayFromBase64 = uint8ArrayFromBase64(base64FromArray);
        var hexFromArray = hexFromUint8Array(arrayFromBase64);
        if (hexFromArray !== expectedHex) {
            console.log('could not round-trip hex through base64');
            console.log('actual:   ' + hexFromArray);
            console.log('expected: ' + expectedHex);
        }
    }
}
function generateClientKey() {
    var alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    var result = '';
    var buffer = new Uint8Array(24); // 120 bits of entropy (5 bits per character)
    crypto.getRandomValues(buffer);
    for (var i = 0; i !== buffer.length; ++i) {
        var base32 = buffer[i] & 0x1f;
        result += alphabet[base32];
        if (i % 6 === 5 && i !== buffer.length - 1) {
            result += '-';
        }
    }
    return result;
}
function symmetricKey256FromClientKeyTestAsync() {
    return __awaiter(this, void 0, void 0, function () {
        var clientKey, iterationsList, salt;
        var _this = this;
        return __generator(this, function (_a) {
            clientKey = generateClientKey();
            console.log("clientKey: " + clientKey);
            iterationsList = [
                10000,
                100000,
                1000000
            ];
            salt = generateSymmetric256Key();
            iterationsList.forEach(function (iterations) { return __awaiter(_this, void 0, void 0, function () {
                var start, key1, end, key2;
                return __generator(this, function (_a) {
                    switch (_a.label) {
                        case 0:
                            start = performance.now();
                            return [4 /*yield*/, symmetric256KeyFromAsciiPassphraseAsync(clientKey, iterations, salt)];
                        case 1:
                            key1 = _a.sent();
                            end = performance.now();
                            console.log("iterations: " + iterations);
                            console.log("call to symmetric256KeyFromAsciiPassphraseAsync took " + (end - start) + " milliseconds");
                            console.log("symmetricKey: " + base64FromArrayBuffer(key1));
                            console.log("salt: " + base64FromUint8Array(salt));
                            return [4 /*yield*/, symmetric256KeyFromAsciiPassphraseAsync(clientKey, iterations, salt)];
                        case 2:
                            key2 = _a.sent();
                            if (!equalArray(new Uint8Array(key1), new Uint8Array(key2))) {
                                throw 'symmetric256KeyFromAsciiPassphraseAsync is not deterministic';
                            }
                            return [2 /*return*/];
                    }
                });
            }); });
            return [2 /*return*/];
        });
    });
}
function tests() {
    return __awaiter(this, void 0, void 0, function () {
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    hexFromArrayBufferTest();
                    console.log('finished hexFromArrayBufferTest');
                    hexFromUint8ArrayTest();
                    console.log('finished hexFromUint8ArrayTest');
                    roundTripHexAndUint8ArrayTest();
                    console.log('finished roundTripHexAndUint8ArrayTest');
                    roundTripBase64AndUint8ArrayTest();
                    console.log('finished roundTripBase64AndUint8ArrayTest');
                    roundTripHexThroughBase64Test();
                    console.log('finished roundTripHexThroughBase64Test');
                    return [4 /*yield*/, symmetricKeyTestAsync()];
                case 1:
                    _a.sent();
                    console.log('finished symmetricKeyTestAsync');
                    return [4 /*yield*/, asymmetricKeyTestAsync()];
                case 2:
                    _a.sent();
                    console.log('finished asymmetricKeyTestAsync');
                    symmetricKeyGenerationTest();
                    console.log('finished symmetricKeyGenerationTest');
                    return [4 /*yield*/, asymmetricKeyGenerationTestAsync()];
                case 3:
                    _a.sent();
                    console.log('finished asymmetricKeyGenerationTestAsync');
                    return [4 /*yield*/, symmetricKey256FromClientKeyTestAsync()];
                case 4:
                    _a.sent();
                    return [2 /*return*/];
            }
        });
    });
}
tests();
