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
var aes256BlockSize = 16;
var algorithm = 'AEAD_AES_256_CBC_HMAC_SHA384';
var algorithmCode = 1;
var algorithmCodeByteLength = 1;
var ivLength = aes256BlockSize;
var tagLength = 24; // from half of sha384 (384/2/8)
var FIXED_ARRAY = [215, 4, 169, 9, 70, 78, 202, 51, 31, 6, 146, 226, 225, 115, 17, 158, 44, 65, 68, 137, 154, 4, 124, 226, 182, 177, 158, 61, 48, 150, 25, 205];
var FIXED_ARRAY16 = [78, 27, 238, 163, 112, 200, 84, 93, 183, 58, 101, 218, 37, 131, 14, 212];
function hmacSha256Async(cek, type, algorithm) {
    return __awaiter(this, void 0, void 0, function () {
        var utf8Encoder, typeBytes, algorithmBytes, cekLengthBytes, buffer, key, crytoPromise;
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
                    crytoPromise = crypto.subtle.sign('HMAC', key, buffer);
                    return [4 /*yield*/, crytoPromise];
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
                            data: data.slice(0, -8),
                            tag: new Uint8Array(tag.slice(0, tagLength))
                        }];
            }
        });
    });
}
function encryptSymmetric256Async(secret, secretKey) {
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
                    initializationVector = new Uint8Array(FIXED_ARRAY16);
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
                    if (encryptedMessage[0] !== algorithmCode) {
                        throw "bad message type. this algorithm can only decode AEAD_AES_256_CBC_HMAC_SHA384";
                    }
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
// function Base64FromArrayBuffer(a: ArrayBuffer): string {
//     return Base64FromUint8Array(new Uint8Array(a));
// }
// function Base64FromUint8Array(a: Uint8Array): string {
//     return btoa(String.fromCharCode(...a));
// }
function Uint8ArrayFromBase64(s) {
    var b = atob(s);
    var buffer = new Uint8Array(b.length);
    Array.prototype.forEach.call(buffer, function (_, i, a) { return a[i] = b.charCodeAt(i); });
    return buffer;
}
function symmetricKeyTestAsync() {
    return __awaiter(this, void 0, void 0, function () {
        var key, cipherKey, macKey, secrets, utf8Decoder, utf8Encoder, i, buf, encryptedPayload, decryptedPayload, decryptedSecret;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    key = generateSymmetric256Key(FIXED_ARRAY);
                    console.log('Key (' + key.length + ' bytes): ' + buf2hex(key));
                    return [4 /*yield*/, cipherKeyFromContentEncryptionKeyAsync(key, algorithm)];
                case 1:
                    cipherKey = _a.sent();
                    console.log('ENC_KEY (' + cipherKey.byteLength + ' bytes): ' + buf2hex(cipherKey));
                    return [4 /*yield*/, macKeyFromContentEncryptionKeyAsync(key, algorithm)];
                case 2:
                    macKey = _a.sent();
                    console.log('MAC_KEY (' + macKey.byteLength + ' bytes): ' + buf2hex(macKey));
                    secrets = [
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
                    utf8Decoder = new TextDecoder();
                    utf8Encoder = new TextEncoder();
                    i = 0;
                    _a.label = 3;
                case 3:
                    if (!(i != secrets.length)) return [3 /*break*/, 7];
                    buf = utf8Encoder.encode(secrets[i]);
                    return [4 /*yield*/, encryptSymmetric256Async(buf, key)];
                case 4:
                    encryptedPayload = _a.sent();
                    return [4 /*yield*/, decryptSymmetric256Async(encryptedPayload, key)];
                case 5:
                    decryptedPayload = _a.sent();
                    decryptedSecret = utf8Decoder.decode(decryptedPayload);
                    console.log("-------------------");
                    console.log("secret:", secrets[i]);
                    console.log("encryptedPayload:", buf2hex(encryptedPayload));
                    console.log("decryptedPayload:", decryptedSecret);
                    console.log("success:", secrets[i] == decryptedSecret);
                    _a.label = 6;
                case 6:
                    ++i;
                    return [3 /*break*/, 3];
                case 7: return [2 /*return*/];
            }
        });
    });
}
symmetricKeyTestAsync();
