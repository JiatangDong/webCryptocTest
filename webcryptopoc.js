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
var utf8Decoder = new TextDecoder();
var utf8Encoder = new TextEncoder();
var FIXED_ARRAY32 = [215, 4, 169, 9, 70, 78, 202, 51, 31, 6, 146, 226, 225, 115, 17, 158, 44, 65, 68, 137, 154, 4, 124, 226, 182, 177, 158, 61, 48, 150, 25, 205];
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
function bytesToArrayBuffer(bytes) {
    var bytesAsArrayBuffer = new ArrayBuffer(bytes.length);
    var bytesUint8 = new Uint8Array(bytesAsArrayBuffer);
    bytesUint8.set(bytes);
    return bytesAsArrayBuffer;
}
function str2ab(str) {
    var buf = new ArrayBuffer(str.length);
    var bufView = new Uint8Array(buf);
    for (var i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return buf;
}
function buf2hex(buf) {
    return Array.prototype.map.call(new Uint8Array(buf), function (x) { return (('00' + x.toString(16)).slice(-2)); }).join('');
}
function buf2base64(buf) {
    var binary = '';
    var bytes = new Uint8Array(buf);
    var len = bytes.byteLength;
    for (var i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}
function base64ToBuffer(base64) {
    var binstr = atob(base64);
    var buf = new Uint8Array(binstr.length);
    Array.prototype.forEach.call(binstr, function (ch, i) {
        buf[i] = ch.charCodeAt(0);
    });
    return buf;
}
function generateRandomVector(fixedVector) {
    if (fixedVector === void 0) { fixedVector = null; }
    var buffer = new Uint8Array(ivLength);
    if (fixedVector != null) {
        buffer = new Uint8Array(fixedVector);
    }
    else {
        crypto.getRandomValues(buffer);
    }
    return buffer;
}
function generateSymmetric256Key(fixedKey) {
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
function encryptSymmetric256Async(secret, secretKey, iniVector) {
    if (iniVector === void 0) { iniVector = null; }
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
                    initializationVector = generateRandomVector(iniVector);
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
function decryptSymmetric256Async(encryptedMessage, secretKey) {
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
function Base64FromUint8Array(a) {
    return btoa(String.fromCharCode.apply(String, __spread(a)));
}
function Uint8ArrayFromBase64(s) {
    var b = atob(s);
    var buffer = new Uint8Array(b.length);
    Array.prototype.forEach.call(buffer, function (_, i, a) { return a[i] = b.charCodeAt(i); });
    return buffer;
}
function generateAsymmetric2048KeyPairAsync() {
    return __awaiter(this, void 0, void 0, function () {
        return __generator(this, function (_a) {
            return [2 /*return*/];
        });
    });
}
function asymmetricKeyTestAsync() {
    return __awaiter(this, void 0, void 0, function () {
        var secret, passphraseBuf, passphrase, keyPair, publicKey, privateKey, plainText, encryptedPayload, decryptedPayload;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    secret = generateSymmetric256Key(FIXED_ARRAY32);
                    passphraseBuf = generateSymmetric256Key(FIXED_ARRAY32);
                    passphrase = Base64FromUint8Array(passphraseBuf);
                    return [4 /*yield*/, crypto.subtle.generateKey({
                            name: "RSA-OAEP",
                            modulusLength: 2048,
                            publicExponent: new Uint8Array([1, 0, 1]),
                            hash: "SHA-256"
                        }, true, ["encrypt", "decrypt"])];
                case 1:
                    keyPair = _a.sent();
                    return [4 /*yield*/, crypto.subtle.exportKey("jwk", keyPair.publicKey)];
                case 2:
                    publicKey = _a.sent();
                    return [4 /*yield*/, crypto.subtle.exportKey("jwk", keyPair.privateKey)];
                case 3:
                    privateKey = _a.sent();
                    console.log('public key:');
                    console.log(publicKey);
                    plainText = "UUUUU";
                    return [4 /*yield*/, crypto.subtle.encrypt({ name: "RSA-OAEP" }, keyPair.publicKey, //from generateKey or importKey above
                        utf8Encoder.encode(plainText) //ArrayBuffer of data you want to sign
                        )];
                case 4:
                    encryptedPayload = _a.sent();
                    console.log(buf2hex(encryptedPayload));
                    return [4 /*yield*/, crypto.subtle.decrypt({ name: "RSA-OAEP" }, keyPair.privateKey, encryptedPayload)];
                case 5:
                    decryptedPayload = _a.sent();
                    console.log(utf8Decoder.decode(decryptedPayload));
                    return [2 /*return*/];
            }
        });
    });
}
function symmetricKeyTestAsync() {
    return __awaiter(this, void 0, void 0, function () {
        var key, cipherKey, macKey, secrets, utf8Decoder, utf8Encoder, i, buf, encryptedPayload, decryptedPayload, decryptedSecret;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    key = generateSymmetric256Key();
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
// symmetricKeyTest();
asymmetricKeyTestAsync();
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoid2ViY3J5cHRvcG9jLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsid2ViY3J5cHRvcG9jLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBQUEsSUFBTSxlQUFlLEdBQUcsRUFBRSxDQUFDO0FBQzNCLElBQU0sU0FBUyxHQUFHLDhCQUE4QixDQUFDO0FBQ2pELElBQU0sYUFBYSxHQUFHLENBQUMsQ0FBQztBQUN4QixJQUFNLHVCQUF1QixHQUFHLENBQUMsQ0FBQztBQUNsQyxJQUFNLFFBQVEsR0FBRyxlQUFlLENBQUM7QUFDakMsSUFBTSxTQUFTLEdBQUcsRUFBRSxDQUFDLENBQUMsZ0NBQWdDO0FBRXRELElBQU0sV0FBVyxHQUFHLElBQUksV0FBVyxFQUFFLENBQUM7QUFDdEMsSUFBTSxXQUFXLEdBQUcsSUFBSSxXQUFXLEVBQUUsQ0FBQztBQUV0QyxJQUFNLGFBQWEsR0FBRyxDQUFDLEdBQUcsRUFBRSxDQUFDLEVBQUUsR0FBRyxFQUFFLENBQUMsRUFBRSxFQUFFLEVBQUUsRUFBRSxFQUFFLEdBQUcsRUFBRSxFQUFFLEVBQUUsRUFBRSxFQUFFLENBQUMsRUFBRSxHQUFHLEVBQUUsR0FBRyxFQUFFLEdBQUcsRUFBRSxHQUFHLEVBQUUsRUFBRSxFQUFFLEdBQUcsRUFBRSxFQUFFLEVBQUUsRUFBRSxFQUFFLEVBQUUsRUFBRSxHQUFHLEVBQUUsR0FBRyxFQUFFLENBQUMsRUFBRSxHQUFHLEVBQUUsR0FBRyxFQUFFLEdBQUcsRUFBRSxHQUFHLEVBQUUsR0FBRyxFQUFFLEVBQUUsRUFBRSxFQUFFLEVBQUUsR0FBRyxFQUFFLEVBQUUsRUFBRSxHQUFHLENBQUMsQ0FBQztBQUNwSyxJQUFNLGFBQWEsR0FBRyxDQUFDLEVBQUUsRUFBRSxFQUFFLEVBQUUsR0FBRyxFQUFFLEdBQUcsRUFBRSxHQUFHLEVBQUUsR0FBRyxFQUFFLEVBQUUsRUFBRSxFQUFFLEVB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