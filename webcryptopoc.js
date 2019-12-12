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
var FIXED_ARRAY = [98, 183, 249, 18, 137, 227, 35, 73, 241, 243, 134, 94, 109, 227, 127, 115, 128, 55, 115, 66, 163, 238, 63, 239, 250, 236, 168, 247, 21, 10, 201, 134];
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
                            data: data,
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
        var key, cipherKey, macKey, secrets, utf8Decoder, utf8Encoder, i, buf, encryptedPayload, decryptedPayload;
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
                        // '',
                        '1',
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
                    console.log(buf2hex(encryptedPayload));
                    return [4 /*yield*/, decryptSymmetric256Async(encryptedPayload, key)];
                case 5:
                    decryptedPayload = _a.sent();
                    console.log(decryptedPayload);
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoid2ViY3J5cHRvcG9jLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsid2ViY3J5cHRvcG9jLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUFBLElBQU0sZUFBZSxHQUFHLEVBQUUsQ0FBQztBQUMzQixJQUFNLFNBQVMsR0FBRyw4QkFBOEIsQ0FBQztBQUNqRCxJQUFNLGFBQWEsR0FBRyxDQUFDLENBQUM7QUFDeEIsSUFBTSx1QkFBdUIsR0FBRyxDQUFDLENBQUM7QUFDbEMsSUFBTSxRQUFRLEdBQUcsZUFBZSxDQUFDO0FBQ2pDLElBQU0sU0FBUyxHQUFHLEVBQUUsQ0FBQyxDQUFDLGdDQUFnQztBQUV0RCxJQUFNLFdBQVcsR0FBRyxDQUFDLEVBQUUsRUFBQyxHQUFHLEVBQUMsR0FBRyxFQUFDLEVBQUUsRUFBQyxHQUFHLEVBQUMsR0FBRyxFQUFDLEVBQUUsRUFBQyxFQUFFLEVBQUMsR0FBRyxFQUFDLEdBQUcsRUFBQyxHQUFHLEVBQUMsRUFBRSxFQUFDLEdBQUcsRUFBQyxHQUFHLEVBQUMsR0FBRyxFQUFDLEdBQUcsRUFBQyxHQUFHLEVBQUMsRUFBRSxFQUFDLEdBQUcsRUFBQyxFQUFFLEVBQUMsR0FBRyxFQUFDLEdBQUcsRUFBQyxFQUFFLEVBQUMsR0FBRyxFQUFDLEdBQUcsRUFBQyxHQUFHLEVBQUMsR0FBRyxFQUFDLEdBQUcsRUFBQyxFQUFFLEVBQUMsRUFBRSxFQUFDLEdBQUcsRUFBQyxHQUFHLENBQUMsQ0FBQztBQUM1SSxJQUFNLGFBQWEsR0FBRyxDQUFDLEVBQUUsRUFBRSxFQUFFLEVBQUUsR0FBRyxFQUFFLEdBQUcsRUFBRSxHQUFHLEVBQUUsR0FBRyxFQUFFLEVBQUUsRUFBRSxFQUFFLEVBQUUsR0FBRyxFQUFFLEVBQUUsRUFBRSxHQUFHLEVBQUUsR0FBRyxFQUFFLEVBQUUsRUFBRSxHQUFHLEVBQUUsRUFBRSxFQUFFLEdBQUcsQ0FBQyxDQUFBO0FBRS9GLFNBQWUsZUFB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