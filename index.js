"use strict";

const cbcAlgorithm = 'aes-256-cbc';
const aes256BlockSize = 16;
const algorithm = 'AEAD_AES_256_CBC_HMAC_SHA384';
const algorithmCode = 1;
const algorithmCodeByteLength = 1;
const ivLength = aes256BlockSize;
const tagLength = 24; // from half of sha384 (384/2/8)
const FIXED_ARRAY = [98,183,249,18,137,227,35,73,241,243,134,94,109,227,127,115,128,55,115,66,163,238,63,239,250,236,168,247,21,10,201,134];

function buf2hex(buf) {
    return Array.prototype.map.call(new Uint8Array(buf), x=>(('00'+x.toString(16)).slice(-2))).join('');
}

function generateSymmetric256Key(fixed = false) {
    var array = new Uint8Array(32);
    if (fixed) {
        array = FIXED_ARRAY
    } else {
        window.crypto.getRandomValues(array)
    }
    return array;
}

async function cipherKeyFromContentEncryptionKey(cek, algorithm) {
    var str = 'Microsoft Teams Vault Symmetric Encryption Key'
    const data = new TextEncoder().encode(str);
    const hash = await window.crypto.subtle.digest('SHA-256', data);
    return hash;
}

async function symmetricKeyTest() {
    var key = generateSymmetric256Key(true);
    console.log('Key (' + key.length + ' bytes): ' + buf2hex(key));
    var cipherKey = await cipherKeyFromContentEncryptionKey(key, algorithm);
    console.log('ENC_KEY (' + cipherKey.byteLength + ' bytes): ' + buf2hex(cipherKey));
}

(function() {
    symmetricKeyTest();
})();