// const saltBytes = [79, 225, 136, 232, 158, 39, 68, 116, 152, 131, 219, 227, 70, 62, 222, 113];
// // const saltBytes = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
// const salt = bytesToArrayBuffer(saltBytes);

// const ivBytes = [250, 110, 136, 113, 110, 202, 54, 196, 17, 144, 228, 246, 211, 14, 156, 23];
// // const ivBytes = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
// const iv = bytesToArrayBuffer(ivBytes);

// const pbkAlgo = {
//     name: "PBKDF2",
//     salt: salt, 
//     iterations: 100000,
//     hash: "SHA-256"
// }

// const aesAlgo = { 
//     name: "AES-CBC", 
//     iv: iv, 
//     length: 256
// };

const rsaAlgo = {
    name: "RSA-OAEP",
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-256"
}

$( document ).ready(function() {

    $('#genClientKey').click(genClientKey)
    $('#deriveKey').click(deriveKey)
    $('#genSalt').click(generateSalt)
    $('#genKey').click(generateKey)
    $('#genVector').click(generateVector)

    $('#encrypt').click(runEncrypt)
    $('#decrypt').click(runDecrypt)
    $('#roundTrip').click(runRoundTrip)

    $('#genKeyPair').click(generateRSAKeyPair)
    $('#pubEncrypt').click(runPubEncrypt)
    $('#ppkDecrypt').click(runPpkDecrypt)
    $('#asymRoundTrip').click(asymRoundTrip)

    async function deriveKey(e) {
        const passphrase = $('#payload').val()
        const saltText = $('#salt').val()
        const iter = +$('#iter').val()
        const salt = base64ToBuffer(saltText)

        const start = performance.now();
        key = await symmetric256KeyFromAsciiPassphraseAsync(passphrase, iter, salt)
        const end = performance.now();

        var runResult = `
took ${end-start} ms
key: ${base64FromArrayBuffer(key)}
`
    $('#output').html(runResult)

    }

    async function genClientKey(e) {
        const clientKey = generateClientKey();
        $('#clientKey').val(clientKey);
    }

    async function generateSalt(e) {
        const salt = generateSymmetric256Key();
        $('#salt').val(base64FromUint8Array(salt));
    }

    async function generateKey(e) {
        const key = generateSymmetric256Key();
        $('#key').val(base64FromUint8Array(key))
    }

    async function generateVector(e) {
        const vector = generateRandomVector();
        $('#vector').val(base64FromUint8Array(vector))
    }

    async function generateRSAKeyPair(e) {
        const keyPair = await generateAsymmetric4096KeyPairAsync();

        $('#pub').val(keyPair.publicKey);
        $('#ppk').val(keyPair.privateKey);
    }



    async function encrypt() {
        const secret = $('#payload').val()
        const buf = utf8Encoder.encode(secret);

        var key
        const keyText = $('#key').val();
        if (keyText == "") {
            key = generateSymmetric256Key();
            $('#key').val(base64FromUint8Array(key))
        } else {
            key = base64ToBuffer(keyText)
        }

        var vector
        const vectorText = $('#vector').val();
        if (vectorText == "") {
            vector = generateRandomVector();
            $('#vector').val(base64FromUint8Array(vector))
        } else {
            vector = base64ToBuffer(vectorText)
        }

        const encryptedPayload = await encryptSymmetric256Async(buf, key, vector);
        const message = splitEncryptedMessage(encryptedPayload);

        var runResult = `
key: ${base64FromUint8Array(key)}

initialize vector: ${base64FromUint8Array(vector)}

algorithmCode (1 byte): ${message.algorithmCode.toString()}

initializationVector (${message.initializationVector.length} bytes):  ${base64FromUint8Array(message.initializationVector)}

encryptedSecret (${message.encryptedSecret.length} bytes): 
${base64FromUint8Array(message.encryptedSecret)}

tag (${message.tag.length} bytes): ${base64FromUint8Array(message.tag)}

concatenated payload (${encryptedPayload.length} bytes):
${base64FromUint8Array(encryptedPayload)}
`
        return {secret, key, encryptedPayload, runResult}
    };

    async function runEncrypt(e) {
        $('#output').html('')
        const result = await encrypt();
        $('#output').html(result.runResult)
    }

    async function runDecrypt(e) {
        $('#output').html('')
        const payload = base64ToBuffer($('#payload').val());
        const key = base64ToBuffer($('#key').val())
        const decryptedPayload = await decryptSymmetric256Async(payload, key);
        const decryptedSecret = utf8Decoder.decode(decryptedPayload)

        var runResult = `
Dencrypted Secret: (${decryptedPayload.byteLength} bytes):
${decryptedSecret}
`
        $('#output').html(runResult)
    }

    async function runRoundTrip(e) {
        $('#output').html('')
        const result = await encrypt();
        const decryptedPayload = await decryptSymmetric256Async(result.encryptedPayload, result.key);
        const decryptedSecret = utf8Decoder.decode(decryptedPayload)
        var runResult = result.runResult + `
round trip success: ${result.secret === decryptedSecret}
`
        $('#output').html(runResult)
    }

    async function pubEncrypt() {
        const pubText = $('#pub').val();
        const ppkText = $('#ppk').val();
        const secret = $('#payload').val();
        // const passphrase = $('#passphrase').val();

        const pub = await importRsa4096PublicKeyAsync(base64ToBuffer(pubText))
        
        var encryptedPayload = await crypto.subtle.encrypt(
            {name: 'RSA-OAEP'}, 
            pub, 
            utf8Encoder.encode(secret)
        )

        const encryptedSecret = base64FromArrayBuffer(encryptedPayload)

        var runResult = `
encryptedSecret (${encryptedPayload.byteLength} bytes): 
${encryptedSecret}
        `
        
        return {runResult, encryptedSecret, secret}
    }

    async function ppkDecrypt(secret) {
        const ppkText = $('#ppk').val();

        const ppk = await crypto.subtle.importKey(
            'pkcs8', 
            base64ToBuffer(ppkText), 
            rsaAlgo, 
            true, 
            ["decrypt"]
        )
        
        const encryptedPayload = base64ToBuffer(secret);
        const decryptedPayload = await crypto.subtle.decrypt(
            {name: 'RSA-OAEP'},
            ppk,
            encryptedPayload
        )

        decryptedSecret = utf8Decoder.decode(decryptedPayload)

        var runResult = `
Dencrypted Secret: (${decryptedPayload.byteLength} bytes):
${decryptedSecret}
        `
        return {runResult, decryptedSecret}
    }

    async function asymRoundTrip() {
        const result = await pubEncrypt();
        const decryptedResult = await ppkDecrypt(result.encryptedSecret);
        var runResult = result.runResult + `
round trip success: ${result.secret === decryptedResult.decryptedSecret}
`
        $('#output').html(runResult)
    }

    async function runPubEncrypt(e) {
        const result = await pubEncrypt();
        $('#output').html(result.runResult)
    }

    async function runPpkDecrypt(e) {
        const secret = $('#payload').val();
        const result = await ppkDecrypt(secret);
        $('#output').html(result.runResult)
    }


});

