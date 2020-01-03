const rsaAlgo = {
    name: "RSA-OAEP",
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-256"
}

$( document ).ready(function() {

    $('#genClientKey').click(genClientKey)
    // $('#deriveKey').click(deriveKey)
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

//     async function deriveKey(e) {
//         const passphrase = $('#payload').val()
//         const saltText = $('#salt').val()
//         const iter = +$('#iter').val()
//         const salt = uint8ArrayFromBase64(saltText)

//         const start = performance.now();
//         key = await symmetric256KeyFromAsciiPassphraseAsync(passphrase, iter, salt)
//         const end = performance.now();

//         var runResult = `
// took ${end-start} ms
// key: ${base64FromArrayBuffer(key)}
// `
//     $('#output').html(runResult)

//     }

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
        if($('#clientKey').val() == '') {
            genClientKey();
        }

        if($('#salt').val() == '') {
            generateSalt()
        }

        const clientKey = $('#clientKey').val();
        const salt = uint8ArrayFromBase64($('#salt').val());
        const iterations = +$('#iter').val();
        const keyPair = await generateAsymmetric4096KeyPairAsync();
        const passworDecryptedPrivateKey = await passwordEncryptAsync(clientKey, uint8ArrayFromBase64(keyPair.privateKey), iterations, salt);
        $('#pub').val(keyPair.publicKey);
        $('#ppk').val(base64FromUint8Array(passworDecryptedPrivateKey));
    }

    async function encrypt() {
        if ($('#key').val() == '') {
            generateKey();
        }

        if ($('#vector').val() == '') {
            generateVector();
        }

        const secret = $('#payload').val()
        const buf = utf8Encoder.encode(secret);

        const keyText = $('#key').val();
        const key = uint8ArrayFromBase64(keyText)

        const vectorText = $('#vector').val();
        const vector = uint8ArrayFromBase64(vectorText)

        const encryptedPayload = await encryptSymmetric256Async(buf, key, vector);
        const message = splitEncryptedMessage(encryptedPayload);

        var runResult = `
key: ${base64FromUint8Array(key)}

initialize vector: ${base64FromUint8Array(vector)}

algorithmCode (1 byte): ${message.algorithmCode.toString()}

initializationVector (${message.initializationVector.length} bytes):  ${base64FromUint8Array(message.initializationVector)}

Encrypted Secret (${message.encryptedSecret.length} bytes): 
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
        const payload = uint8ArrayFromBase64($('#payload').val());
        const key = uint8ArrayFromBase64($('#key').val())
        const decryptedPayload = await decryptSymmetric256Async(payload, key);
        const decryptedSecret = utf8Decoder.decode(decryptedPayload)

        var runResult = `
Decrypted Secret: (${decryptedPayload.byteLength} bytes):
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

        const pub = await importBase64EncodedRsa4096PublicKeyAsync(pubText);
        
        var encryptedPayload = await crypto.subtle.encrypt(
            {name: 'RSA-OAEP'}, 
            pub, 
            utf8Encoder.encode(secret)
        )

        const encryptedSecret = base64FromArrayBuffer(encryptedPayload)

        var runResult = `
Encrypted Secret (${encryptedPayload.byteLength} bytes): 
${encryptedSecret}
        `
        
        return {runResult, encryptedSecret, secret}
    }

    async function ppkDecrypt(secret) {
        const ppkText = $('#ppk').val();
        const clientKey = $('#clientKey').val();
        const salt = uint8ArrayFromBase64($('#salt').val());
        const iterations = +$('#iter').val();

        const encryptedPPK = uint8ArrayFromBase64(ppkText);
        const encryptedPPKParts = splitPasswordEncryptedMessage(encryptedPPK);

        const secretBuf = uint8ArrayFromBase64(secret);

        const decryptionKey = await symmetric256KeyFromAsciiPassphraseAsync(clientKey, iterations, salt);
        const decryptedPPKBuf = await decryptSymmetric256Async(encryptedPPKParts.encryptedMessage, new Uint8Array(decryptionKey));
        const decryptedPPK = base64FromArrayBuffer(decryptedPPKBuf)
        const decryptedPayload = await decryptUsingPrivateKeyAsync(secretBuf, decryptedPPKBuf);

        const decryptedSecret = utf8Decoder.decode(decryptedPayload);
        var runResult = `
Decrypted Private Key: 
${decryptedPPK}

Decrypted Secret: (${decryptedPayload.byteLength} bytes):
${decryptedSecret}
        `
        return {runResult, decryptedSecret}
    }

    async function asymRoundTrip() {
        const result = await pubEncrypt();
        const decryptedResult = await ppkDecrypt(result.encryptedSecret);
        var runResult = result.runResult + decryptedResult.runResult + `
round trip success: ${result.secret === decryptedResult.decryptedSecret}
`;
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

