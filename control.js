const saltBytes = [79, 225, 136, 232, 158, 39, 68, 116, 152, 131, 219, 227, 70, 62, 222, 113];
// const saltBytes = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const salt = bytesToArrayBuffer(saltBytes);

const ivBytes = [250, 110, 136, 113, 110, 202, 54, 196, 17, 144, 228, 246, 211, 14, 156, 23];
// const ivBytes = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const iv = bytesToArrayBuffer(ivBytes);

const pbkAlgo = {
    name: "PBKDF2",
    salt: salt, 
    iterations: 100000,
    hash: "SHA-256"
}

const aesAlgo = { 
    name: "AES-CBC", 
    iv: iv, 
    length: 256
};

const rsaAlgo = {
    name: "RSA-OAEP",
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-256"
}

$( document ).ready(function() {

    $('#genKey').click(generateKey)
    $('#genVector').click(generateVector)

    $('#encrypt').click(runEncrypt)
    $('#decrypt').click(runDecrypt)
    $('#roundTrip').click(runRoundTrip)

    $('#genKeyPair').click(generateRSAKeyPair)
    $('#pubEncrypt').click(runPubEncrypt)
    $('#ppkDecrypt').click(runPpkDecrypt)
    $('#asymRoundTrip').click(asymRoundTrip)

    async function generateKey(e) {
        const key = generateSymmetric256Key();
        $('#key').val(buf2base64(key))
    }

    async function generateVector(e) {
        const vector = generateRandomVector();
        $('#vector').val(buf2base64(vector))
    }

    async function getKeyMaterial(passphrase) {
        return crypto.subtle.importKey(
            "raw",
            utf8Encoder.encode(passphrase),
            {name: "PBKDF2"},
            false,
            ["deriveKey", "deriveKey"]
        )
    }

    async function getWrappingKey(keyMaterial) {
        return window.crypto.subtle.deriveKey(
            pbkAlgo,
            keyMaterial,
            aesAlgo,
            true,
            [ "wrapKey", "unwrapKey" ]
          );
    }

    async function generateRSAKeyPair(e) {
        // const passphrase = prompt("Enter your passphrase.")
        const passphrase = "12345";
        const keyPair = await crypto.subtle.generateKey(
            rsaAlgo,
            true,
            ["encrypt", "decrypt"]
        )

        const pub = await crypto.subtle.exportKey('spki', keyPair.publicKey);

        const ppk = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
        // const keyMaterial = await getKeyMaterial(passphrase)
        // const wrappingKey = await getWrappingKey(keyMaterial);
        // const ppk = await crypto.subtle.wrapKey("pkcs8", keyPair.privateKey, wrappingKey, aesAlgo);
        
        $('#pub').val(buf2base64(pub));
        $('#ppk').val(buf2base64(ppk));
    }



    async function encrypt() {
        const secret = $('#payload').val()
        const buf = utf8Encoder.encode(secret);

        var key
        const keyText = $('#key').val();
        if (keyText == "") {
            key = generateSymmetric256Key();
            $('#key').val(buf2base64(key))
        } else {
            key = base64ToBuffer(keyText)
        }

        var vector
        const vectorText = $('#vector').val();
        if (vectorText == "") {
            vector = generateRandomVector();
            $('#vector').val(buf2base64(vector))
        } else {
            vector = base64ToBuffer(vectorText)
        }

        const encryptedPayload = await encryptSymmetric256Async(buf, key, vector);
        const message = splitEncryptedMessage(encryptedPayload);

        var runResult = `
key: ${buf2base64(key)}

initialize vector: ${buf2base64(vector)}

algorithmCode (1 byte): ${message.algorithmCode.toString()}

initializationVector (${message.initializationVector.length} bytes):  ${buf2base64(message.initializationVector)}

encryptedSecret (${message.encryptedSecret.length} bytes): 
${buf2base64(message.encryptedSecret)}

tag (${message.tag.length} bytes): ${buf2base64(message.tag)}

concatenated payload (${encryptedPayload.length} bytes):
${buf2base64(encryptedPayload)}
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
        // const iv = base64ToBuffer($('#vector').val())
        // const decryptedPayload = await decryptMessageAsync({
        //     initializationVector: iv,
        //     encryptedSecret: payload
        // }, key)
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

        const pub = await crypto.subtle.importKey(
            'spki', 
            base64ToBuffer(pubText), 
            rsaAlgo, 
            true, 
            ["encrypt"]
        )
        
        // import none encrypted ppk
        // const ppk = await crypto.subtle.importKey(
        //     'pkcs8', 
        //     base64ToBuffer(ppkText), 
        //     rsaAlgo, 
        //     true, 
        //     ["decrypt"]
        // )

        // import encrypted ppk-----------------------------------------
        // const keyMaterial = await getKeyMaterial(passphrase);
        // const wrappingKey = await getWrappingKey(keyMaterial);

        // const ppk = await crypto.subtle.unwrapKey(
        //     'pkcs8',
        //     base64ToBuffer(ppkText),
        //     wrappingKey,
        //     aesAlgo,
        //     rsaAlgo, 
        //     true,
        //     ["decrypt"]
        // )
        // end import encrypted ppk-----------------------------------------

        
        var encryptedPayload = await crypto.subtle.encrypt(
            {name: 'RSA-OAEP'}, 
            pub, 
            utf8Encoder.encode(secret)
        )


        // console.log(buf2base64(encryptedPayload))

        // const decryptedPayload = await crypto.subtle.decrypt(
        //     {name: 'RSA-OAEP'},
        //     ppk,
        //     encryptedPayload
        // )

        // console.log(utf8Decoder.decode(decryptedPayload))
        const encryptedSecret = buf2base64(encryptedPayload)

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

