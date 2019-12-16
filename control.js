const saltBytes = [79, 225, 136, 232, 158, 39, 68, 116, 152, 131, 219, 227, 70, 62, 222, 113];
// const saltBytes = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const salt = bytesToArrayBuffer(saltBytes);

const ivBytes = [250, 110, 136, 113, 110, 202, 54, 196, 17, 144, 228, 246, 211, 14, 156, 23];
// const ivBytes = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const iv = bytesToArrayBuffer(ivBytes);

const aesAlgo = { 
    name: "AES-CBC", 
    iv: iv, 
    length: 256
};

$( document ).ready(function() {

    $('#genKey').click(generateKey)
    $('#genVector').click(generateVector)

    $('#encrypt').click(runEncrypt)
    $('#decrypt').click(runDecrypt)
    $('#roundTrip').click(runRoundTrip)

    $('#pubEncrypt').click(pubEncrypt)

    async function generateKey(e) {
        const key = generateSymmetric256Key();
        $('#key').val(buf2hex(key))
    }

    async function generateVector(e) {
        const vector = generateRandomVector();
        $('#vector').val(buf2hex(vector))
    }

    async function generateRSAKeyPair(e) {
    
    }

    async function encrypt() {
        const secret = $('#payload').val()
        const buf = utf8Encoder.encode(secret);

        var key
        const keyText = $('#key').val();
        if (keyText == "") {
            key = generateSymmetric256Key();
            $('#key').val(buf2hex(key))
        } else {
            key = Uint8ArrayFromHex(keyText)
        }

        var vector
        const vectorText = $('#vector').val();
        if (vectorText == "") {
            vector = generateRandomVector();
            $('#vector').val(buf2hex(vector))
        } else {
            vector = Uint8ArrayFromHex(vectorText)
        }

        const encryptedPayload = await encryptSymmetric256Async(buf, key, vector);
        const message = splitEncryptedMessage(encryptedPayload);

        var runResult = `
key: ${buf2hex(key)}

initialize vector: ${buf2hex(vector)}

algorithmCode (1 byte): ${message.algorithmCode.toString()}

initializationVector (${message.initializationVector.length} bytes):  ${buf2hex(message.initializationVector)}

encryptedSecret (${message.encryptedSecret.length} bytes): 
${buf2hex(message.encryptedSecret)}

tag (${message.tag.length} bytes): ${buf2hex(message.tag)}

concatenated payload (${encryptedPayload.length} bytes):
${buf2hex(encryptedPayload)}
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
        const payload = Uint8ArrayFromHex($('#payload').val());
        const key = Uint8ArrayFromHex($('#key').val())
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

    async function pubEncrypt(e) {
        const pubText = $('#pub').val();
        const ppkText = $('#ppk').val();
        const secret = $('#payload').val();
        const passphrase = $('#passphrase').val();

        const pub = await crypto.subtle.importKey(
            'spki', 
            base64ToBuffer(pubText), 
            {
                name: "RSA-OAEP", 
                hash: "SHA-256",
                modulusLength: 2048,
                publicExponent: 0x10001
            }, 
            true, 
            ["encrypt"]
        )
        
        // import none encrypted ppk
        // const ppk = await crypto.subtle.importKey(
        //     'pkcs8', 
        //     str2ab(atob(ppkText)), 
        //     {
        //         name: "RSA-OAEP", 
        //         hash: "SHA-256",
        //         modulusLength: 2048,
        //         publicExponent: new Uint8Array([1, 0, 1])
        //     }, 
        //     true, 
        //     ["decrypt"]
        // )

        // import encrypted ppk-----------------------------------------
        const keyMaterial = await crypto.subtle.importKey(
            "raw",
            utf8Encoder.encode(passphrase),
            {name: "PBKDF2"},
            false,
            ["deriveKey"]
        );
        const unwrappingKey = await crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt, 
                iterations: 1000,
                hash: "SHA-256"
            },
            keyMaterial,
            aesAlgo,
            true,
            ["unwrapKey"]
        );

        const ppk = await crypto.subtle.unwrapKey(
            'pkcs8',
            base64ToBuffer(ppkText),
            unwrappingKey,
            aesAlgo,
            {
                name: "RSA-OAEP",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256",
            }, 
            true,
            ["decrypt"]
        )
        // end import encrypted ppk-----------------------------------------

        
        var encryptedPayload = await crypto.subtle.encrypt(
            {name: 'RSA-OAEP'}, 
            pub, 
            utf8Encoder.encode(secret)
        )

        console.log(buf2hex(encryptedPayload))

        const decryptedPayload = await crypto.subtle.decrypt(
            {name: 'RSA-OAEP'},
            ppk,
            encryptedPayload
        )

        console.log(utf8Decoder.decode(decryptedPayload))

    }

});

