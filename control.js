$( document ).ready(function() {
    const utf8Decoder = new TextDecoder();
    const utf8Encoder = new TextEncoder();

    $('#genKey').click(generateKey)

    $('#encrypt').click(runEncrypt)
    $('#decrypt').click(runDecrypt)
    $('#roundTrip').click(runRoundTrip)

    async function generateKey(e) {
        const key = generateSymmetric256Key();
        $('#key').val(buf2hex(key))
    }

    async function runEncrypt(e) {
        const secret = $('#payload').val()
        const buf = utf8Encoder.encode(secret);

        var key
        const keyText = $('#key').val();
        if (keyText == "") {
            key = generateSymmetric256Key();
            $('#key').val(buf2hex(key))
        } else {
            key = Uint8ArrayFromHex($('#key').val())
        }
        
        const encryptedPayload = await encryptSymmetric256Async(buf, key);
        const message = splitEncryptedMessage(encryptedPayload);

        var runResult = `
key: ${buf2hex(key)}

algorithmCode (1 byte): ${message.algorithmCode.toString()}

initializationVector (${message.initializationVector.length} bytes):  ${buf2hex(message.initializationVector)}

encryptedSecret (${message.encryptedSecret.length} bytes): 
${buf2hex(message.encryptedSecret)}

tag (${message.tag.length} bytes): ${buf2hex(message.tag)}

concatenated payload (${encryptedPayload.length} bytes):
${buf2hex(encryptedPayload)}
`
        $('#output').html(runResult)
    }

    async function runDecrypt(e) {
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
        const secret = $('#payload').val()
        const buf = utf8Encoder.encode(secret);

        var key
        const keyText = $('#key').val();
        if (keyText == "") {
            key = generateSymmetric256Key();
            $('#key').val(buf2hex(key))
        } else {
            key = Uint8ArrayFromHex($('#key').val())
        }
        
        const encryptedPayload = await encryptSymmetric256Async(buf, key);
        const decryptedPayload = await decryptSymmetric256Async(encryptedPayload, key);
        const decryptedSecret = utf8Decoder.decode(decryptedPayload)
        
        const message = splitEncryptedMessage(encryptedPayload);
        var runResult = `
key: ${buf2hex(key)}

algorithmCode (1 byte): ${message.algorithmCode.toString()}

initializationVector (${message.initializationVector.length} bytes):  ${buf2hex(message.initializationVector)}

encryptedSecret (${message.encryptedSecret.length} bytes): 
${buf2hex(message.encryptedSecret)}

tag (${message.tag.length} bytes): ${buf2hex(message.tag)}

concatenated payload (${encryptedPayload.length} bytes):
${buf2hex(encryptedPayload)}

success: ${secret === decryptedSecret}
`

        $('#output').html(runResult)
    }
});

