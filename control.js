$( document ).ready(function() {
    const utf8Decoder = new TextDecoder();
    const utf8Encoder = new TextEncoder();

    $('#genKey').click(generateKey)
    $('#genVector').click(generateVector)

    $('#encrypt').click(runEncrypt)
    $('#decrypt').click(runDecrypt)
    $('#roundTrip').click(runRoundTrip)

    async function generateKey(e) {
        const key = generateSymmetric256Key();
        $('#key').val(buf2hex(key))
    }

    async function generateVector(e) {
        const vector = generateRandomVector();
        $('#vector').val(buf2hex(vector))
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
        const result = await encrypt();
        $('#output').html(result.runResult)
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
        const result = await encrypt();
        const decryptedPayload = await decryptSymmetric256Async(result.encryptedPayload, result.key);
        const decryptedSecret = utf8Decoder.decode(decryptedPayload)
        var runResult = result.runResult + `
round trip success: ${result.secret === decryptedSecret}
`
        $('#output').html(runResult)
    }
});

