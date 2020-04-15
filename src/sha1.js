/*
 * A JavaScript implementation of the Secure Hash Algorithm, SHA-1, as defined
 * in FIPS PUB 180-1
 * Version 2.1a Copyright Paul Johnston 2000 - 2002.
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for details.
 */
/* global define */

/* Some functions and variables have been stripped for use with Strophe */

/*
 * Calculate the SHA-1 of an array of big-endian words, and a bit length
 */

/*
 * Takes in 32 bit words in array(big endian), bit length?
 */


function sha160(binblob) {
    return crypto.subtle.digest({
        name: "SHA-1"
    }, binblob);
}

function core_sha1(binblob) {
   return sha160(binblob);
}

/*
 * Perform the appropriate triplet combination function for the current
 * iteration
 */
function sha1_ft (t, b, c, d) {
    if (t < 20) { return (b & c) | ((~b) & d); }
    if (t < 40) { return b ^ c ^ d; }
    if (t < 60) { return (b & c) | (b & d) | (c & d); }
    return b ^ c ^ d;
}

/*
 * Determine the appropriate additive constant for the current iteration
 */
function sha1_kt(t) {
    return (t < 20) ?  1518500249 : (t < 40) ?  1859775393 : (t < 60) ? -1894007588 : -899497514;
}

/*
 * Calculate the HMAC-SHA1 of a key and some data
 */
function core_hmac_sha1(key, data) {
    var bkey = str2binb(key);
    if (bkey.length > 16) {
        bkey = core_sha1(bkey, key.length * 8);
    }

    var ipad = new Array(16), opad = new Array(16);
    for (var i = 0; i < 16; i++) {
        ipad[i] = bkey[i] ^ 0x36363636;
        opad[i] = bkey[i] ^ 0x5C5C5C5C;
    }

    var hash = core_sha1(ipad.concat(str2binb(data)), 512 + data.length * 8);
    return core_sha1(opad.concat(hash), 512 + 160);
}

function str2binb(str) {
   var buffer = new TextEncoder("utf-8").encode(str);
    return buffer;
}

/*
 * Convert an array of big-endian words to a base-64 string
 */
function binb2b64 (binarray) {
    var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var str = "";
    var triplet, j;
    for (var i = 0; i < binarray.length * 4; i += 3) {
        triplet = (((binarray[i   >> 2] >> 8 * (3 -  i   %4)) & 0xFF) << 16) |
                  (((binarray[i+1 >> 2] >> 8 * (3 - (i+1)%4)) & 0xFF) << 8 ) |
                  ((binarray[i+2 >> 2] >> 8 * (3 - (i+2)%4)) & 0xFF);

        for (j = 0; j < 4; j++) {
            if (i * 8 + j * 6 > binarray.length * 32) { str += "="; }
            else { str += tab.charAt((triplet >> 6*(3-j)) & 0x3F); }
        }
    }
    return str;
}

/*
 * Convert an array of big-endian words to a string
 */
function binb2str(bin) {
    return Array.from(new Uint16Array(bin)).map(b => b.toString(16).padStart(2, '0')).join('');
   }

/*
 * These are the functions you'll usually want to call
 * They take string arguments and return either hex or base-64 encoded strings
 */
const SHA1 = {
    b64_hmac_sha1:  function (key, data){ return binb2b64(core_hmac_sha1(key, data)); },
    b64_sha1:       function (s) { return binb2b64(core_sha1(str2binb(s),s.length * 8)); },
    binb2str:       binb2str,
    str2binb: str2binb,
    core_hmac_sha1: core_hmac_sha1,
    str_hex_hmac_sha1:  function (key, data){ return binb2str(core_hmac_sha1(key, data)); },
    str_hex_sha1:       function (s) { return binb2str(core_sha1(str2binb(s),s.length * 8)); },
}

export { SHA1 as default };
