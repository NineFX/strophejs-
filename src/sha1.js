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


const ENCODING = "utf-8";

function sha160(binblob) {
    return crypto.subtle.digest({
        name: "SHA-1"
    }, binblob);
}

function core_sha1(binblob) {
   return sha160(binblob);
}

/*
 * Calculate the HMAC-SHA1 of a key and some data
 */
function core_hmac_sha1(key, data) {
  return crypto.subtle.sign(
    "HMAC",
    key,
    data
  );
}

function str2binb(str) {
    return new TextEncoder(ENCODING).encode(str);
}

/*
 * Convert an array of big-endian words to a base-64 string
 */
function binb2b64 (binarray) {
    return btoa(String.fromCharCode(...new Uint8Array(binarray)));
}

/*
 * Convert an array of big-endian words to a string
 */
function bin2hexstr(bin) {
    return Array.from(new Uint16Array(bin)).map(b => b.toString(16).padStart(2, '0')).join('');
}

/*
 * These are the functions you'll usually want to call
 * They take string arguments and return either hex or base-64 encoded strings
 */
const SHA1 = {
    b64_hmac_sha1:  function (key, data){ return binb2b64(core_hmac_sha1(key, data)); },
    b64_sha1:       function (s) { return binb2b64(core_sha1(str2binb(s),s.length * 8)); },
    bin2hexstr:       bin2hexstr,
    str2binb: str2binb,
    core_hmac_sha1: core_hmac_sha1,
    str_hex_hmac_sha1:  function (key, data){ return core_hmac_sha1(key, data).then(bin2hexstr); },
    str_hex_sha1:       function (s) { return core_sha1(str2binb(s)).then(bin2hexstr); },
}

export { SHA1 as default };
