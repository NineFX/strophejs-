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
const HMACSHA1 = {name: "HMAC", "hash" : "SHA-1"};
const PBKDF2SHA1 = {name: "PBKDF2", "hash": "SHA-1"};

async function sha160(binblob) {
    return crypto.subtle.digest({
        name: "SHA-1"
    }, binblob);
}

async function core_sha1(binblob) {
   return sha160(binblob);
}

async function hmac_generate_key_from_string(string) {
  return crypto.subtle.importKey(
    "raw",
    str2binb(string),
    HMACSHA1,
    false,
    [
      "sign",
      "verify"
    ]
  );
}

async function hmac_generate_key_from_raw(blob) {
  return crypto.subtle.importKey(
    "raw",
    blob,
    HMACSHA1,
    false,
    [
      "sign",
      "verify"
    ]
  );
}

async function pbkdf2_generate_key_from_string(string) {
  return crypto.subtle.importKey(
    "raw",
    str2binb(string),
    PBKDF2SHA1,
    false,
    ["deriveKey", "deriveBits"],
  );
}

async function pbkdf2_derive_salted_key(key, salt, iterations) {
  return crypto.subtle.deriveKey(
    {
      "name": "PBKDF2",
      salt: salt,
      "iterations": iterations,
      "hash": "SHA-1",
    },
    key,
    {
      "name": "HMAC",
      "hash": "SHA-1",
      "length": 160
    },
    true,
    [ "sign", "verify"]
  );
}

async function pbkdf2_sign(key, data) {  // Unknown
  return crypto.subtle.sign(
    "HMAC",
    key,
    data
  );
}



/*
 * Calculate the HMAC-SHA1 of a key and some data
 */
async function core_hmac_sha1(key, data) {
  return crypto.subtle.sign(
    HMACSHA1,
    key,
    data
  );
}

function str2binb(str) {
    return (new TextEncoder(ENCODING)).encode(str);
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
    return Array.prototype.map.call(new Uint8Array(bin), x => ('00' + x.toString(16)).slice(-2)).join('');
}

function b64binb(base64String) {
    return Uint8Array.from(atob(base64String), c => c.charCodeAt(0));
}

function binb2arr5(binblob) {
  if (binblob.length != 5) {
    return []
  }
  return [0,1,2,3,4].map((x) => binblob[x]);
}

/*
 * These are the functions you'll usually want to call
 * They take string arguments and return either hex or base-64 encoded strings
 */
const SHA1 = {
    sha1: sha160,
    b64_hmac_sha1:  function (key, data) { return binb2b64(core_hmac_sha1(key, data)); },
    b64_sha1:       function (s) { return binb2b64(core_sha1(str2binb(s),s.length * 8)); },
    bin2hexstr:       bin2hexstr,
    str2binb: str2binb,
    core_hmac_sha1: core_hmac_sha1,
    str_hex_hmac_sha1:  function (key, data) { return core_hmac_sha1(key, data).then(bin2hexstr); },
    str_hex_sha1:       function (s) { return core_sha1(str2binb(s)).then(bin2hexstr); },
    hmac_generate_key_from_string: hmac_generate_key_from_string,
    hmac_generate_key_from_raw,
    pbkdf2_generate_key_from_string: pbkdf2_generate_key_from_string,
    pbkdf2_full_sign_from_string: function (keyString, salt, iterations, data) {
      return pbkdf2_generate_key_from_string(keyString).then((key) => pbkdf2_derive_salted_key(key, salt, iterations).then((key) => pbkdf2_sign(key, data)));
      },
    pbkdf2_sign: pbkdf2_sign,
    pbkdf2_generate_salted_key: function (password, salt, iterations) {
      return pbkdf2_generate_key_from_string(password).then((key) => pbkdf2_derive_salted_key(key, salt, iterations));
    }
}

export { SHA1 as default };
