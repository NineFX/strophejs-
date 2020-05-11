const username = "user";
const password = "pencil";
const clientNonce = b64binb("fyko+d2lbbFgONRv9qkxdawL");
const serverNonce = b64binb("3rfcNHYJY1ZVvWVs7j");
const serverSalt = b64binb("QSXCR+Q6sek8bf92");
const iterations = 4096;

//import * from "./sha1";

async function testSignedPassword() {
  key = await pbkdf2_generate_key_from_string(password);
  saltedKey = await pbkdf2_derive_salted_key(key, serverSalt, iterations);
  hexKey = bin2hexstr(await crypto.subtle.exportKey("raw", saltedKey));
  console.assert(hexKey === "1d96ee3a529b5a5f9e47c01f229a2cb8a6e15f7d", "Error, strings do not match");
}

testSignedPassword();
