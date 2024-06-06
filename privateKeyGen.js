// A small implementation of a public/private key generator using PBKDF2 and TweetNaCl

import crypto from "node:crypto";
import nacl from "tweetnacl";

const email = "random@email.com";
const password = "S0meR@nd0mP@ssw0rd!";

function getHash(value) {
    return crypto.createHash("sha256").update(value).digest("hex");
}

async function getPBKDF2Key(password, salt, iterations, keyLength) {
    const key = await new Promise((resolve, reject) => {
        crypto.pbkdf2(password, salt, iterations, keyLength, "sha256", (err, derivedKey) => {
            if (err) reject(err);
            resolve(derivedKey);
        });
    });
    return key;
}

(async () => {
    const salt = getHash(email);
    const key = await getPBKDF2Key(password, salt, 600_000, 32);
    console.log(Buffer.from(key).toString("hex"));

    const keyPair = nacl.box.keyPair.fromSecretKey(key);
    const publicKey = keyPair.publicKey;
    const privateKey = keyPair.secretKey;

    console.log(Buffer.from(privateKey).toString("hex"));
    console.log(Buffer.from(publicKey).toString("hex"));

    console.log(key == Buffer.from(privateKey).toString());
})();
