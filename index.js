import Server from "./server.js";
import nacl from "tweetnacl";
import naclUtil from "tweetnacl-util";
import crypto from "node:crypto";

const api = new Server();

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

const user = {
    id: 1,
    email: "random@email.com",
    password: "S0meR@ndp@ssw0rd!",
};

const project = {
    id: 1,
    name: "Test Project",
};

const salt = getHash(user.email);
const key = await getPBKDF2Key(user.password, salt, 600_000, 32);

const keyPair = nacl.box.keyPair.fromSecretKey(key);
user.publicKey = keyPair.publicKey;
user.privateKey = keyPair.secretKey;

// Generate a project key (symmetric encryption key)
const projectKey = "56a92b13cf75ff43e0b38f95bf7be6595f1f048e16252cd1f706efb7aa123548";
project.projectKey = Buffer.from(projectKey, "hex");

// Encrypt the project key for each user using their public keys (client-side)
const nonce = nacl.randomBytes(nacl.box.nonceLength);
const encryptedProjectKey = nacl.box(project.projectKey, nonce, user.publicKey, user.privateKey);
user.encryptedProjectKey = { encryptedProjectKey, nonce };
console.log("Encrypted Project Key for user:", naclUtil.encodeBase64(encryptedProjectKey));

api.addUser(user.id, {
    id: user.id,
    email: user.email,
    password: getHash(user.password),
    publicKey: user.publicKey,
    encryptedProjectKey: user.encryptedProjectKey,
});

// Encrypt a secret with the project key (client-side)
function encryptSecret(secret, projectKey) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", projectKey, iv);

    let encrypted = cipher.update(secret, "utf8", "hex");
    encrypted += cipher.final("hex");
    const authTag = cipher.getAuthTag().toString("hex");

    return {
        iv: iv.toString("hex"),
        encrypted,
        authTag,
    };
}

// Decrypt a secret with the project key (client-side)
function decryptSecret(encryptedSecret, projectKey) {
    const { iv, encrypted, authTag } = encryptedSecret;
    const decipher = crypto.createDecipheriv("aes-256-gcm", projectKey, Buffer.from(iv, "hex"));
    decipher.setAuthTag(Buffer.from(authTag, "hex"));

    let decrypted = decipher.update(encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");

    return decrypted;
}

// Client-side decryption of the project key
function decryptProjectKey(encryptedProjectKey, publicKey, privateKey) {
    const { encryptedProjectKey: ciphertext, nonce } = encryptedProjectKey;
    const decryptedProjectKey = nacl.box.open(ciphertext, nonce, publicKey, privateKey);
    return decryptedProjectKey;
}

// Example client-side decryption of the project key for a user
const decryptedProjectKey = decryptProjectKey(user.encryptedProjectKey, user.publicKey, user.privateKey);
console.log("Decrypted Project Key for user1:", naclUtil.encodeBase64(decryptedProjectKey));

// Create secret (modal)
(() => {
    const secret = "http://localhost:8080/api/v1";
    const encryptedSecret = encryptSecret(secret, decryptedProjectKey);
    api.setSecret(1, encryptedSecret);
})();

// Get secret
const decryptedSecret = decryptSecret(api.getSecret(1), decryptedProjectKey);
console.log("Decrypted Secret:", decryptedSecret);
