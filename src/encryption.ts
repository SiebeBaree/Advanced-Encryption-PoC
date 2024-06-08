// For more information visit: https://enkryptify.com/security
import crypto from "node:crypto";
import nacl from "tweetnacl";
import naclUtil from "tweetnacl-util";

const ENCRYPTION_ALGORITHM = "aes-256-gcm";

export type EncryptedProjectKey = {
    key: string;
    nonce: string;
};

export type EncryptedSecretValue = {
    iv: string;
    encrypted: string;
    authTag: string;
};

export async function generateKeyPair(
    email: string,
    password: string,
): Promise<{ publicKey: string; privateKey: string }> {
    const salt = getHash(email);
    const key = await getPBKDF2Key(password, salt, 600_000, 32);
    const keyPair = nacl.box.keyPair.fromSecretKey(key);

    return {
        publicKey: naclUtil.encodeBase64(keyPair.publicKey),
        privateKey: naclUtil.encodeBase64(keyPair.secretKey),
    };
}

export function encryptProjectKey(
    publicKey: string,
    privateKey: string,
    existingProjectKey?: Uint8Array,
): EncryptedProjectKey {
    const projectKey = existingProjectKey ? existingProjectKey : createRandomProjectKey();
    const nonce = nacl.randomBytes(nacl.box.nonceLength);
    const encryptedProjectKey = nacl.box(
        projectKey,
        nonce,
        naclUtil.decodeBase64(publicKey),
        naclUtil.decodeBase64(privateKey),
    );

    return {
        key: naclUtil.encodeBase64(encryptedProjectKey),
        nonce: naclUtil.encodeBase64(nonce),
    };
}

export function decryptProjectKey(
    encryptedProjectKey: EncryptedProjectKey,
    publicKey: string,
    privateKey: string,
): Uint8Array | null {
    const { key, nonce } = encryptedProjectKey;
    const decryptedProjectKey = nacl.box.open(
        naclUtil.decodeBase64(key),
        naclUtil.decodeBase64(nonce),
        naclUtil.decodeBase64(publicKey),
        naclUtil.decodeBase64(privateKey),
    );
    return decryptedProjectKey;
}

export function encryptSecret(secret: string, projectKey: Uint8Array): EncryptedSecretValue {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(
        ENCRYPTION_ALGORITHM,
        Buffer.from(naclUtil.encodeBase64(projectKey), "base64"),
        iv,
    );

    let encrypted = cipher.update(secret, "utf8", "hex");
    encrypted += cipher.final("hex");
    const authTag = cipher.getAuthTag().toString("hex");

    return {
        iv: iv.toString("hex"),
        encrypted,
        authTag,
    };
}

export function decryptSecret(secret: EncryptedSecretValue, projectKey: Uint8Array): string {
    const { iv, encrypted, authTag } = secret;
    const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, projectKey, Buffer.from(iv, "hex"));
    decipher.setAuthTag(Buffer.from(authTag, "hex"));

    let decrypted = decipher.update(encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");

    return decrypted;
}

async function getPBKDF2Key(password: string, salt: string, iterations: number, keyLength: number): Promise<Buffer> {
    return new Promise((resolve, reject) => {
        crypto.pbkdf2(password, salt, iterations, keyLength, "sha256", (err, derivedKey) => {
            if (err) reject(err);
            resolve(derivedKey);
        });
    });
}

function getHash(value: string): string {
    return crypto.createHash("sha256").update(value).digest("hex");
}

function createRandomProjectKey(): Uint8Array {
    return nacl.randomBytes(32);
}
