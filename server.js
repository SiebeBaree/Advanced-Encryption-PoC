import crypto from "node:crypto";

// Mock implementation of a server
export default class Server {
    constructor() {
        this._secrets = new Map();
        this.ENCRYPTION_METHOD = "aes-256-cbc"; // Check why aes-256-gcm is not working
        this.iv = crypto.randomBytes(16); // NOT a secure way to generate an IV
        this.key = crypto.randomBytes(32); // NOT a secure way to generate a key

        this._users = new Map();
        this._projects = new Map();
    }

    setSecret(key, value) {
        const encryptedValue = this.encryptSecret(value);
        this._secrets.set(key, encryptedValue);
    }

    getSecret(key) {
        const secret = this._secrets.get(key);
        return this.decryptSecret(secret);
    }

    deleteSecret(key) {
        this._secrets.delete(key);
    }

    getUser(id) {
        return this._users.get(id);
    }

    addUser(id, data) {
        this._users.set(id, data);
    }

    updateUser(id, data) {
        this._users.set(id, { ...this._users.get(id), ...data });
    }

    getProject(id) {
        return this._projects.get(id);
    }

    encryptSecret(value) {
        const cipher = crypto.createCipheriv(
            this.ENCRYPTION_METHOD,
            Buffer.from(this.key, "hex"),
            Buffer.from(this.iv, "hex"),
        );
        let encrypted = cipher.update(JSON.stringify(value), "utf8", "hex");
        encrypted += cipher.final("hex");

        return encrypted;
    }

    decryptSecret(value) {
        const decipher = crypto.createDecipheriv(this.ENCRYPTION_METHOD, this.key, this.iv);
        let decrypted = decipher.update(value, "hex", "utf8");
        decrypted += decipher.final("utf8");

        return JSON.parse(decrypted);
    }
}
