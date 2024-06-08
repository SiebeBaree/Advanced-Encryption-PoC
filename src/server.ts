import crypto from "node:crypto";

export default class Server {
    private readonly ENCRYPTION_METHOD: string = "aes-256-cbc";
    private readonly iv: Buffer;
    private readonly key: Buffer;

    private _secrets: Map<number, any>;
    private _users: Map<number, any>;
    private _projects: Map<number, any>;
    private _projectKeys: Map<number, any>;

    constructor() {
        this._secrets = new Map();
        this.iv = crypto.randomBytes(16);
        this.key = crypto.randomBytes(32);

        this._users = new Map();
        this._projects = new Map();
        this._projectKeys = new Map();
    }

    setSecret(key: number, value: any) {
        const encryptedValue = this.encryptSecret(value);
        this._secrets.set(key, encryptedValue);
    }

    getSecret(key: number) {
        const secret = this._secrets.get(key);
        return this.decryptSecret(secret);
    }

    deleteSecret(key: number) {
        this._secrets.delete(key);
    }

    getUser(id: number) {
        return this._users.get(id);
    }

    addUser(id: number, data: any) {
        this._users.set(id, data);
    }

    updateUser(id: number, data: any) {
        this._users.set(id, { ...this._users.get(id), ...data });
    }

    getProject(id: number) {
        return this._projects.get(id);
    }

    addProject(id: number, data: any) {
        this._projects.set(id, data);
    }

    getProjectKey(id: number) {
        return this._projectKeys.get(id);
    }

    addProjectKey(id: number, data: any) {
        this._projectKeys.set(id, data);
    }

    encryptSecret(value: any) {
        const cipher = crypto.createCipheriv(this.ENCRYPTION_METHOD, this.key, this.iv);
        let encrypted = cipher.update(JSON.stringify(value), "utf8", "hex");
        encrypted += cipher.final("hex");

        return encrypted;
    }

    decryptSecret(value: string) {
        const decipher = crypto.createDecipheriv(this.ENCRYPTION_METHOD, this.key, this.iv);
        let decrypted = decipher.update(value, "hex", "utf8");
        decrypted += decipher.final("utf8");

        return JSON.parse(decrypted);
    }
}
