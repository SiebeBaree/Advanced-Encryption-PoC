import fs from "fs";

export default class LocalStorage {
    private store: Record<string, string>;

    constructor() {
        this.store = {};
        this.loadFromJsonFile();
    }

    getItem(key: string) {
        return this.store[key] || null;
    }

    setItem(key: string, value: string) {
        this.store[key] = value.toString();
        this.saveToJsonFile();
    }

    clear() {
        this.store = {};
        this.saveToJsonFile();
    }

    removeItem(key: string) {
        delete this.store[key];
        this.saveToJsonFile();
    }

    private loadFromJsonFile() {
        try {
            const data = fs.readFileSync("localstorage.json", "utf8");
            this.store = JSON.parse(data);
        } catch (err) {
            console.error("Error reading JSON file:", err);
        }
    }

    private saveToJsonFile() {
        try {
            const data = JSON.stringify(this.store);
            fs.writeFileSync("localstorage.json", data, "utf8");
        } catch (err) {
            console.error("Error writing JSON file:", err);
        }
    }
}
