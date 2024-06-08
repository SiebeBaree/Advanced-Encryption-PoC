import Server from "./server";
import { decryptProjectKey, decryptSecret, encryptProjectKey, encryptSecret, generateKeyPair } from "./encryption";

const api = new Server();

async function main() {
    // Create users
    (() => {
        const user1 = {
            id: 1,
            email: "user1@email.com",
            password: "S0meR@ndp@ssw0rd!",
        };

        const user2 = {
            id: 2,
            email: "user2@email.com",
            password: "S0meR@ndp@ssw0rd!",
        };

        api.addUser(user1.id, user1);
        api.addUser(user2.id, user2);
    })();

    // User login
    const user1 = api.getUser(1);
    const now = new Date();
    const keyPair = await generateKeyPair(user1.email, user1.password);
    console.log("Generated Key Pair in", new Date().getTime() - now.getTime(), "ms");
    console.log("Key Pair:", keyPair.privateKey);
    api.updateUser(1, { publicKey: keyPair.publicKey });

    // Create Project
    api.addProject(1, { id: 1, name: "Test Project" });
    api.addProjectKey(1, {
        id: 1,
        projectId: 1,
        userId: 1,
        key: encryptProjectKey(keyPair.publicKey, keyPair.privateKey),
    });

    // Create Secret
    (() => {
        const projectKey = decryptProjectKey(api.getProjectKey(1).key, keyPair.publicKey, keyPair.privateKey);
        api.setSecret(1, {
            id: 1,
            projectId: 1,
            value: encryptSecret("http://localhost:8080/api/v1", projectKey!),
        });
    })();

    // Get secret for user 1
    (() => {
        const secret = api.getSecret(1);
        console.log("Encrypted Secret (user1):", secret);

        const projectKey = decryptProjectKey(api.getProjectKey(1).key, keyPair.publicKey, keyPair.privateKey);
        const decryptedSecret = decryptSecret(secret.value, projectKey!);
        console.log("Decrypted Secret (user1):", decryptedSecret);
    })();

    // User 2 login
    const user2 = api.getUser(2);
    const keyPair2 = await generateKeyPair(user2.email, user2.password);
    api.updateUser(2, { publicKey: keyPair2.publicKey });

    // Add user 2 to project
    (() => {
        user1.encryptedProjectKey = api.getProjectKey(1).key;
        const projectKey = decryptProjectKey(user1.encryptedProjectKey, keyPair.publicKey, keyPair.privateKey);

        api.addProjectKey(1, {
            id: 2,
            projectId: 1,
            userId: 2,
            key: encryptProjectKey(keyPair2.publicKey, keyPair.privateKey, projectKey!),
        });
    })();

    // Get secret for user 2
    (() => {
        const secret = api.getSecret(1);
        console.log("Encrypted Secret (user2):", secret);

        const projectKey = decryptProjectKey(api.getProjectKey(1).key, keyPair.publicKey, keyPair2.privateKey);
        const decryptedSecret = decryptSecret(secret.value, projectKey!);
        console.log("Decrypted Secret (user2):", decryptedSecret);
    })();
}

main();
