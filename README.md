# Encryption PoC

This proof of concept demonstrates how to encrypt and decrypt values in a project and let anyone who has access to the project to use the encrypted values. This PoC uses a zero-knowledge-first approach, meaning that the encryption key is never shared with the backend.

## How it works

Enkryptify employs a zero-knowledge-first approach to ensure the secure storage and sharing of secrets. This means that all secrets are encrypted on the client side before they reach our API, guaranteeing that the API cannot access the value of any secret.

When a user logs in, a private key is generated locally using 600,000 rounds of the Password-Based Key Derivation Function 2 ([PBKDF2](https://nodejs.org/api/crypto.html#cryptopbkdf2password-salt-iterations-keylen-digest-callback)) with SHA256 as the digest. This private key then generates an asymmetrical x25519-xsalsa20-poly1305 key using the [TweetNaCl.js](https://tweetnacl.js.org/) library. Only the public key is sent to the server, keeping the private key secure on the client side.

Upon creating a project, a randomly generated project key is encrypted on your device using your public key. The encrypted project key is then sent to the server. The plaintext project key is only temporarily stored in the client's memory and is promptly removed after use. All secret values created are encrypted on the client side using AES-256-GCM with the project key before being sent to the server, thereby maintaining the zero-knowledge-first principle. On the server, they undergo an additional layer of encryption using AES-256-GCM, ensuring double AES protection on both client and server sides. When an admin adds a new user to a project, the admin can encrypt the project key for the new user and update the server.

Certain integrations need secrets to be decrypted on the server for communication with these integrations. Even in these cases, all secrets are securely encrypted. Integrations that compromise the zero-knowledge principle are clearly marked with a red shield icon and trigger a confirmation pop-up. To revert this decision, all integrations marked by the red shield must be disabled.

> This PoC is used as research for Enkryptify, a secure secrets management platform that employs a zero-knowledge-first approach to ensure the secure storage and sharing of secrets. Visit [enkryptify.com](https://enkryptify.com) for more information and visit the [security page](https://enkryptify.com/security) for a detailed explanation of our security measures.

## How to run

1. Clone the repository

```bash
git clone https://github.com/SiebeBaree/Advanced-Encryption-PoC.git
```

2. Install the dependencies

```bash
pnpm install
```

3. Run the project

```bash
pnpm start
```
