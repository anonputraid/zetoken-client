# Zetoken Client (Browser / Pure Vanilla JavaScript)

[![Version](https://img.shields.io/badge/version-1.0.1-blue.svg)](https://github.com/anonputraid/zetoken-client/releases/tag/v1.0.1)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Dependencies](https://img.shields.io/badge/dependencies-0%20(Pure%20Vanilla)-brightgreen.svg)](#)
[![Crypto Standard](https://img.shields.io/badge/crypto-Web%20Crypto%20API-orange.svg)](#)
[![Interoperability](https://img.shields.io/badge/interoperability-Python%20%7C%20PHP%20%7C%20Node.js-purple.svg)](#)

Official client-side implementation of the **Zetoken** cryptographic algorithm built with **Pure Vanilla JavaScript** (zero external runtime dependencies). Designed for **Zero-Knowledge Client-Side Encryption (CSE)**, it leverages the browser-native **Web Crypto API** to encrypt sensitive data and binary files before they leave the browser, ensuring 100% interoperability with Zetoken backends in **Python**, **PHP**, and **Node.js**.

---

## 📑 Table of Contents

- [🛡️ Security Philosophy & Threat Model](#️-security-philosophy--threat-model)
  - [The `www-data` Server Breach Problem](#1-the-critical-flaw-in-conventional-server-side-encryption)
  - [The Zero-Knowledge CSE Solution](#2-the-zetoken-client-solution-zero-knowledge-architecture)
  - [Data Flow Diagram](#data-flow-diagram)
  - [Security Best Practices](#3-frontend-security-best-practices)
- [🚀 Key Features](#-key-features)
- [📦 Installation & CDN Setup](#-installation--cdn-setup)
  - [Method 1: Direct Download (Self-Hosted)](#-method-1-direct-download-self-hosted--recommended)
  - [Method 2: jsDelivr CDN (`v1.0.1`)](#-method-2-jsdelivr-cdn-instant-cloud-hosted)
- [⚡ Quickstart & Usage](#-quickstart--usage)
- [🔑 Key Configuration File Format](#-key-configuration-file-format)
- [📚 Complete API Reference](#-complete-api-reference)
  - [Core Encryption & Decryption](#core-encryption--decryption)
  - [3-Layer Entity Sign](#3-layer-entity-sign)
  - [File Vault (`.zetoken` Format)](#file-vault-zetoken-binary-encryption)
  - [Key & Onboarding Modal Management](#key--onboarding-modal-management)
- [🗄️ `.zetoken` Container Specification](#️-specification-of-the-zetoken-file-container)
- [🔄 Cross-Habitat Matrix](#-cross-habitat-interoperability-matrix)
- [🖥️ Interactive Demo Dashboard](#️-interactive-demo-dashboard)
- [📄 License](#-license)

---

## 🛡️ Security Philosophy & Threat Model

### 1. The Critical Flaw in Conventional Server-Side Encryption

In traditional web applications, confidential data is sent from the user's browser to the server as plaintext (protected only by SSL/TLS in transit) and encrypted at the server using secret keys stored in the server's `.env` configuration.

**The Catastrophic Breach Scenario:**
When an application vulnerability (e.g., Local File Inclusion, Remote Code Execution, or SQL Injection) occurs:
1. The attacker gains command execution under `www-data` (the default web server user).
2. With `www-data` privileges, the attacker reads the server's **`.env` file** and database credentials.
3. The attacker dumps the database tables and decrypts all records using the leaked `.env` keys.
4. **Result:** Total data breach. Every confidential user record is compromised in plain text.

---

### 2. The Zetoken Client Solution: Zero-Knowledge Architecture

Zetoken Client eliminates this single point of failure by enforcing client-side encryption **before** transmission:

#### Data Flow Diagram:
```text
[ USER BROWSER ]                                        [ SERVER / DATABASE ]
       │                                                         │
 1. User inputs sensitive data                                   │
       │                                                         │
 2. Encrypt locally in browser via                               │
    zetoken-client.js (Key in localStorage)                      │
       │                                                         │
 3. Send numeric token (Ciphertext) ──── HTTP POST ────────────> │
                                                            4. Store numeric token
                                                               into Database
                                                                 │
 6. Receive numeric token           <─── HTTP GET ────────────── 5. Query stored token
       │
 7. Decrypt locally in browser via
    key held in localStorage
       │
 8. Plaintext displayed to user
```

**Security Guarantees:**
- **Keys Never Leave the Client:** Cryptographic keys reside exclusively on the user's device (uploaded or generated in the onboarding modal and stored in browser `localStorage`), never written to server `.env` files or databases.
- **Immune to Server Compromises:** Even if an attacker compromises the server with `www-data` or root access, they obtain only meaningless numeric ciphertext streams (`226243233014...`). The data cannot be decrypted without the client-side keys.
- **Zero Legal Liability:** Service providers never store unencrypted Personally Identifiable Information (PII) or financial data at rest.
- **"Your Keys, Your Data":** No backdoors and no recovery keys on the server. If a user loses their `.key` file, the encrypted data cannot be decrypted by anyone.

---

### 3. Frontend Security Best Practices

Because cryptographic operations occur inside the browser:
1. **Strict Content Security Policy (CSP):** Disallow unauthorized third-party scripts to safeguard `localStorage`.
2. **Sanitize Inputs:** Prevent Cross-Site Scripting (XSS).
3. **Key Purging on Shared Devices:** Always provide a **"Reset / Clear Key"** option on shared terminals to purge keys from `localStorage` upon logout.

---

## 🚀 Key Features

- **Pure Vanilla JavaScript:** Zero runtime dependencies. No npm build steps, Webpack, or Vite required.
- **W3C Standard Cryptography (Web Crypto API):**
  - **Cipher:** `AES-128-GCM` with a cryptographically secure 12-byte CSPRNG IV generated per encryption.
  - **KDF:** PBKDF2 with `SHA-512` digest (128-bit derived symmetric key).
  - **Auth Tag:** 16-byte GCM authentication tag preventing any payload tampering.
  - **Numeric Stream:** 3-digit zero-padded decimal stream (`000` to `255`), URL-safe and WebSocket-safe without Base64 padding anomalies.
- **Multi-Line Key Parser (`key=value`):** Parses `.key`, `.env`, and `.txt` files; ignores comments and derives keys deterministically for custom key names.
- **Fullscreen Onboarding Modal:** Built-in UI for uploading key files, 1-click generation, and manual key entry.
- **Scoped Component Styles:** `style.css` is strictly scoped under `.ztx-*` to prevent any CSS pollution or background mutation on host websites.
- **Time-Bound Tokens (TTL):** Built-in token expiration with clock-skew leeway (default: 60s).
- **3-Layer Entity Sign:** Mathematically binds tokens to a specific entity ID (`masterKey::entityId`).
- **Binary File Vault (`.zetoken`):** Encrypts documents, PDFs, and images into `.zetoken` containers and restores them bit-by-bit.
- **100% Interoperability:** Compatible bidirectionally with Zetoken implementations in **Python**, **PHP**, and **Node.js**.

---

## 📦 Installation & CDN Setup

### 🔹 Method 1: Direct Download (Self-Hosted) — *Recommended*

> [!TIP]
> **Why Self-Hosted?** For financial and privacy-critical applications, serving files from your own domain ensures 100% autonomy, enables offline/air-gapped operation, and eliminates third-party CDN supply-chain risks.

1. Download the two core files:
   - `zetoken-client.js` (Cryptographic Engine & Modal)
   - `style.css` (Scoped Glassmorphism Modal Styles)
2. Place them in your project structure:
   ```text
   my-web-app/
   ├── assets/
   │   ├── css/
   │   │   └── zetoken-style.css   <-- from style.css
   │   └── js/
   │       └── zetoken-client.js   <-- from zetoken-client.js
   └── index.html
   ```
3. Import them in your HTML:
   ```html
   <link rel="stylesheet" href="./assets/css/zetoken-style.css">
   <script src="./assets/js/zetoken-client.js"></script>
   ```

---

### 🔹 Method 2: jsDelivr CDN (Instant Cloud-Hosted)

Load the library directly via global CDN using release tag **`v1.0.1`**:

```html
<!-- Tagged Release v1.0.1 (Production Recommended) -->
<link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/anonputraid/zetoken-client@v1.0.1/style.css">
<script src="https://cdn.jsdelivr.net/gh/anonputraid/zetoken-client@v1.0.1/zetoken-client.js"></script>

<!-- Or latest commit from main branch -->
<link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/anonputraid/zetoken-client@main/style.css">
<script src="https://cdn.jsdelivr.net/gh/anonputraid/zetoken-client@main/zetoken-client.js"></script>

<!-- Auto-Minified via jsDelivr CDN -->
<script src="https://cdn.jsdelivr.net/gh/anonputraid/zetoken-client@v1.0.1/zetoken-client.min.js"></script>
```

> [!NOTE]
> **Style Isolation Guarantee:** `style.css` is strictly scoped under `.ztx-*`. It will **never** alter your page's `<body>`, `<button>`, fonts, or backgrounds.

---

## ⚡ Quickstart & Usage

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Zero-Knowledge App</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/anonputraid/zetoken-client@v1.0.1/style.css">
</head>
<body>

  <h1>My Confidential App</h1>
  <button onclick="saveSecretData()">Encrypt & Save</button>

  <script src="https://cdn.jsdelivr.net/gh/anonputraid/zetoken-client@v1.0.1/zetoken-client.js"></script>
  <script>
    // 1. Initialize client
    const ztx = new ZetokenClient({
      storageKey: 'my_app_keys',
      autoShowModal: true // Prompts modal if no key is found in localStorage
    });

    // 2. Encrypt sensitive data locally in the browser
    async function saveSecretData() {
      const plaintext = "Monthly Revenue: $125,000 | Profit: $42,000";
      
      const token = await ztx.encode(plaintext);
      console.log("Numeric Ciphertext ready for server:", token);

      // Send to server (server only sees ciphertext)
      // await fetch('/api/finance', { method: 'POST', body: JSON.stringify({ token }) });
    }

    // 3. Decrypt data received from server
    async function readSecretData(tokenFromServer) {
      const decrypted = await ztx.decode(tokenFromServer);
      console.log("Decrypted Plaintext:", decrypted);
    }
  </script>
</body>
</html>
```

---

## 🔑 Key Configuration File Format

Key files support `.key`, `.env`, or `.txt` formats with multi-line `key=value` pairs:

```env
# ==============================================================================
# Zetoken Cryptographic Configuration File
# Keep this file private. Never commit to public source control.
# ==============================================================================

ZETOKEN_ACCESS_KEY_ID="8347293847293847293847293847293847293847293847293"
ZETOKEN_SECRET_KEY="ZET/12345678/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmno="
ZETOKEN_ITERATIONS="1000"
```

> **Flexible Parser:** If custom key names are provided, the parser automatically combines the pairs and computes a deterministic, collision-resistant key pair.

---

## 📚 Complete API Reference

### Initialization

```javascript
const ztx = new ZetokenClient(options);
```

| Option | Type | Default | Description |
|---|---|---|---|
| `storageKey` | `string` | `'zetoken_active_config'` | Key name used in browser `localStorage` |
| `autoShowModal` | `boolean` | `true` | Automatically opens modal if no key is loaded |
| `throwOnError` | `boolean` | `false` | Throws exceptions instead of returning `false` |

---

### Core Encryption & Decryption

#### `encode(text, options)` / `encrypt(text, options)`
Encrypts plaintext string into a Zetoken numeric stream.

```javascript
const token = await ztx.encode("Confidential Information", {
  ttl: 300 // (Optional) Expire after 300 seconds (5 minutes)
});
```
- **Returns:** `Promise<string|false>`
- **Output Format:** 3-digit zero-padded decimal string (divisible by 3, min. 84 chars).

#### `decode(cipherText, options)` / `decrypt(cipherText, options)`
Decrypts a Zetoken numeric token back to plaintext.

```javascript
const text = await ztx.decode(token, {
  leeway: 60 // (Optional) Clock-skew tolerance in seconds (default: 60)
});
if (text === false) {
  console.error("Decryption failed: Token is invalid, expired, or tampered with.");
}
```
- **Returns:** `Promise<string|false>`

---

### 3-Layer Entity Sign

#### `sign(text, entityId, options)`
Cryptographically binds a token exclusively to a specific entity ID (`masterKey::entityId`).

```javascript
const boundToken = await ztx.sign("Transaction Invoice #9021", "USER-1002", {
  ttl: 600
});
```

#### `verifySign(token, entityId, options)`
Verifies and unlocks an entity-bound token.

```javascript
const verified = await ztx.verifySign(boundToken, "USER-1002");
if (verified !== false) {
  console.log("Verified Content:", verified);
} else {
  console.warn("Access Denied: Entity mismatch or tampered token.");
}
```

---

### File Vault (`.zetoken` Binary Encryption)

#### `encryptFile(file, options)`
Encrypts binary files (Images, PDFs, Spreadsheets, Documents) into a secure `.zetoken` container file.

```javascript
const fileInput = document.querySelector('#fileUpload');
const file = fileInput.files[0];

const result = await ztx.encryptFile(file, {
  download: true // (Default: true) Auto-downloads 'filename.ext.zetoken'
});

console.log("Container filename:", result.filename);
console.log("Encrypted size:", result.size);
```
- **Returns:** `Promise<Object|false>`:
  - `filename`: Generated `.zetoken` filename.
  - `originalName`: Original file name.
  - `mimeType`: Original MIME type.
  - `blob`: Binary `Blob` of `.zetoken` container.
  - `json`: Container JSON string.
  - `size`: Byte size of container.

#### `decryptFile(fileOrString, options)`
Decrypts a `.zetoken` file back into its exact original binary format, filename, and MIME type.

```javascript
const restored = await ztx.decryptFile(uploadedZetokenFile, {
  download: true // (Default: true) Auto-downloads restored original file
});

console.log("Restored name:", restored.originalName);
console.log("Restored MIME:", restored.mimeType);

// Live preview in browser (for images/receipts):
if (restored.mimeType.startsWith('image/')) {
  document.querySelector('#previewImage').src = restored.dataUrl;
}
```
- **Returns:** `Promise<Object|false>`:
  - `originalName`: Restored original file name.
  - `mimeType`: Restored MIME type.
  - `size`: Restored byte size.
  - `blob`: Restored `Blob` object.
  - `dataUrl`: Base64 DataURL (ready for `<img>` or `<iframe>` preview).

---

### Key & Onboarding Modal Management

```javascript
// Open onboarding modal
ztx.showKeyModal();

// Close modal
ztx.hideKeyModal();

// Check if an active key is loaded
const active = ztx.hasKey(); // true / false

// Retrieve sanitized active key metadata
const info = ztx.getActiveKeyInfo();
console.log(info.keyIdPreview); // e.g. "8347293847...7293"

// Download current key file
ztx.downloadKeyFile('my-zetoken.key');

// Purge keys from localStorage
ztx.clearConfig();
```

---

## 🗄️ Specification of the `.zetoken` File Container

The `.zetoken` file container is a structured JSON envelope:

```json
{
  "zetoken_format": "ZETOKEN_FILE_V1",
  "version": "1.0",
  "encrypted_at": "2026-09-05T19:00:00.000Z",
  "original_name_masked": "rec***",
  "payload": "166163190203033148174..."
}
```

The decrypted `payload` contains the complete original file structure:
```json
{
  "name": "financial_statement.pdf",
  "type": "application/pdf",
  "size": 184520,
  "lastModified": 1788619200000,
  "data": "data:application/pdf;base64,JVBERi0xLjQKJ..."
}
```

---

## 🔄 Cross-Habitat Interoperability Matrix

Zetoken Client is fully audited and tested bidirectionally across all habitats:

| Operation | Client (Browser) | Python Backend | PHP Backend | Node.js Backend |
|:---|:---:|:---:|:---:|:---:|
| **Client Encode** | ✅ Self | ✅ Decrypts | ✅ Decrypts | ✅ Decrypts |
| **Python Encode** | ✅ Decrypts | ✅ Self | ✅ Decrypts | ✅ Decrypts |
| **PHP Encode** | ✅ Decrypts | ✅ Decrypts | ✅ Self | ✅ Decrypts |
| **Node.js Encode** | ✅ Decrypts | ✅ Decrypts | ✅ Decrypts | ✅ Self |
| **3-Layer Entity Sign** | ✅ Verified | ✅ Verified | ✅ Verified | ✅ Verified |
| **File Vault (`.zetoken`)** | ✅ Bit-for-Bit | N/A (JSON Envelope) | N/A (JSON Envelope) | N/A (JSON Envelope) |

---

## 🖥️ Interactive Demo Dashboard

Explore all features visually by opening `client/index.html` in your browser:
- **Tab 1: Enkripsi (Encode):** Live encryption with component breakdown (IV, Tag, Ciphertext).
- **Tab 2: Dekripsi (Decode):** Decryption with real-time TTL clock-skew verification.
- **Tab 3: Entity Sign:** 3-Layer sign/verify testing with simulated attacker rejection.
- **Tab 4: Uji Silang Backend:** Live decryption buttons for tokens generated by **Python**, **Node.js**, and **PHP**.
- **Tab 5: File Vault (`.zetoken`):** Drag-and-drop encryption & restoration with image previews.

---

## 📄 License

MIT License. Free for open-source and commercial use.
