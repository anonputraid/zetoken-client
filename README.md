# Zetoken Client (Browser / Pure Vanilla JavaScript)

Official client-side implementation of the **Zetoken** cryptographic algorithm built with **Pure Vanilla JavaScript** (zero external runtime dependencies). This library leverages the browser-native **Web Crypto API** for high-speed authenticated encryption, offering 100% interoperability with Zetoken backend implementations in **Python**, **Node.js**, and **PHP**.

---

## 🛡️ Security Philosophy & Threat Model

### 1. The Critical Flaw in Conventional Paradigms (Server-Side Encryption)

In traditional web applications, sensitive user data is submitted from the browser as plaintext (or protected only by SSL/TLS in transit) and encrypted at the server level using secret keys stored in the server's `.env` configuration.

**Catastrophic Compromise Scenario:**
If an attacker discovers a common web vulnerability (e.g., Local File Inclusion, Remote Code Execution, arbitrary file upload, or SQL Injection):
1. The attacker gains shell access with `www-data` privileges (the standard web server process user for Nginx/Apache).
2. Under `www-data`, the attacker possesses read access to the **server's `.env` file** and database connection credentials.
3. The attacker dumps the entire database table and decrypts all records using the leaked `.env` keys.
4. **Outcome:** A total data breach occurs. Every user record is exposed in plain text.

---

### 2. The Zetoken Client Solution: Zero-Knowledge Client-Side Encryption (CSE)

Zetoken Client eliminates this single point of failure by enforcing a **Zero-Knowledge Data-at-Rest** model:

```text
[ USER BROWSER ]                                        [ SERVER / DATABASE ]
       │                                                         │
 1. User inputs confidential data                                │
       │                                                         │
 2. Browser encrypts locally via                                 │
    zetoken-client.js (Key in localStorage)                      │
       │                                                         │
 3. Send numeric token (Ciphertext) ──── HTTP POST ────────────> │
                                                            4. Store numeric token
                                                               into Database
                                                                 │
 6. Receive numeric token           <─── HTTP GET ────────────── 5. Query stored token
       │
 7. Browser decrypts locally via
    key held in localStorage
       │
 8. Plaintext displayed to user
```

**Key Security Advantages During a Server Breach:**
- **Keys Never Touch the Server:** Cryptographic keys reside exclusively on the client side (uploaded via the onboarding modal and preserved in the user's browser `localStorage`), never written to `.env` and never saved in the database.
- **Server Only Sees Ciphertext:** The backend and database only ever process randomized Zetoken numeric streams (`226243233014...`).
- **Immune to `www-data` Server Compromises:** Even if an attacker gains root or `www-data` access, reads `.env`, and exfiltrates the entire database, they **CANNOT** decrypt the data because the AES-128-GCM keys do not exist on the server.
- **Zero Liability for Service Providers:** The hosting provider does not store raw unencrypted personally identifiable information (PII), protecting business owners from negligence claims in data breaches.

---

### 3. "Your Keys, Your Data" Principle & Boundaries of Responsibility

This strict separation of duties places complete ownership and control in the hands of the end user:
- **Lost Key = Irretrievable Data:** Because the server possesses no backdoor and no master recovery key, losing a `.key` file means the encrypted data in the database can never be recovered by anyone.
- **Key Hygiene:** Users are responsible for preserving their `.key` files securely (e.g., encrypted flash drives, offline storage, or password managers).

---

### 4. Frontend Security Best Practices

Because the active key resides in browser memory and `localStorage`, the primary threat surface shifts from the server to the client browser (specifically Cross-Site Scripting / XSS). To ensure maximum security:
1. **Enforce a Strict Content Security Policy (CSP):** Disallow execution of untrusted third-party scripts to prevent unauthorized scripts from accessing `localStorage`.
2. **Sanitize All HTML Inputs:** Prevent XSS injection vectors.
3. **Provide Key Reset for Shared Terminals:** For public or shared office workstations, always provide an explicit **"Reset / Clear Key"** option to purge keys from `localStorage` upon logout.

---

## 🚀 Key Features

1. **Pure Vanilla JavaScript (Zero Dependencies):** No bundlers (Webpack, Vite) or runtime dependencies required. Runs directly in any modern browser via a simple `<script>` tag.
2. **W3C Standard Cryptography (Web Crypto API):**
   - **KDF:** PBKDF2 with `SHA-512` digest (128-bit derived symmetric key).
   - **Cipher:** `AES-128-GCM` with a cryptographically secure 12-byte CSPRNG IV per encryption.
   - **Auth Tag:** 16-byte GCM authentication tag preventing any tampering or data manipulation.
   - **Serialization:** 3-digit zero-padded decimal string stream (`000` to `255`), URL-safe, WebSocket-safe, and free of special characters or Base64 padding issues.
3. **Multi-Line Key Parser (`key=value`):**
   - Supports standard `ZETOKEN_*` environment files as well as custom multi-line key-value configurations.
   - Resiliently ignores comments (`#`, `//`, `;`) and empty lines.
   - Auto-saves and restores configuration from browser `localStorage`.
4. **Interactive Fullscreen Onboarding Modal:**
   - Automatically prompts the user on startup if no active key exists in `localStorage`.
   - **Upload:** Drag-and-drop or file picker for `.key`, `.env`, or `.txt` files.
   - **1-Click Generator:** Generates a cryptographically secure key file and automatically triggers an immediate local download while storing it in the browser.
   - **Manual Paste:** Instant text input for direct key configuration.
5. **Time-Bound Tokens (TTL):** Built-in token expiration with configurable clock-skew leeway (default: 60s).
6. **3-Layer Entity Sign & Verification:** Mathematically binds tokens to a specific User ID, Device ID, or Invoice ID (`masterKey::entityId`).
7. **100% Cross-Habitat Interoperability:** Tokens encrypted in the browser can be decrypted in **Python**, **PHP**, and **Node.js**, and vice versa.
8. **Document & Binary File Vault (`.zetoken` Format):** Encrypts files (PDF invoices, receipt photos, spreadsheets) into `.zetoken` encrypted container files that can be decrypted back to their exact original bytes, MIME type, and filename.

---

## 📦 Installation & Usage Guides

You can integrate `zetoken-client` using either of the two methods below:

### 🔹 Method 1: Direct Download (Self-Hosted / Offline Ready) — *Recommended*

> [!TIP]
> **Why is this the best choice?** For security and financial applications, serving JS and CSS files from your own domain guarantees 100% autonomy, works seamlessly in offline or air-gapped environments, and completely eliminates third-party supply-chain risks.

1. Download the 2 core files from the `client/` folder:
   - `zetoken-client.js` (Web Crypto logic, Onboarding Modal, File Vault)
   - `style.css` (Glassmorphism dark theme UI styles)
2. Place them into your project's frontend assets directory:
   ```text
   my-web-app/
   ├── assets/
   │   ├── css/
   │   │   └── zetoken-style.css   <-- from style.css
   │   └── js/
   │       └── zetoken-client.js   <-- from zetoken-client.js
   └── index.html
   ```
3. Include them in your HTML document:
   ```html
   <!DOCTYPE html>
   <html lang="en">
   <head>
     <meta charset="UTF-8">
     <title>My Zero-Knowledge Web App</title>
     <!-- 1. Local CSS -->
     <link rel="stylesheet" href="./assets/css/zetoken-style.css">
   </head>
   <body>

     <!-- 2. Local Library Script -->
     <script src="./assets/js/zetoken-client.js"></script>
     <script>
       // Initialize Zetoken Client
       const ztx = new ZetokenClient({
         storageKey: 'zetoken_active_config',
         autoShowModal: true // Automatically opens modal if no key is loaded
       });

       async function saveNote(plaintext) {
         // Encrypt locally in browser before sending to backend database
         const ciphertextToken = await ztx.encode(plaintext);
         console.log("Ciphertext ready to send:", ciphertextToken);
       }
     </script>
   </body>
   </html>
   ```

---

### 🔹 Method 2: jsDelivr CDN (Instant Cloud-Hosted)

If you prefer to load the library directly without downloading files manually (e.g., for rapid prototyping, CodePen, or cloud demos), you can load it from **jsDelivr CDN**:

#### Via NPM on jsDelivr:
```html
<!-- CSS from jsDelivr CDN -->
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/zetoken-client@1.0.0/style.css">

<!-- JS from jsDelivr CDN -->
<script src="https://cdn.jsdelivr.net/npm/zetoken-client@1.0.0/zetoken-client.js"></script>
```

#### Via GitHub Repository on jsDelivr:
```html
<!-- Format: https://cdn.jsdelivr.net/gh/<username>/<repo>@<version_or_branch>/<path> -->
<link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/Anonputraid/zetoken@v1.0.0/client/style.css">
<script src="https://cdn.jsdelivr.net/gh/Anonputraid/zetoken@v1.0.0/client/zetoken-client.js"></script>
```

> [!NOTE]
> **CDN Security Best Practice:** When loading cryptographic libraries from a CDN in production environments, always include the `integrity="sha384-..."` (Subresource Integrity / SRI) attribute to verify that the fetched script has not been modified in transit.

---

### Full Application Flow Example

```javascript
// 1. Initialize client
const ztx = new ZetokenClient({
  storageKey: 'zetoken_active_config',
  autoShowModal: true
});

// 2. Encrypt & Save Data (Client-Side Encryption)
async function saveSecretRecord(plaintextRecord) {
  // Data is encrypted in user's browser memory
  const numericToken = await ztx.encode(plaintextRecord);

  // Send ciphertext to server (server and DB admin cannot read the content)
  await fetch('/api/records', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ payload: numericToken })
  });
}

// 3. Retrieve & Decrypt Data (Client-Side Decryption)
async function readSecretRecord(recordId) {
  const response = await fetch(`/api/records/${recordId}`);
  const data = await response.json();

  // Decrypt token locally in browser memory
  const originalPlaintext = await ztx.decode(data.payload);
  return originalPlaintext;
}
```

---

## 🔑 Key Configuration File Format (`key=value`)

Key files can use `.key`, `.env`, or `.txt` extensions with multi-line key-value pairs:

```env
# ==============================================================================
# Zetoken Cryptographic Configuration File
# Keep this file secure and private. Never commit to public repositories.
# ==============================================================================

ZETOKEN_ACCESS_KEY_ID="8347293847293847293847293847293847293847293847293"
ZETOKEN_SECRET_KEY="ZET/12345678/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmno="
ZETOKEN_ITERATIONS="1000"
```

> **Parser Flexibility:** If you upload a custom configuration without `ZETOKEN_*` variable names, the parser automatically combines the available key-value pairs and derives a deterministic, collision-resistant key pair.

---

## 📚 API Reference

### Initialization

```javascript
const ztx = new ZetokenClient(options);
```

| Option | Type | Default | Description |
|---|---|---|---|
| `storageKey` | `string` | `'zetoken_active_config'` | Key name in browser `localStorage` |
| `autoShowModal` | `boolean` | `true` | Automatically opens modal if no key exists |
| `throwOnError` | `boolean` | `false` | Throws errors instead of returning `false` |

---

### `encode(text, options)` / `encrypt(text, options)`

Encrypts a plaintext string into a Zetoken numeric token.

```javascript
const token = await ztx.encode("Confidential Financial Record", {
  ttl: 300 // (Optional) Expires in 300 seconds (5 minutes)
});
```

- **Returns:** `Promise<string|false>`
- **Output:** Decimal string (length divisible by 3, minimum 84 characters).

---

### `decode(cipherText, options)` / `decrypt(cipherText, options)`

Decrypts a Zetoken numeric token back to plaintext.

```javascript
const plaintext = await ztx.decode(token, {
  leeway: 60 // (Optional) Clock skew tolerance in seconds (default: 60)
});

if (plaintext === false) {
  console.log("Token is invalid, tampered with, or expired!");
}
```

- **Returns:** `Promise<string|false>`

---

### `sign(text, entityId, options)`

Binds a token cryptographically to a specific entity (e.g., `USER-1002`). The token cannot be decrypted by any other entity even with the same master access key.

```javascript
const boundToken = await ztx.sign("Transaction Ticket", "USER-1002", {
  ttl: 600
});
```

---

### `verifySign(token, entityId, options)`

Decrypts and verifies an entity-bound token.

```javascript
const verified = await ztx.verifySign(boundToken, "USER-1002");
if (verified !== false) {
  console.log("Valid token for User-1002:", verified);
} else {
  console.log("Access Denied: Entity mismatch or invalid token.");
}
```

---

### `encryptFile(file, options)`

Encrypts binary files (Images, PDFs, Spreadsheets, Docs) into `.zetoken` format.

```javascript
// file from <input type="file"> or dropzone event
const fileInput = document.querySelector('#myFileInput');
const file = fileInput.files[0];

const result = await ztx.encryptFile(file, {
  download: true // (Default: true) Automatically triggers browser download
});

console.log("Output filename:", result.filename); // e.g., "financial_report.pdf.zetoken"
console.log("Container size:", result.size);
```

- **Returns:** `Promise<Object|false>`:
  - `filename`: Encrypted filename with `.zetoken` extension
  - `originalName`: Original file name
  - `mimeType`: Original MIME type
  - `blob`: Binary `Blob` of `.zetoken` container
  - `json`: Raw JSON container string
  - `size`: Byte size of container

---

### `decryptFile(fileOrString, options)`

Decrypts a `.zetoken` file back into its original file format (name, MIME type, and binary content 100% intact).

```javascript
// fileZetoken is a .zetoken File or Blob uploaded by the user
const restored = await ztx.decryptFile(fileZetoken, {
  download: true // (Default: true) Automatically downloads restored file
});

console.log("Restored name:", restored.originalName); // e.g., "financial_report.pdf"
console.log("MIME type:", restored.mimeType);         // e.g., "application/pdf"
console.log("Restored size:", restored.size);

// Live preview in browser (for images/receipts):
if (restored.mimeType.startsWith('image/')) {
  document.querySelector('#previewImg').src = restored.dataUrl;
}
```

- **Returns:** `Promise<Object|false>`:
  - `originalName`: Restored original filename
  - `mimeType`: Restored original MIME type
  - `size`: Restored byte size
  - `blob`: Restored `Blob` object
  - `dataUrl`: Base64 DataURL (ready for `<img>` or `<iframe>` preview)

---

### Key & Modal Management Methods

```javascript
// Open onboarding / key management modal
ztx.showKeyModal();

// Close modal
ztx.hideKeyModal();

// Check if an active key is loaded
console.log(ztx.hasKey()); // true / false

// Retrieve sanitized active key metadata
const info = ztx.getActiveKeyInfo();
console.log(info.keyIdPreview); // e.g., "8347293847...7293"

// Download current key configuration as a file
ztx.downloadKeyFile('my-zetoken.key');

// Purge keys from browser localStorage
ztx.clearConfig();
```

---

## 🗄️ Specification of the `.zetoken` File Container

The `.zetoken` file is a structured, encrypted envelope containing:

```json
{
  "zetoken_format": "ZETOKEN_FILE_V1",
  "version": "1.0",
  "encrypted_at": "2026-09-05T19:00:00.000Z",
  "original_name_masked": "rec***",
  "payload": "166163190203033148174..."
}
```

Inside the encrypted `payload` (AES-128-GCM):
```json
{
  "name": "receipt_august_2026.png",
  "type": "image/png",
  "size": 245820,
  "lastModified": 1788619200000,
  "data": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA..."
}
```

---

## 🔄 Cross-Habitat Interoperability Matrix

Zetoken Client is fully tested and verified against all backend implementations:

| Operation | Client (Browser) | Python Backend | PHP Backend | Node.js Backend |
|---|:---:|:---:|:---:|:---:|
| **Client Encode** | ✅ Self | ✅ Decrypts | ✅ Decrypts | ✅ Decrypts |
| **Python Encode** | ✅ Decrypts | ✅ Self | ✅ Decrypts | ✅ Decrypts |
| **PHP Encode** | ✅ Decrypts | ✅ Decrypts | ✅ Self | ✅ Decrypts |
| **Node.js Encode** | ✅ Decrypts | ✅ Decrypts | ✅ Decrypts | ✅ Self |
| **3-Layer Entity Sign** | ✅ Verified | ✅ Verified | ✅ Verified | ✅ Verified |
| **File Vault (.zetoken)**| ✅ Bit-for-Bit | N/A (JSON Envelope) | N/A (JSON Envelope) | N/A (JSON Envelope) |

---

## 🖥️ Running the Interactive Demo Dashboard

Open `client/index.html` directly in any web browser to explore:
- Onboarding modal workflow (Key Upload & 1-Click Generator).
- Real-time encryption with visual binary component breakdown (IV, Tag, Ciphertext).
- Decryption with real-time TTL validity and clock-skew checking.
- 3-Layer Entity Sign & Verify simulation with simulated attacker rejection.
- Live cross-test decryption verifying tokens generated by **Python**, **Node.js**, and **PHP**.
- The **File Vault** for encrypting and restoring binary files into `.zetoken` format.

---

## 📄 License

MIT License. Free for open-source and commercial use.
