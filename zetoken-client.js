/**
 * ============================================================================
 * ZETOKEN CLIENT-SIDE CRYPTOGRAPHIC LIBRARY (VANILLA JAVASCRIPT)
 * ============================================================================
 * Standard-compliant, zero-dependency client-side cryptographic library for
 * generating, parsing, encrypting, and decrypting Zetoken tokens in browsers.
 * 
 * Cryptographic Standard:
 * - KDF    : PBKDF2 with SHA-512 (128-bit derived key)
 * - Cipher : AES-128-GCM (Authenticated Encryption with Associated Data)
 * - Nonce  : 12-byte CSPRNG IV
 * - Tag    : 16-byte GCM Authentication Tag
 * - Stream : 3-digit zero-padded decimal string per byte (000-255)
 * 
 * 100% Interoperable with PHP, Python, and Node.js Zetoken implementations.
 * ============================================================================
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.ZetokenClient = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  class ZetokenClient {
    /**
     * @param {Object} options
     * @param {string} [options.storageKey='zetoken_active_config'] - LocalStorage key name
     * @param {boolean} [options.autoShowModal=true] - Auto-open modal if no key is stored
     * @param {boolean} [options.throwOnError=false] - Throw errors instead of returning false
     */
    constructor(options = {}) {
      this.storageKey = options.storageKey || 'zetoken_active_config';
      this.autoShowModal = options.autoShowModal !== false;
      this.throwOnError = !!options.throwOnError;
      this.config = null;
      this.cryptoKeyCache = new Map();

      // Initialize active configuration from LocalStorage
      this.loadConfig();

      // Initialize Modal UI if running in a browser environment
      if (typeof window !== 'undefined' && typeof document !== 'undefined') {
        if (document.readyState === 'loading') {
          document.addEventListener('DOMContentLoaded', () => this._onDocumentReady());
        } else {
          this._onDocumentReady();
        }
      }
    }

    _onDocumentReady() {
      this._injectModalUI();
      if (!this.hasKey() && this.autoShowModal) {
        this.showKeyModal();
      }
    }

    // ========================================================================
    // 1. KEY MANAGEMENT (STORAGE & PARSER)
    // ========================================================================

    /**
     * Parses multi-line key=value configuration text into a structured config object.
     * Resilient: Ignores comments (#, //, ;), blank lines, and whitespace.
     * Automatically extracts and deterministically derives keys if custom key names are used.
     * 
     * @param {string} rawText
     * @returns {Object} Parsed configuration object
     */
    parseKeyConfig(rawText) {
      if (!rawText || typeof rawText !== 'string') {
        throw new Error("Key file content is empty or invalid.");
      }

      const lines = rawText.split(/\r?\n/);
      const parsedMap = {};
      let pairCount = 0;

      for (let line of lines) {
        line = line.trim();
        // Skip comments and empty lines
        if (!line || line.startsWith('#') || line.startsWith('//') || line.startsWith(';')) {
          continue;
        }

        const eqIdx = line.indexOf('=');
        if (eqIdx === -1) continue;

        const k = line.substring(0, eqIdx).trim();
        let v = line.substring(eqIdx + 1).trim();

        // Strip surrounding quotes if present (" or ')
        if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
          v = v.substring(1, v.length - 1);
        }

        if (k) {
          parsedMap[k] = v;
          pairCount++;
        }
      }

      if (pairCount === 0) {
        throw new Error("No valid 'key=value' line pairs found in file.");
      }

      // 1. Check for standard Zetoken variable names
      let accessKey = parsedMap['ZETOKEN_ACCESS_KEY_ID'] || parsedMap['ACCESS_KEY_ID'] || parsedMap['ACCESS_KEY'] || null;
      let secretKey = parsedMap['ZETOKEN_SECRET_KEY'] || parsedMap['SECRET_KEY'] || parsedMap['MASTER_SECRET'] || null;
      let iterations = parseInt(parsedMap['ZETOKEN_ITERATIONS'] || parsedMap['ITERATIONS'] || '1000', 10);

      if (isNaN(iterations) || iterations < 1) {
        iterations = 1000;
      }

      // 2. If non-standard names, derive keys deterministically from composite key=value pairs
      if (!accessKey || !secretKey) {
        const sortedKeys = Object.keys(parsedMap).sort();
        let compositeStr = "";
        for (let key of sortedKeys) {
          compositeStr += `${key}=${parsedMap[key]};`;
        }

        accessKey = accessKey || this._deterministicDigits(compositeStr, 49);
        secretKey = secretKey || `ZET/${this._deterministicDigits(compositeStr + '_sec', 8)}/${this._deterministicBase64(compositeStr, 43)}`;
      }

      return {
        raw: rawText,
        map: parsedMap,
        keyId: accessKey,
        secretKey: secretKey,
        iterations: iterations,
        pairCount: pairCount,
        updatedAt: new Date().toISOString()
      };
    }

    /**
     * Loads active key configuration from browser LocalStorage
     * @returns {Object|null}
     */
    loadConfig() {
      if (typeof localStorage === 'undefined') return null;
      try {
        const stored = localStorage.getItem(this.storageKey);
        if (stored) {
          this.config = this.parseKeyConfig(stored);
          this.cryptoKeyCache.clear();
          return this.config;
        }
      } catch (err) {
        console.warn("[ZetokenClient] Failed to load key from localStorage:", err);
        this.config = null;
      }
      return null;
    }

    /**
     * Saves raw configuration text into LocalStorage and updates active state.
     * @param {string} rawText 
     * @returns {Object} Parsed configuration
     */
    saveConfig(rawText) {
      const parsed = this.parseKeyConfig(rawText);
      if (typeof localStorage !== 'undefined') {
        localStorage.setItem(this.storageKey, rawText);
      }
      this.config = parsed;
      this.cryptoKeyCache.clear();

      this._dispatchCustomEvent('zetoken:key-updated', { config: parsed });
      return parsed;
    }

    /**
     * Clears active configuration from LocalStorage and memory.
     */
    clearConfig() {
      if (typeof localStorage !== 'undefined') {
        localStorage.removeItem(this.storageKey);
      }
      this.config = null;
      this.cryptoKeyCache.clear();

      this._dispatchCustomEvent('zetoken:key-cleared', {});
    }

    /**
     * Checks whether an active key configuration is currently loaded.
     * @returns {boolean}
     */
    hasKey() {
      return !!(this.config && this.config.keyId && this.config.secretKey);
    }

    /**
     * Retrieves sanitized metadata of the active key for UI display.
     * @returns {Object|null}
     */
    getActiveKeyInfo() {
      if (!this.hasKey()) return null;
      return {
        keyIdPreview: this.config.keyId.substring(0, 10) + '...' + this.config.keyId.slice(-6),
        fullKeyId: this.config.keyId,
        iterations: this.config.iterations,
        pairCount: this.config.pairCount,
        updatedAt: this.config.updatedAt
      };
    }

    /**
     * Generates fresh, cryptographically secure key file content.
     * @returns {string} Raw configuration text
     */
    generateNewKeyFile() {
      const accessKey = this._generateSecureDigits(49);
      const random8 = this._generateSecureDigits(8);
      const randomBase64 = this._generateSecureBase64(43);
      const secretKey = `ZET/${random8}/${randomBase64}`;
      const iterations = this._generateSecureIterations();
      const clientId = 'ztx-client-' + this._generateSecureDigits(6);

      const content = [
        `# ==============================================================================`,
        `# Zetoken Cryptographic Configuration File`,
        `# Generated: ${new Date().toISOString()}`,
        `# Keep this file secure and private. Do NOT expose to public repositories.`,
        `# ==============================================================================`,
        ``,
        `ZETOKEN_ACCESS_KEY_ID="${accessKey}"`,
        `ZETOKEN_SECRET_KEY="${secretKey}"`,
        `ZETOKEN_ITERATIONS="${iterations}"`,
        `ZETOKEN_CLIENT_ID="${clientId}"`,
        `ZETOKEN_ENCRYPTION="AES-128-GCM"`,
        `ZETOKEN_KDF="PBKDF2-HMAC-SHA512"`,
        ``
      ].join('\n');

      return content;
    }

    /**
     * Triggers browser download of active (or freshly generated) key file.
     * @param {string} [filename='zetoken-client.key']
     */
    downloadKeyFile(filename = 'zetoken-client.key') {
      let content = this.config ? this.config.raw : this.generateNewKeyFile();
      const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }

    // ========================================================================
    // 2. CORE CRYPTOGRAPHY ENGINE (WEB CRYPTO API)
    // ========================================================================

    _utf8ToBytes(str) {
      return new TextEncoder().encode(str);
    }

    _bytesToUtf8(bytes) {
      return new TextDecoder().decode(bytes);
    }

    _getCrypto() {
      if (typeof window !== 'undefined' && window.crypto) return window.crypto;
      if (typeof globalThis !== 'undefined' && globalThis.crypto) return globalThis.crypto;
      if (typeof self !== 'undefined' && self.crypto) return self.crypto;
      throw new Error("Web Crypto API is not supported in this environment.");
    }

    /**
     * Symmetric Key Derivation using PBKDF2-HMAC-SHA512 (128-bit key)
     */
    async _deriveCryptographicKey(keyId, secretKey, iterations) {
      const cacheKey = `${keyId}::${secretKey}::${iterations}`;
      if (this.cryptoKeyCache.has(cacheKey)) {
        return this.cryptoKeyCache.get(cacheKey);
      }

      const cryptoObj = this._getCrypto();
      const subtle = cryptoObj.subtle;
      const secretBytes = this._utf8ToBytes(secretKey);
      const saltBytes = this._utf8ToBytes(keyId);

      // Import Secret Key as base key for PBKDF2
      const baseKey = await subtle.importKey(
        'raw',
        secretBytes,
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
      );

      // Derive 128-bit AES-GCM CryptoKey
      const aesKey = await subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: saltBytes,
          iterations: iterations,
          hash: 'SHA-512'
        },
        baseKey,
        { name: 'AES-GCM', length: 128 },
        false,
        ['encrypt', 'decrypt']
      );

      this.cryptoKeyCache.set(cacheKey, aesKey);
      return aesKey;
    }

    /**
     * Resolves key parameters with fallback to currently active config.
     */
    _resolveKeys(customKeyId, customSecretKey) {
      const keyId = customKeyId || (this.config ? this.config.keyId : null);
      const secretKey = customSecretKey || (this.config ? this.config.secretKey : null);
      const iterations = (this.config ? this.config.iterations : 1000) || 1000;

      return [keyId, secretKey, iterations];
    }

    /**
     * Encrypts plaintext string into a Zetoken numeric token (3-digit decimal stream).
     * 
     * @param {string} text - Plain text to encrypt
     * @param {Object} [options]
     * @param {string} [options.keyId] - Optional Key ID override
     * @param {string} [options.secretKey] - Optional Secret Key override
     * @param {number} [options.ttl] - Optional Time-to-live in seconds
     * @returns {Promise<string|false>} Numeric token string or false on failure
     */
    async encode(text, options = {}) {
      try {
        if (typeof text !== 'string') {
          text = String(text);
        }

        const [keyId, secretKey, iterations] = this._resolveKeys(options.keyId, options.secretKey);
        if (!keyId || !secretKey) {
          throw new Error("Key is not configured. Please upload or generate a key first.");
        }

        // Handle Time-To-Live (TTL) expiration suffix
        let payloadText = text;
        if (options.ttl && typeof options.ttl === 'number' && options.ttl > 0) {
          const expTime = Math.floor(Date.now() / 1000) + options.ttl;
          payloadText = `${text}__ZTX__${expTime}`;
        }

        // Derive AES-GCM Key
        const aesKey = await this._deriveCryptographicKey(keyId, secretKey, iterations);

        // Generate cryptographically secure 12-byte IV (Nonce)
        const cryptoObj = this._getCrypto();
        const iv = cryptoObj.getRandomValues(new Uint8Array(12));

        // AES-GCM encryption via Web Crypto API
        const textBytes = this._utf8ToBytes(payloadText);
        const encryptedBuffer = await cryptoObj.subtle.encrypt(
          { name: 'AES-GCM', iv: iv },
          aesKey,
          textBytes
        );

        const encryptedBytes = new Uint8Array(encryptedBuffer);

        // Web Crypto API appends the 16-byte authentication tag at the end
        const actualCiphertext = encryptedBytes.slice(0, encryptedBytes.length - 16);
        const tag = encryptedBytes.slice(encryptedBytes.length - 16);

        // Standard Zetoken Wire Format: [12B IV] + [16B TAG] + [N-B CIPHERTEXT]
        const finalPayload = new Uint8Array(12 + 16 + actualCiphertext.length);
        finalPayload.set(iv, 0);
        finalPayload.set(tag, 12);
        finalPayload.set(actualCiphertext, 28);

        // Serialize binary payload into 3-digit zero-padded decimal stream
        let numericResult = '';
        for (let i = 0; i < finalPayload.length; i++) {
          numericResult += finalPayload[i].toString().padStart(3, '0');
        }

        return numericResult;
      } catch (err) {
        if (this.throwOnError) throw err;
        console.error("[ZetokenClient] Encryption failed:", err.message);
        return false;
      }
    }

    // Intuitive alias
    async encrypt(text, options = {}) {
      return this.encode(text, options);
    }

    /**
     * Decrypts Zetoken numeric token string back into original plaintext.
     * 
     * @param {string} cipherText - Numeric Zetoken token string
     * @param {Object} [options]
     * @param {string} [options.keyId] - Optional Key ID override
     * @param {string} [options.secretKey] - Optional Secret Key override
     * @param {number} [options.leeway=60] - Clock skew leeway in seconds
     * @returns {Promise<string|false>} Decrypted string or false on failure/tampering/expiry
     */
    async decode(cipherText, options = {}) {
      try {
        if (!cipherText || typeof cipherText !== 'string') {
          return false;
        }

        const [keyId, secretKey, iterations] = this._resolveKeys(options.keyId, options.secretKey);
        if (!keyId || !secretKey) {
          throw new Error("Key is not configured.");
        }

        const leeway = typeof options.leeway === 'number' ? options.leeway : 60;

        // Validate numeric stream: all digits and length divisible by 3
        if (cipherText.length % 3 !== 0 || !/^\d+$/.test(cipherText)) {
          return false;
        }

        // Reconstruct binary bytes from 3-digit chunks
        const totalBytes = cipherText.length / 3;
        if (totalBytes < 28) {
          // Minimum wire length: 12-byte IV + 16-byte Tag
          return false;
        }

        const decodedBytes = new Uint8Array(totalBytes);
        for (let i = 0; i < cipherText.length; i += 3) {
          decodedBytes[i / 3] = parseInt(cipherText.substring(i, i + 3), 10);
        }

        // Extract binary components per Zetoken specification
        const iv = decodedBytes.slice(0, 12);
        const tag = decodedBytes.slice(12, 28);
        const actualCiphertext = decodedBytes.slice(28);

        // Reconstruct Web Crypto API input buffer: [ciphertext] + [tag]
        const webCryptoPayload = new Uint8Array(actualCiphertext.length + 16);
        webCryptoPayload.set(actualCiphertext, 0);
        webCryptoPayload.set(tag, actualCiphertext.length);

        const aesKey = await this._deriveCryptographicKey(keyId, secretKey, iterations);

        // Decrypt and authenticate using Web Crypto API
        const cryptoObj = this._getCrypto();
        const decryptedBuffer = await cryptoObj.subtle.decrypt(
          { name: 'AES-GCM', iv: iv },
          aesKey,
          webCryptoPayload
        );

        const decryptedText = this._bytesToUtf8(new Uint8Array(decryptedBuffer));

        // Evaluate Time-To-Live (TTL) expiration
        const pos = decryptedText.lastIndexOf('__ZTX__');
        if (pos !== -1) {
          const expString = decryptedText.substring(pos + 7);
          if (/^\d+$/.test(expString)) {
            const expTime = parseInt(expString, 10);
            const currentTime = Math.floor(Date.now() / 1000);

            if ((currentTime - leeway) > expTime) {
              if (this.throwOnError) throw new Error("Token has expired.");
              return false;
            }

            return decryptedText.substring(0, pos);
          }
        }

        return decryptedText;
      } catch (err) {
        if (this.throwOnError) throw err;
        return false;
      }
    }

    // Intuitive alias
    async decrypt(cipherText, options = {}) {
      return this.decode(cipherText, options);
    }

    /**
     * 3-Layer Entity Sign: Cryptographically binds token exclusively to an entity ID
     * 
     * @param {string} text - Plain text data
     * @param {string} entityId - Unique identifier (User ID, Device ID, Invoice ID, etc.)
     * @param {Object} [options]
     * @returns {Promise<string|false>} Signed numeric token
     */
    async sign(text, entityId, options = {}) {
      if (!entityId) return false;
      const [masterAccessKey] = this._resolveKeys();
      if (!masterAccessKey) return false;

      const layeredKeyId = `${masterAccessKey}::${entityId}`;
      return this.encode(text, { ...options, keyId: layeredKeyId });
    }

    /**
     * 3-Layer Entity Verification: Unlocks and verifies an entity-bound token
     * 
     * @param {string} token - Numeric token
     * @param {string} entityId - Matching entity identifier
     * @param {Object} [options]
     * @returns {Promise<string|false>} Verified plaintext or false on mismatch
     */
    async verifySign(token, entityId, options = {}) {
      if (!entityId) return false;
      const [masterAccessKey] = this._resolveKeys();
      if (!masterAccessKey) return false;

      const layeredKeyId = `${masterAccessKey}::${entityId}`;
      return this.decode(token, { ...options, keyId: layeredKeyId });
    }

    // ========================================================================
    // 2.5. FILE CRYPTOGRAPHY (.ZETOKEN FORMAT)
    // ========================================================================

    /**
     * Encrypts binary files (Images, PDFs, Spreadsheets, Docs) into `.zetoken` format.
     * 
     * @param {File|Blob} file - File object from file input or dropzone
     * @param {Object} [options]
     * @param {boolean} [options.download=true] - Auto-trigger browser download
     * @param {string} [options.customFilename] - Custom output filename
     * @param {number} [options.ttl] - Optional TTL expiration in seconds
     * @returns {Promise<Object|false>} Encrypted file container or false on failure
     */
    async encryptFile(file, options = {}) {
      try {
        if (!file || (!(file instanceof Blob) && typeof file.arrayBuffer !== 'function')) {
          throw new Error("File is invalid or not selected.");
        }

        const base64Data = await this._fileToBase64(file);
        const originalName = file.name || 'unnamed_file.bin';
        const mimeType = file.type || 'application/octet-stream';
        const originalSize = file.size || 0;

        // Pack metadata and binary payload into encrypted envelope
        const envelope = JSON.stringify({
          name: originalName,
          type: mimeType,
          size: originalSize,
          lastModified: file.lastModified || Date.now(),
          data: base64Data
        });

        // Encrypt envelope using Zetoken AES-128-GCM
        const tokenPayload = await this.encode(envelope, options);
        if (!tokenPayload) {
          throw new Error("Failed to encrypt file content.");
        }

        // Construct .zetoken container object
        const zetokenContainer = {
          zetoken_format: "ZETOKEN_FILE_V1",
          version: "1.0",
          encrypted_at: new Date().toISOString(),
          original_name_masked: originalName.length > 4 ? originalName.substring(0, 3) + '***' : '***',
          payload: tokenPayload
        };

        const containerJson = JSON.stringify(zetokenContainer, null, 2);
        const zetokenBlob = new Blob([containerJson], { type: 'application/x-zetoken' });
        const outputFilename = options.customFilename || `${originalName}.zetoken`;

        if (options.download !== false && typeof document !== 'undefined') {
          this._triggerDownload(zetokenBlob, outputFilename);
        }

        return {
          filename: outputFilename,
          originalName: originalName,
          mimeType: mimeType,
          blob: zetokenBlob,
          json: containerJson,
          size: zetokenBlob.size
        };
      } catch (err) {
        if (this.throwOnError) throw err;
        console.error("[ZetokenClient] File encryption failed:", err.message);
        return false;
      }
    }

    /**
     * Decrypts `.zetoken` container file back into original format bit-by-bit.
     * 
     * @param {File|Blob|string} fileOrString - .zetoken file object or JSON string
     * @param {Object} [options]
     * @param {boolean} [options.download=true] - Auto-trigger restored file download
     * @param {number} [options.leeway=60] - TTL clock skew leeway
     * @returns {Promise<Object|false>} Restored file metadata, Blob, and preview URL
     */
    async decryptFile(fileOrString, options = {}) {
      try {
        let rawContent = '';
        if (typeof fileOrString === 'string') {
          rawContent = fileOrString;
        } else if (fileOrString instanceof Blob || (fileOrString && typeof fileOrString.text === 'function')) {
          rawContent = await fileOrString.text();
        } else {
          throw new Error("Invalid .zetoken file input.");
        }

        rawContent = rawContent.trim();
        let payloadToken = '';

        // Check if content is a valid .zetoken JSON container
        if (rawContent.startsWith('{') && rawContent.endsWith('}')) {
          try {
            const parsed = JSON.parse(rawContent);
            payloadToken = parsed.payload || '';
          } catch (e) {
            payloadToken = rawContent;
          }
        } else {
          payloadToken = rawContent;
        }

        if (!payloadToken) {
          throw new Error("Corrupted .zetoken file or empty payload.");
        }

        // Decrypt payload using active key
        const decryptedEnvelopeJson = await this.decode(payloadToken, options);
        if (!decryptedEnvelopeJson) {
          throw new Error("Failed to decrypt file. Key mismatch, corrupted file, or token expired.");
        }

        let envelope;
        try {
          envelope = JSON.parse(decryptedEnvelopeJson);
        } catch (e) {
          throw new Error("Invalid encrypted file envelope format.");
        }

        const { name, type, size, data } = envelope;
        const restoredBlob = this._base64ToBlob(data, type || 'application/octet-stream');

        if (options.download !== false && typeof document !== 'undefined') {
          this._triggerDownload(restoredBlob, name || 'restored_file.bin');
        }

        return {
          originalName: name,
          mimeType: type,
          size: size || restoredBlob.size,
          blob: restoredBlob,
          dataUrl: data
        };
      } catch (err) {
        if (this.throwOnError) throw err;
        console.error("[ZetokenClient] File decryption failed:", err.message);
        return false;
      }
    }

    async _fileToBase64(file) {
      if (typeof file.arrayBuffer === 'function') {
        const buffer = await file.arrayBuffer();
        const bytes = new Uint8Array(buffer);
        let binary = '';
        const chunkSize = 8192;
        for (let i = 0; i < bytes.length; i += chunkSize) {
          binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
        }
        const b64 = typeof btoa === 'function' ? btoa(binary) : Buffer.from(binary, 'binary').toString('base64');
        const mime = file.type || 'application/octet-stream';
        return `data:${mime};base64,${b64}`;
      } else if (typeof FileReader !== 'undefined') {
        return new Promise((resolve, reject) => {
          const reader = new FileReader();
          reader.onload = () => resolve(reader.result);
          reader.onerror = (error) => reject(error);
          reader.readAsDataURL(file);
        });
      }
      throw new Error("Unable to read file data.");
    }

    _base64ToBlob(dataUrl, defaultMime = 'application/octet-stream') {
      const arr = dataUrl.split(',');
      const mime = (arr[0].match(/:(.*?);/) || [])[1] || defaultMime;
      const bstr = typeof atob === 'function' ? atob(arr[1] || arr[0]) : Buffer.from(arr[1] || arr[0], 'base64').toString('binary');
      let n = bstr.length;
      const u8arr = new Uint8Array(n);
      while (n--) {
        u8arr[n] = bstr.charCodeAt(n);
      }
      return new Blob([u8arr], { type: mime });
    }

    _triggerDownload(blob, filename) {
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    // ========================================================================
    // 3. FULLSCREEN ONBOARDING MODAL (UI)
    // ========================================================================

    _injectModalUI() {
      if (document.getElementById('ztxKeyModal')) return;

      const modalHtml = `
        <div id="ztxKeyModal" class="ztx-modal-backdrop">
          <div class="ztx-modal-container">
            <div class="ztx-modal-glow"></div>
            
            <button id="ztxCloseModalBtn" class="ztx-modal-close-btn" title="Close">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <line x1="18" y1="6" x2="6" y2="18"></line>
                <line x1="6" y1="6" x2="18" y2="18"></line>
              </svg>
            </button>

            <div class="ztx-modal-header">
              <h2 class="ztx-modal-title">Cryptographic Key Configuration</h2>
              <p class="ztx-modal-subtitle">
                Zetoken Client requires an active key to encrypt and decrypt sensitive data. Please upload your key file or generate a fresh key instantly.
              </p>
            </div>

            <div class="ztx-options-grid">
              <!-- Upload Option -->
              <div id="ztxDropzone" class="ztx-action-card">
                <input type="file" id="ztxFileInput" accept=".key,.env,.txt" style="display: none;" />
                <div class="ztx-card-icon upload">
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                    <polyline points="17 8 12 3 7 8"></polyline>
                    <line x1="12" y1="3" x2="12" y2="15"></line>
                  </svg>
                </div>
                <div class="ztx-card-title">Upload Key File</div>
                <div class="ztx-card-desc">Drag & drop or click to select a <code>.key</code> / <code>.env</code> file</div>
              </div>

              <!-- Generate Option -->
              <div id="ztxGenerateCard" class="ztx-action-card">
                <div class="ztx-card-icon generate">
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                    <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                  </svg>
                </div>
                <div class="ztx-card-title">Generate Fresh Key</div>
                <div class="ztx-card-desc">Create a secure random key & download it automatically to your device</div>
              </div>
            </div>

            <!-- Manual Section -->
            <div class="ztx-manual-section">
              <button id="ztxManualToggle" class="ztx-manual-toggle" type="button">
                <span>Or Paste Raw Key Configuration</span>
                <span id="ztxToggleIcon">+</span>
              </button>
              
              <div id="ztxManualBody" class="ztx-manual-body">
                <div class="form-group" style="margin-bottom: 0.75rem;">
                  <textarea id="ztxManualInput" class="form-textarea mono" style="font-size: 0.8rem; height: 110px;" placeholder="ZETOKEN_ACCESS_KEY_ID=...\nZETOKEN_SECRET_KEY=...\nZETOKEN_ITERATIONS=1000"></textarea>
                </div>
                <button id="ztxSaveManualBtn" class="btn btn-primary btn-sm" style="width: 100%;">
                  Save & Apply Key
                </button>
              </div>
            </div>

          </div>
        </div>

        <div id="ztxToastContainer" class="ztx-toast-container"></div>
      `;

      const wrapper = document.createElement('div');
      wrapper.innerHTML = modalHtml;
      document.body.appendChild(wrapper);

      this._setupModalEvents();
    }

    _setupModalEvents() {
      const modal = document.getElementById('ztxKeyModal');
      const closeBtn = document.getElementById('ztxCloseModalBtn');
      const dropzone = document.getElementById('ztxDropzone');
      const fileInput = document.getElementById('ztxFileInput');
      const generateCard = document.getElementById('ztxGenerateCard');
      const manualToggle = document.getElementById('ztxManualToggle');
      const manualBody = document.getElementById('ztxManualBody');
      const toggleIcon = document.getElementById('ztxToggleIcon');
      const saveManualBtn = document.getElementById('ztxSaveManualBtn');
      const manualInput = document.getElementById('ztxManualInput');

      // Close Button
      closeBtn.addEventListener('click', () => {
        if (!this.hasKey()) {
          this.showToast("Key is not configured. Please upload or generate a key first.", "error");
          return;
        }
        this.hideKeyModal();
      });

      // File Pick & Drag-drop
      dropzone.addEventListener('click', () => fileInput.click());

      dropzone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropzone.classList.add('drag-over');
      });

      dropzone.addEventListener('dragleave', () => {
        dropzone.classList.remove('drag-over');
      });

      dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropzone.classList.remove('drag-over');
        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
          this._handleUploadedFile(e.dataTransfer.files[0]);
        }
      });

      fileInput.addEventListener('change', (e) => {
        if (e.target.files && e.target.files[0]) {
          this._handleUploadedFile(e.target.files[0]);
        }
      });

      // Generate Card
      generateCard.addEventListener('click', () => {
        try {
          const newContent = this.generateNewKeyFile();
          this.saveConfig(newContent);
          this.downloadKeyFile('zetoken-client.key');
          this.showToast("New key successfully generated, saved, and downloaded!", "success");
          this.hideKeyModal();
        } catch (err) {
          this.showToast("Failed to generate key: " + err.message, "error");
        }
      });

      // Manual Toggle
      manualToggle.addEventListener('click', () => {
        const isOpen = manualBody.classList.contains('open');
        manualBody.classList.toggle('open');
        toggleIcon.textContent = isOpen ? '+' : '−';
      });

      // Save Manual
      saveManualBtn.addEventListener('click', () => {
        const text = manualInput.value.trim();
        if (!text) {
          this.showToast("Please enter key=value configuration lines.", "error");
          return;
        }
        try {
          this.saveConfig(text);
          this.showToast("Key configuration saved and applied successfully!", "success");
          this.hideKeyModal();
          manualInput.value = '';
        } catch (err) {
          this.showToast("Invalid key format: " + err.message, "error");
        }
      });
    }

    _handleUploadedFile(file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        try {
          const content = e.target.result;
          this.saveConfig(content);
          this.showToast(`Key from '${file.name}' successfully loaded!`, "success");
          this.hideKeyModal();
        } catch (err) {
          this.showToast("Failed to parse key file: " + err.message, "error");
        }
      };
      reader.onerror = () => {
        this.showToast("An error occurred while reading the file.", "error");
      };
      reader.readAsText(file);
    }

    showKeyModal() {
      const modal = document.getElementById('ztxKeyModal');
      if (modal) {
        modal.classList.add('open');
        const closeBtn = document.getElementById('ztxCloseModalBtn');
        if (closeBtn) {
          closeBtn.style.display = this.hasKey() ? 'flex' : 'none';
        }
      }
    }

    hideKeyModal() {
      const modal = document.getElementById('ztxKeyModal');
      if (modal) {
        modal.classList.remove('open');
      }
    }

    showToast(message, type = 'info') {
      const container = document.getElementById('ztxToastContainer');
      if (!container) return;

      const toast = document.createElement('div');
      toast.className = `ztx-toast ${type}`;
      toast.textContent = message;

      container.appendChild(toast);
      setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 300);
      }, 3500);
    }

    _dispatchCustomEvent(name, detail) {
      if (typeof window !== 'undefined' && typeof CustomEvent === 'function') {
        window.dispatchEvent(new CustomEvent(name, { detail }));
      }
    }

    // ========================================================================
    // 4. CRYPTOGRAPHIC UTILITY HELPERS
    // ========================================================================

    _generateSecureDigits(length) {
      let result = '';
      const cryptoObj = this._getCrypto();
      while (result.length < length) {
        const array = new Uint8Array(1);
        cryptoObj.getRandomValues(array);
        if (array[0] < 250) {
          result += (array[0] % 10).toString();
        }
      }
      return result;
    }

    _generateSecureBase64(length) {
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
      let result = '';
      const cryptoObj = this._getCrypto();
      const array = new Uint8Array(length);
      cryptoObj.getRandomValues(array);
      for (let i = 0; i < length; i++) {
        result += chars.charAt(array[i] % 64);
      }
      return result + '=';
    }

    _generateSecureIterations() {
      const cryptoObj = this._getCrypto();
      const array = new Uint16Array(1);
      cryptoObj.getRandomValues(array);
      return (array[0] % 2001) + 1000; // Range: 1000 - 3000
    }

    _deterministicDigits(str, length) {
      let hash = 0;
      for (let i = 0; i < str.length; i++) {
        hash = (hash * 31 + str.charCodeAt(i)) >>> 0;
      }
      let res = '';
      let seed = hash;
      while (res.length < length) {
        seed = (seed * 1664525 + 1013904223) >>> 0;
        res += (seed % 10).toString();
      }
      return res;
    }

    _deterministicBase64(str, length) {
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
      let hash = 0;
      for (let i = 0; i < str.length; i++) {
        hash = (hash * 37 + str.charCodeAt(i)) >>> 0;
      }
      let res = '';
      let seed = hash;
      for (let i = 0; i < length; i++) {
        seed = (seed * 1103515245 + 12345) >>> 0;
        res += chars.charAt(seed % 64);
      }
      return res + '=';
    }
  }

  return ZetokenClient;
}));
