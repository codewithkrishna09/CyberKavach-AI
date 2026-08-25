/* Shared browser identity helper.
   Some local HTTP preview servers expose crypto.getRandomValues but not
   crypto.randomUUID. A missing convenience API must never stop a scan. */
(function () {
    function randomHex(byteCount) {
        const bytes = new Uint8Array(byteCount);
        if (globalThis.crypto && typeof globalThis.crypto.getRandomValues === "function") {
            globalThis.crypto.getRandomValues(bytes);
        } else {
            // Compatibility fallback for old preview environments. This only
            // creates a local FREE-session identifier, never an auth secret.
            for (let index = 0; index < bytes.length; index += 1) {
                bytes[index] = Math.floor(Math.random() * 256);
            }
        }
        return Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
    }

    function createFreeKey() {
        return `FREE-${randomHex(16)}`;
    }

    function getOrCreateKey(storageKey = "cyberkavach_key") {
        let key = localStorage.getItem(storageKey);
        if (!key || key === "GUEST_SESSION") {
            key = createFreeKey();
            localStorage.setItem(storageKey, key);
        }
        return key;
    }

    globalThis.CyberKavachIdentity = Object.freeze({ createFreeKey, getOrCreateKey });
}());
