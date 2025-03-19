# Applied-Crypto_Project1
A password manager using SubtleCrypto library



## Checklist

###  Functionality
    
- [ ]   **`init(password)`:** Correctly derives keys (PBKDF2, then HMAC for `k_mac` and `k_enc`), generates a salt, and initializes a new `Keychain` instance.
- [ ]   **`load(password, representation, trustedDataCheck)`:** Correctly parses the JSON, derives keys using the provided password and stored salt, verifies the `trustedDataCheck` (if provided), and loads the KVS. Throws an error if the integrity check fails or the password is invalid.
- [ ]   **`dump()`:** Correctly serializes the KVS (including the salt) to JSON and returns the JSON string along with its SHA-256 hash.
- [ ]   **`set(name, value)`:** Correctly pads the password, encrypts it with AES-GCM (using a unique IV), calculates the HMAC of the domain name, and stores the Base64-encoded ciphertext and IV in the KVS.
- [ ]   **`get(name)`:** Correctly calculates the HMAC of the domain name, retrieves the Base64-encoded ciphertext and IV from the KVS, decrypts the password, removes the padding, and returns the original password. Returns `null` if the domain is not found.
- [ ]   **`remove(name)`:** Correctly calculates the HMAC of the domain name, removes the entry from the KVS, and returns `true` if found, `false` otherwise.
- [ ]   **`constructor()`:** Initializes an empty `kvs` object.

### Test

- [ ] Chạy test có sẵn (`npm test`)

### Questions

- [ ]   Trả lời đống câu hỏi ở cuối

