"use strict";

/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
//const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters
const PASSWORD_VERIFICATION_DUMMY_TEXT = "password_verification_test";

/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load.
   * Arguments:
   *  You may design the constructor with any parameters you would like.
   * Return Type: void
   */
  constructor(domainKey, encryptionKey, kvs, salt, passwordVerificationData) {
    this.data = {
      /* Store member variables that you intend to be public here
         (i.e. information that will not compromise security if an adversary sees) */
    };
    this.secrets = {
      /* Store member variables that you intend to be private here
         (information that an adversary should NOT see). */
      domainKey: domainKey,
      encryptionKey: encryptionKey,
      kvs: kvs,
      salt: salt,
      passwordVerificationData: passwordVerificationData // Store verification data
    };
  };

  /**
    * Creates an empty keychain with the given password.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  static async init(password) {
    if (typeof password !== 'string') {
      throw new Error("Password must be a string");
    }

    const salt = await getRandomBytes(16); // 128-bit salt
    const keyMaterial = await subtle.importKey("raw", stringToBuffer(password), "PBKDF2", false, ["deriveKey"]);
    const masterKey = await subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256"
      },
      keyMaterial,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"]
    );

    const domainKeyMaterial = await subtle.sign({ name: "HMAC", hash: "SHA-256" }, masterKey, stringToBuffer("domain_key"));
    const domainKey = await subtle.importKey("raw", domainKeyMaterial, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);

    const encryptionKeyMaterial = await subtle.sign({ name: "HMAC", hash: "SHA-256" }, masterKey, stringToBuffer("encryption_key"));
    const encryptionKey = await subtle.importKey("raw", encryptionKeyMaterial, "AES-GCM", false, ["encrypt", "decrypt"]);

    // Create password verification data
    const verificationIv = await getRandomBytes(12);
    const encryptedVerificationValueBuffer = await subtle.encrypt(
        { name: "AES-GCM", iv: verificationIv },
        encryptionKey,
        stringToBuffer(PASSWORD_VERIFICATION_DUMMY_TEXT)
    );
    const passwordVerificationData = encodeBuffer(verificationIv) + "." + encodeBuffer(encryptedVerificationValueBuffer);


    return new Keychain(domainKey, encryptionKey, {}, encodeBuffer(salt), passwordVerificationData);
  }

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object).Returns a Keychain object that contains the data
    * from repr.
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: Keychain | boolean (false on incorrect password)
    */
  static async load(password, repr, trustedDataCheck) {
    if (typeof password !== 'string') {
      throw new Error("Password must be a string");
    }
    if (typeof repr !== 'string') {
      throw new Error("Representation must be a string");
    }
    if (trustedDataCheck !== undefined && typeof trustedDataCheck !== 'string') {
      throw new Error("trustedDataCheck must be a string or undefined");
    }

    try {
      const data = JSON.parse(repr);
      if (!data.kvs || !data.salt || !data.passwordVerificationData) { // Check for verification data
        throw new Error("Invalid keychain format: missing kvs, salt, or passwordVerificationData");
      }
      const saltBuffer = decodeBuffer(data.salt);
      const keyMaterial = await subtle.importKey("raw", stringToBuffer(password), "PBKDF2", false, ["deriveKey"]);
      const masterKey = await subtle.deriveKey(
        {
          name: "PBKDF2",
          salt: saltBuffer,
          iterations: PBKDF2_ITERATIONS,
          hash: "SHA-256"
        },
        keyMaterial,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign", "verify"]
      );

      const domainKeyMaterial = await subtle.sign({ name: "HMAC", hash: "SHA-256" }, masterKey, stringToBuffer("domain_key"));
      const domainKey = await subtle.importKey("raw", domainKeyMaterial, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);

      const encryptionKeyMaterial = await subtle.sign({ name: "HMAC", hash: "SHA-256" }, masterKey, stringToBuffer("encryption_key"));
      const encryptionKey = await subtle.importKey("raw", encryptionKeyMaterial, "AES-GCM", false, ["encrypt", "decrypt"]);


      if (trustedDataCheck !== undefined) {
        const calculatedChecksumBuffer = await subtle.digest("SHA-256", stringToBuffer(repr));
        const calculatedChecksum = encodeBuffer(calculatedChecksumBuffer);
        if (calculatedChecksum !== trustedDataCheck) {
          throw new Error("Checksum verification failed: database may be corrupted or tampered with.");
        }
      }

      // Password verification: Attempt to decrypt dummy data
      const [verificationIvBase64, encryptedVerificationValueBase64] = data.passwordVerificationData.split('.');
      if (!verificationIvBase64 || !encryptedVerificationValueBase64) {
          throw new Error("Invalid password verification data format");
      }
      const verificationIv = decodeBuffer(verificationIvBase64);
      const encryptedVerificationValueBuffer = decodeBuffer(encryptedVerificationValueBase64);

      try {
          const decryptedVerificationValueBuffer = await subtle.decrypt(
              { name: "AES-GCM", iv: verificationIv },
              encryptionKey,
              encryptedVerificationValueBuffer
          );
          const decryptedVerificationText = bufferToString(decryptedVerificationValueBuffer);
          if (decryptedVerificationText !== PASSWORD_VERIFICATION_DUMMY_TEXT) {
              throw new Error("Incorrect password or invalid keychain data."); // Password incorrect - now THROW error
          }
      } catch (e) {
          throw new Error("Incorrect password or invalid keychain data."); // Password incorrect - now THROW error in catch too
      }


      return new Keychain(domainKey, encryptionKey, data.kvs, data.salt, data.passwordVerificationData);


    } catch (e) {
      if (e.message === "Checksum verification failed: database may be corrupted or tampered with." || e.message === "Invalid keychain format: missing kvs, salt, or passwordVerificationData" || e.message === "Invalid password verification data format") {
        throw e; // Re-throw specific errors
      }
       else {
        throw new Error("Incorrect password or invalid keychain data."); // Generic error for incorrect password or other load failures - THROW error
      }
    }
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity.
    *
    * Return Type: array
    */
  async dump() {
    const dataToSerialize = {
        kvs: this.secrets.kvs,
        salt: this.secrets.salt,
        passwordVerificationData: this.secrets.passwordVerificationData // Include verification data in dump
    };
    const representation = JSON.stringify(dataToSerialize);
    const checksumBuffer = await subtle.digest("SHA-256", stringToBuffer(representation));
    const checksum = encodeBuffer(checksumBuffer);
    return [representation, checksum];
  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) {
    if (typeof name !== 'string') {
      throw new Error("Domain name must be a string");
    }

    const domainHashBuffer = await subtle.sign({ name: "HMAC", hash: "SHA-256" }, this.secrets.domainKey, stringToBuffer(name));
    const domainHash = encodeBuffer(domainHashBuffer);
    const authData = this.secrets.kvs[domainHash];
    if (!authData) {
      return null;
    }

    const [ivBase64, encryptedValueBase64] = authData.split('.');
    if (!ivBase64 || !encryptedValueBase64) {
      throw new Error("Invalid auth data format"); // Should not happen if dump/load is correct
    }

    const iv = decodeBuffer(ivBase64);
    const encryptedValueBuffer = decodeBuffer(encryptedValueBase64);

    try {
      const decryptedValueBuffer = await subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        this.secrets.encryptionKey,
        encryptedValueBuffer
      );
      return bufferToString(decryptedValueBuffer);
    } catch (e) {
      // Decryption failed - possible tampering or incorrect key, OR incorrect password used for loading.
      console.error("Decryption error:", e);
      return null; // Or throw an exception if you want to signal error more explicitly.
    }
  };

  /**
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  async set(name, value) {
    if (typeof name !== 'string') {
      throw new Error("Domain name must be a string");
    }
    if (typeof value !== 'string') {
      throw new Error("Password value must be a string");
    }

    const domainHashBuffer = await subtle.sign({ name: "HMAC", hash: "SHA-256" }, this.secrets.domainKey, stringToBuffer(name));
    const domainHash = encodeBuffer(domainHashBuffer);
    const encodedValueBuffer = stringToBuffer(value);
    const iv = await getRandomBytes(12); // 96-bit IV recommended for AES-GCM
    const encryptedValueBuffer = await subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      this.secrets.encryptionKey,
      encodedValueBuffer
    );
    const authData = encodeBuffer(iv) + "." + encodeBuffer(encryptedValueBuffer); // Store IV and ciphertext, separated by "."
    this.secrets.kvs[domainHash] = authData;
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {
    if (typeof name !== 'string') {
      throw new Error("Domain name must be a string");
    }

    const domainHashBuffer = await subtle.sign({ name: "HMAC", hash: "SHA-256" }, this.secrets.domainKey, stringToBuffer(name));
    const domainHash = encodeBuffer(domainHashBuffer);
    if (this.secrets.kvs[domainHash]) {
      delete this.secrets.kvs[domainHash];
      return true;
    } else {
      return false;
    }
  };
};

module.exports = { Keychain }