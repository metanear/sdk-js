import * as nearlib from "near-api-js";
import * as nacl from "tweetnacl";

const GAS = 200000000000000;
const MESSAGE_GAS = 300000000000000;

const encryptionKey = "encryptionKey";

/**
  a class representing the MetaNear contract API

  this API supports local contract methods
  - get: gets a value from local storage
  - set: sets a value on local storage
  - remove: deletes a value from local storage

  and remote contract methods
  - pull: reads a message from a remote contract
  - post / send: sends a message to a remote contract
 */
class MetaNearApp {
  constructor(appId, accountId, nearConfig) {
    this.appId = appId;
    this.accountId = accountId;
    this._nearConfig = nearConfig;
    this.blocking = Promise.resolve();
    this.parseEncryptionKey();
    window.nacl = nacl;
    window.Buffer = Buffer;
  }

  /**
    read private key from local storage
    - if found, recreate the related key pair
    - if not found, create a new key pair and save it to local storage
   */
  parseEncryptionKey() {
    const keyKey = "enc_key:" + this.accountId + ":" + this.appId + ":";
    let key = localStorage.getItem(keyKey);
    if (key) {
      const buf = Buffer.from(key, 'base64');
      if (buf.length !== nacl.box.secretKeyLength) {
        throw new Error("Given secret key has wrong length");
      }
      key = nacl.box.keyPair.fromSecretKey(buf);
    } else {
      key = new nacl.box.keyPair();
      localStorage.setItem(keyKey, Buffer.from(key.secretKey).toString('base64'));
    }
    this._key = key;
  }

  /**
   updates local secret key to the new given secret key and stores it to local storage.
   @param newSecretKey64 base64 encoded secret key
   */
  updateEncryptionKey(newSecretKey64) {
    const buf = Buffer.from(newSecretKey64, 'base64');
    if (buf.length !== nacl.box.secretKeyLength) {
      throw new Error("Given secret key has wrong length");
    }
    const key = nacl.box.keyPair.fromSecretKey(buf);
    this._key = key;
    const keyKey = "enc_key:" + this.accountId + ":" + this.appId + ":";
    localStorage.setItem(keyKey, Buffer.from(key.secretKey).toString('base64'));
  }

  async _innerInit() {
    this._keyStore = new nearlib.keyStores.BrowserLocalStorageKeyStore(
      localStorage, "app:" + this.appId + ":",
    );
    this._near = await nearlib.connect(Object.assign({ deps: { keyStore:  this._keyStore } }, this._nearConfig));
    this._account = new nearlib.Account(this._near.connection, this.accountId);
    this._contract = new nearlib.Contract(this._account, this.accountId, {
      viewMethods: ['get', 'apps', 'num_messages'],
      changeMethods: ['set', 'remove', 'pull_message', 'send_message'],
      sender: this.accountId
    });
    this._networkId = this._nearConfig.networkId;
    return true;
  }

  /**
    initialize the client-side application with a BrowserLocalStorageKeyStore
    and a connection to the NEAR platform, binding OpenWebContract methods:

    - get, set, remove: local invocation methods for controlling the state of local applications
    - pull_message, send_message: remote invocation methods for communicating with contracts of other users
    - apps, num_messages: convenience methods for listing all apps on the OpenWeb and messages for a specific app
   */
  async init() {
    return this._init || (this._init = this._innerInit());
  }

  /**
    helper method to check if the the user is logged in with the app
   */
  async ready() {
    await this.init();
    const key = await this._keyStore.getKey(this._networkId, this.accountId);
    return !!key;
  }

  /**
   helper method to wait until the the user is logged in with the app
   */
  async waitReady() {
    return await this.ready() || this._ready || (this._ready = (new Promise((resolve) => {
      this._keyAwait = resolve;
    })));
  }

  /**
    produce a public key on the user account
    @return {string} existing (or create new) public key for the current account
   */
  async getAccessPublicKey() {
    const key = await this._keyStore.getKey(this._networkId, this.accountId);
    if (key) {
      return key.getPublicKey();
    }
    if (this._tmpKey) {
      return this._tmpKey.getPublicKey();
    }
    const accessKey = nearlib.KeyPair.fromRandom('ed25519');
    this._tmpKey = accessKey;
    return accessKey.getPublicKey();
  }

  /**
    returns a public key on the user account in binary borsh serialized format
    @returns {Promise<Uint8Array>} public access key
   */
  async getSerializedAccessPublicKey() {
    return nearlib.utils.serialize.serialize(nearlib.transactions.SCHEMA, await this.getAccessPublicKey());
  }

  /**
    returns the encryption key stored under given accountId

    @param {string|null} accountId optional accountId to get stored encryption key (your account by default).
    @param {object} options to specify:
    - {bool} `encrypted` flag indicating whether or not the value is box encrypted. Default false.
    - {string} `appId` the name of the app. Same app by default.
    @returns {Promise<string|null>} the stored encryption key in base64 format or null
   */
  async getStoredEncryptionPublicKey(accountId, options) {
    return this.getFrom(accountId || this.accountId, encryptionKey, options)
  }


  getEncryptionPublicKey() {
    return Buffer.from(this._key.publicKey).toString('base64')
  }

  async storeEncryptionPublicKey() {
    return this.set(encryptionKey, this.getEncryptionPublicKey());
  }

  /**
    capture new keys in the keystore
   */
  async onKeyAdded() {
    if (!this._tmpKey) {
      throw new Error('The key is not initialized yet');
    }
    await this._keyStore.setKey(this._networkId, this.accountId, this._tmpKey);
    this._tmpKey = null;
    if (this._keyAwait) {
      this._keyAwait();
    }
  }

  /**
    enforces that the app is ready

    @returns {Promise<void>}
   */
  async forceReady() {
    if (!await this.ready()) {
      throw new Error('Not ready yet');
    }
  }

  /**
    wrap a call in a Promise for async handling?

    @param {Function} call the function to be wrapped in a Promise
    @return {Promise} the Promise to return
   */
  wrappedCall(call) {
    this.blocking = this.blocking.then(() => call()).catch(() => call());
    return this.blocking;
  }

  /**
    unbox encrypted messages with our secret key
    @param {string} msg64 encrypted message encoded as Base64
    @return {string} decoded contents of the box
   */
  decryptSecretBox(msg64) {
    const buf = Buffer.from(msg64, 'base64');
    const nonce = new Uint8Array(nacl.secretbox.nonceLength);
    buf.copy(nonce, 0, 0, nonce.length);
    const box = new Uint8Array(buf.length - nacl.secretbox.nonceLength);
    buf.copy(box, 0, nonce.length);
    const decodedBuf = nacl.secretbox.open(box, nonce, this._key.secretKey);
    return Buffer.from(decodedBuf).toString()
  }

  /**
    box an unencrypted message with our secret key
    @param {string} str the message to wrap in a box
    @return {string} base64 encoded box of incoming message
   */
  encryptSecretBox(str) {
    const buf = Buffer.from(str);
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const box = nacl.secretbox(buf, nonce, this._key.secretKey);

    const fullBuf = new Uint8Array(box.length + nacl.secretbox.nonceLength);
    fullBuf.set(nonce);
    fullBuf.set(box, nacl.secretbox.nonceLength);
    return Buffer.from(fullBuf).toString('base64')
  }

  /**
   unbox encrypted messages with our secret key
   @param {string} msg64 encrypted message encoded as Base64
   @param {Uint8Array} theirPublicKey the public key to use to verify the message
   @return {string} decoded contents of the box
   */
  decryptBox(msg64, theirPublicKey) {
    if (theirPublicKey.length !== nacl.box.publicKeyLength) {
      throw new Error("Given encryption public key is invalid.");
    }
    const buf = Buffer.from(msg64, 'base64');
    const nonce = new Uint8Array(nacl.box.nonceLength);
    buf.copy(nonce, 0, 0, nonce.length);
    const box = new Uint8Array(buf.length - nacl.box.nonceLength);
    buf.copy(box, 0, nonce.length);
    const decodedBuf = nacl.box.open(box, nonce, theirPublicKey, this._key.secretKey);
    return Buffer.from(decodedBuf).toString()
  }

  /**
   box an unencrypted message with their public key and sign it with our secret key
   @param {string} str the message to wrap in a box
   @param {Uint8Array} theirPublicKey the public key to use to encrypt the message
   @returns {string} base64 encoded box of incoming message
   */
  encryptBox(str, theirPublicKey) {
    if (theirPublicKey.length !== nacl.box.publicKeyLength) {
      throw new Error("Given encryption public key is invalid.");
    }
    const buf = Buffer.from(str);
    const nonce = nacl.randomBytes(nacl.box.nonceLength);
    const box = nacl.box(buf, nonce, theirPublicKey, this._key.secretKey);

    const fullBuf = new Uint8Array(box.length + nacl.box.nonceLength);
    fullBuf.set(nonce);
    fullBuf.set(box, nacl.box.nonceLength);
    return Buffer.from(fullBuf).toString('base64')
  }

  /**
    get data from a local app.  apps can decide whether or not to encrypt their contents

    @param {string} key the key used to store a value in the app
    @param {object} options to specify:
    - {bool} `encrypted` flag indicating whether or not the value is box encrypted. Default false.
    - {string} `appId` the name of the app. Same app by default.
    @return {string} the value returned by the local app
   */
  async get(key, options) {
    options = Object.assign({
      encrypted: false,  // not supported yet
      appId: this.appId,
    }, options);
    let str = await this._contract.get({
      app_id: options.appId,
      key,
    });
    if (str) {
      str = JSON.parse(options.encrypted ? this.decryptSecretBox(str) : str);
    }
    return str;
  }

  /**
    get a value from a remote app installed on another account

    @param {string} accountId account from which to get a value
    @param {string} key the key to use to identify the value
    @param {object} options to specify:
     - {bool} `encrypted` flag indicating whether or not the value is box encrypted. Default false.
     - {string} `appId` the name of the app. Same app by default.
    @return {string} the value returned from the remote app
   */
  async getFrom(accountId, key, options) {
    options = Object.assign({
      encrypted: false,  // not supported yet
      appId: this.appId,
    }, options);
    const account = new nearlib.Account(this._near.connection, accountId);
    const contract = new nearlib.Contract(account, accountId, {
      viewMethods: ['get'],
      changeMethods: [],
      sender: this.accountId
    });

    let str = await contract.get({
      app_id: options.appId,
      key,
    });
    if (str) {
      str = JSON.parse(options.encrypted ? this.decryptSecretBox(str) : str);
    }
    return str;
  }

  /**
    return a list of installed apps
    @return {object} collection of installed apps
   */
  async apps() {
    return await this._contract.apps();
  }

  /**
    set a value in local storage

    @param {string} key identifier for the value to be set
    @param {string} value the value to be set
    @param {object} options to specify:
      - {bool} `encrypted` flag indicating whether to encrypt (box) the value. Default false.
   */
  async set(key, value, options) {
    await this.forceReady();
    options = Object.assign({
      encrypted: false,
    }, options);
    await this.wrappedCall(() => this._contract.set({
      key,
      value: options.encrypted ? this.encryptSecretBox(JSON.stringify(value)) : JSON.stringify(value),
    }, GAS));
  }

  /**
    remove a key-value pair from local storage

    @param {string} key key to be removed
   */
  async remove(key) {
    await this.forceReady();
    await this.wrappedCall(() => this._contract.remove({
      key,
    }, GAS));
  }

  /**
    retrieve a message

    @return {any} return async? pull from local storage, null if not found
   */
  async pullMessage() {
    await this.forceReady();
    if (await this._contract.num_messages({app_id: this.appId}) > 0) {
      return await this.wrappedCall(() => this._contract.pull_message({}, GAS));
    } else {
      return null;
    }
  }

  async getTheirPublicKey(options) {
    options = Object.assign({
      accountId: null,
      theirPublicKey: null,
      theirPublicKey64: null,
      encryptionKey,
      appId: this.appId,
    }, options);
    if (options.theirPublicKey) {
      return options.theirPublicKey;
    }
    if (!options.theirPublicKey64) {
      if (!options.accountId) {
        throw new Error("Either accountId or theirPublicKey64 has to be provided");
      }
      options.theirPublicKey64 = await this.getFrom(options.accountId, options.encryptionKey, {
        appId: options.appId,
      });
    }
    if (!options.theirPublicKey64) {
      throw new Error("Their app doesn't provide the encryption public key.");
    }
    const buf = Buffer.from(options.theirPublicKey64, 'base64');
    if (buf.length !== nacl.box.publicKeyLength) {
      throw new Error("Their encryption public key is invalid.");
    }
    const theirPublicKey = new Uint8Array(nacl.box.publicKeyLength);
    theirPublicKey.set(buf);
    return theirPublicKey;
  }

  /**
   * Encrypts given content. Typical usage: encryptMessage("hello world", {accountId: bla})
   *
   * @param {string} content The message to encrypt
   * @param options
   * @returns {Promise<string>}
   */
  async encryptMessage(content, options) {
    const theirPublicKey = await this.getTheirPublicKey(options);
    return this.encryptBox(content, theirPublicKey);
  }

  async decryptMessage(msg64, options) {
    const theirPublicKey = await this.getTheirPublicKey(options);
    return this.decryptBox(msg64, theirPublicKey);
  }

  /**
    send a message to another account

    @param {string} receiverId account id which will receive the message
    @param {string} message the content of the message
    @param {object} options to specify:
      - {string} `appId` the app ID to receive the message. Same app by default.
   */
  async sendMessage(receiverId, message, options) {
    this.forceReady();
    options = Object.assign({
      appId: this.appId,
    }, options);
    await this.wrappedCall(() => this._contract.send_message({
      receiver_id: receiverId,
      app_id: options.appId,
      message,
    }, MESSAGE_GAS));
  }
}

export {encryptionKey, MetaNearApp}
