# **EXPERIMENTAL: node-libhydrogen-binding** #

[![Build Status](https://travis-ci.org/trampi/node-libhydrogen-binding.svg)](https://travis-ci.org/trampi/node-libhydrogen-binding)

### libhydrogen native bindings for Node.js
**Work in progress!** This package brings the easy-to-use encryption library [libhydrogen](https://github.com/jedisct1/libhydrogen/) to Node.js.  


# Usage example
Install *node-libhydrogen-binding* as any other package:
```bash
npm install node-libhydrogen-binding
```

You can use it for encrypting and decrypting payload:
```javascript
const hydrogen = require('node-libhydrogen-binding');
hydrogen.init();

const msg = "message";
const key = hydrogen.secretbox_keygen();
const msgId = 0;
const context = "testtest";

// encrypt
const ciphertext = hydrogen.secretbox_encrypt(msg, key, msgId, context);

// decrypt
const plaintext = hydrogen.secretbox_decrypt(ciphertext, key, msgId, context)
```


# [API Documentation](https://github.com/trampi/node-libhydrogen-binding/wiki)
[Check the wiki](https://github.com/trampi/node-libhydrogen-binding/wiki)

# Building
* `npm install --global --production windows-build-tools` (windows only)
* `npm run build` 

# License
ISC, same as [libhydrogen](https://github.com/jedisct1/libhydrogen/).
