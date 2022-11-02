# wisp.js

wisp.js is a small wasm module that handles client-side cryptographic functions for wisp.

## Usage

Import the wasm module, which exports the following global functions.

```html
<script src="https://wisp.day/js/wisp.js"></script>
```

### `wisp_GenerateKeyPair`

Generate a new RSA public/private key pair.

```js
let keyPair = wisp_GenerateKeyPair()
console.log(keyPair.public)
console.log(keyPair.private)
```

### `wisp_CreateLoginJSON`

Creates a signed JSON payload which can be used to login to a wisp server.

The public and private keys are expected to be passed in as PEM strings (see the output of `wisp_GenerateKeyPair` for an example).

```js
let loginJSON = wisp_CreateLoginJSON("username", keyPair.public, keyPair.private)
console.log(loginJSON)
```