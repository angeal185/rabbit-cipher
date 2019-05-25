# rabbit-cipher

rabbit 128bit cipher with poly1305


demo: https://angeal185.github.io/rabbit-cipher/

### Installation

npm

```sh
$ npm install rabbit-cipher --save
```

bower

```sh
$ bower install rabbit-cipher
```

git
```sh
$ git clone git@github.com:angeal185/rabbit-cipher.git
```


#### nodejs

```js

const rabbit = require('rabbit-cipher');

```

#### browser

```html

<script src="./dist/rabbit.min.js"></script>

```



#### API

```js

/* encrypt */

/**
 *  sync ~ encrypt data
 *  @param {string/byteArray/uint8Array} plain ~ data to be encrypted
 *  @param {string/byteArray/uint8Array} secret ~ encryption key
 *  @param {string} digest ~ encrypted data digest hex/bytes/binary/uint8/base64
 **/

rabbit.encSync(plain, secret, digest)



/**
 *  callback ~ encrypt data
 *  @param {string/byteArray/uint8Array} plain ~ data to be encrypted
 *  @param {string/byteArray/uint8Array} secret ~ encryption key
 *  @param {string} digest ~ encrypted data digest hex/bytes/binary/uint8/base64
 *  @param {function} cb ~ callback function(err,data)
 **/

rabbit.enc(plain, secret, digest, cb)


/**
 *  promise ~ encrypt data
 *  @param {string/byteArray/uint8Array} plain ~ data to be encrypted
 *  @param {string/byteArray/uint8Array} secret ~ encryption key
 *  @param {string} digest ~ encrypted data digest hex/bytes/binary/uint8/base64
 **/
rabbit.encP(plain, secret, digest)


/* decrypt */

/**
 *  sync  ~ decrypt data
 *  @param {string/byteArray/uint8Array} ctext ~ data to be decrypted
 *  @param {string/byteArray/uint8Array} key ~ encryption key
 *  @param {string} digest ~ encrypted data digest hex/bytes/binary/uint8/base64
 **/

rabbit.decSync(ctext, key, digest)


/**
 *  callback  ~ decrypt data
 *  @param {string/byteArray/uint8Array} ctext ~ data to be decrypted
 *  @param {string/byteArray/uint8Array} key ~ encryption key
 *  @param {string} digest ~ encrypted data digest hex/bytes/binary/uint8/base64
 *  @param {function} cb ~ callback function(err,data)
 **/

rabbit.dec(ctext, key, digest, cb)


/**
 *  promise  ~ decrypt data
 *  @param {string/byteArray/uint8Array} ctext ~ data to be encrypted
 *  @param {string/byteArray/uint8Array} key ~ encryption key
 *  @param {string} digest ~ encrypted data digest hex/bytes/binary/uint8/base64
 **/

rabbit.decP(ctext, key, digest)


/* encrypt and sign with poly1305 */

/**
 *  callback ~  encrypt and sign
 *  @param {string/byteArray/uint8Array} plain ~ data to encrypt
 *  @param {string/byteArray/uint8Array} key ~ encryption key
 *  @param {string/byteArray/uint8Array} skey ~ poly1305 key
 *  @param {string} digest ~ poly/data digest hex/bytes/binary/uint8/base64
 *  @param {function} cb ~ callback function(err,data)
 **/

rabbit.encPoly(plain, key, skey, digest, cb)


/**
 *  promise ~  encrypt and sign
 *  @param {string/byteArray/uint8Array} plain ~ data to encrypt
 *  @param {string/byteArray/uint8Array} key ~ encryption key
 *  @param {string/byteArray/uint8Array} skey ~ poly1305 key
 *  @param {string} digest ~ poly/data digest hex/bytes/binary/uint8/base64
 **/

rabbit.encPolyP(plain, hkey, hash, digest)


/* verify poly1305 and decrypt */

/**
 *  callback ~  verify and decrypt
 *  @param {string/byteArray/uint8Array} ctext ~ data to decrypt
 *  @param {string/byteArray/uint8Array} key ~ decrypt key
 *  @param {string/byteArray/uint8Array} sig1 ~ poly signature
 *  @param {string/byteArray/uint8Array} sig2 ~ ctext signature
 *  @param {string} digest ~ poly/data digest hex/bytes/binary/uint8/base64
 *  @param {function} cb ~ callback function(err,data)
 **/

rabbit.decPoly(ctext, key, sig1, sig2, digest, cb)


/**
 *  promise ~  verify and decrypt
 *  @param {string/byteArray/uint8Array} ctext ~ data to decrypt
 *  @param {string/byteArray/uint8Array} key ~ decrypt key
 *  @param {string/byteArray/uint8Array} sig1 ~ poly signature
 *  @param {string/byteArray/uint8Array} sig2 ~ ctext signature
 *  @param {string} digest ~ poly/data digest hex/bytes/binary/uint8/base64
 **/

rabbit.decPolyP(ctext, key, sig1, sig2, digest)



/* poly1305 */

/**
 *  callback ~ verify encrypted data
 *  @param {string/byteArray/uint8Array} ctext ~ cipher text
 *  @param {integer} len ~ cipher text length
 *  @param {string/byteArray/uint8Array} key ~ poly1305 key
 *  @param {string} digest ~ hmac key digest hex/bytes/binary/uint8/base64
 *  @param {function} cb ~ callback function(err,data)
 **/

rabbit.poly1305.sign(ctext, len, key, digest, cb)


/**
 *  callback ~ verify encrypted data
 *  @param {string/byteArray/uint8Array} sig ~ first signature
 *  @param {string/byteArray/uint8Array} sig ~ second signature
 *  @param {string} digest ~ hmac key digest hex/bytes/binary/uint8/base64
 *  @param {function} cb ~ callback function(err,data)
 **/

rabbit.poly1305.verify(sig1, sig2, digest, cb)


/**
 *  callback ~ verify encrypted data
 *  @param {string/byteArray/uint8Array} ctext ~ cipher text
 *  @param {integer} len ~ cipher text length
 *  @param {string/byteArray/uint8Array} key ~ poly1305 key
 *  @param {string} digest ~ hmac key digest hex/bytes/binary/uint8/base64
 **/

rabbit.poly1305.signSync(ctext, len, key, digest)


/**
 *  sync ~ verify encrypted data
 *  @param {string/byteArray/uint8Array} sig ~ first signature
 *  @param {string/byteArray/uint8Array} sig ~ second signature
 *  @param {string} digest ~ hmac key digest hex/bytes/binary/uint8/base64
 **/

rabbit.poly1305.verifySync(sig1, sig2, digest)


// demo

const utils = rabbit.utils,
cl = console.log,
ce = console.error,
secret = 'secret',
skey = utils.randomBytes(32),
text = 'test',
digest = 'hex';

// enc/dec ~ sync
let sync = rabbit.encSync(text, secret, digest);
cl(sync)
sync = rabbit.decSync(sync, secret, digest)
cl(sync === text)



// enc/dec ~ callback
rabbit.enc(text, secret, digest, function(err, ctext){
  if(err){return ce(err)};
  rabbit.dec(ctext, secret, digest, function(err, plain){
    if(err){return ce(err)};
    cl(plain === text);
  });
});


// enc/dec ~ promise
rabbit.encP(text, secret, digest).then(function(ctext){
  rabbit.decP(ctext, secret, digest).then(function(plain){
      cl(plain === text);
  }).catch(function(err){
    ce(err)
  })
}).catch(function(err){
  ce(err)
})

// encrypt/decrypt with poly1305 ~ callback
rabbit.encPoly(text, secret, skey, digest, function(err, res){
  if(err){return ce(err)};

  let verify = rabbit.poly1305.signSync(res.ctext, res.ctext.length, skey, digest);

  rabbit.decPoly(res.ctext, secret, res.sig, verify, digest, function(err, plain){
    if(err){return ce(err)};
    cl(plain)
  });

});

// encrypt/decrypt with poly1305 ~ promise
rabbit.encPolyP(text, secret, skey, digest).then(function(res){
  let verify = rabbit.poly1305.signSync(res.ctext, res.ctext.length, skey, digest);
  rabbit.decPolyP(res.ctext, secret, res.sig, verify, digest).then(function(plain){
    cl(plain)
  }).catch(function(err){
    ce(err)
  })
}).catch(function(err){
  ce(err)
})


// poly1305
rabbit.enc(text, secret, digest, function(err, ctext){
  if(err){return ce(err)};

  // poly1305 ~ callback
  rabbit.poly1305.sign(ctext, ctext.length, skey, digest, function(err, sig){

    // poly1305 ~ sync
    let verify = rabbit.poly1305.signSync(ctext, ctext.length, skey, digest);

    rabbit.poly1305.verify(sig, verify, digest, function(err, ver){
      if(ver){
        rabbit.dec(ctext, secret, digest, function(err, plain){
          if(err){return ce(err)};
          cl(plain);
        });
      } else {
        ce('rabbit poly1305 authentication failure')
      }
    });

  })
});

```
