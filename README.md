# rabbit-cipher
rabbit 128bit cipher with poly1305


```js


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
