const utils = rabbit.utils,
secret = Uint8Array.from(utils.randomBytes(32)),
ssecret = Uint8Array.from(utils.randomBytes(32)),
salt = Uint8Array.from(utils.randomBytes(32)),
text = 'test',
digest = 'hex';

//sync test
let sync = rabbit.encSync('test', secret, 'Uint8');
sync = rabbit.decSync(sync, secret, 'Uint8')
if(sync === text){
  console.log('sync test pass');
}

// enc/dec test
rabbit.enc(text, secret, digest, function(err, ctext){
  if(err){return console.error(err)};
  rabbit.dec(ctext, secret, digest, function(err, plain){
    if(err){return console.error(err)};
    if(plain === text){
      console.log('enc/dec test pass');
    }
  });
});

// rabbit-pbkdf2-poly1305
rabbit.PBKDF2(secret, salt, function(err,rkey){
  if(err){return console.error(err)};
  console.log(rkey);

  rabbit.enc(text, rkey, digest, function(err, ctext){
    if(err){return console.error(err)};

    let encData = {
      ctext: ctext,
      smac: rabbit.poly1305.sign(ctext, ctext.length, ssecret, digest)
    }
    //console.log(encData);
    let verify = rabbit.poly1305.verify(
      encData.smac,
      rabbit.poly1305.sign(encData.ctext, encData.ctext.length, ssecret, digest),
      digest
    );

    if(verify){
      rabbit.dec(encData.ctext, rkey, digest, function(err, plain){
        if(err){return console.error(err)};
        //console.log(plain);
        if(plain === text){
          console.log('rabbit-pbkdf2-poly1305 test pass');
        }
      });
    } else {
      console.error('rabbit poly1305 authentication failure')
    }

  });
});

//pdkf2 test
rabbit.PBKDF2(secret, salt, function(err,rkey){
  if(err){return console.error(err)};
  console.log(rkey);
});
