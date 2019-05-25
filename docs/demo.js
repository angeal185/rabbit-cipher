const utils = rabbit.utils,
cl = console.log,
ce = console.error,
secret = 'secret',
skey = utils.randomBytes(32),
text = 'test',
digest = 'hex';

/*
//sync test
let sync = rabbit.encSync('test', secret, 'base64');
console.log(sync)
sync = rabbit.decSync(sync, secret, 'base64')
console.log(sync)
*/

/*
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
*/

rabbit.encPoly(text, secret, skey, digest, function(err, res){
  if(err){return ce(err)};

  let verify = rabbit.poly1305.signSync(res.ctext, res.ctext.length, skey, digest);

  rabbit.decPoly(res.ctext, secret, res.sig, verify, digest, function(err, plain){
    if(err){return ce(err)};
    cl(plain)
  });

});

/*
rabbit.enc(text, secret, digest, function(err, ctext){
  if(err){return console.error(err)};

  rabbit.poly1305.sign(ctext, ctext.length, skey, digest, function(err, sig){

    let verify = rabbit.poly1305.signSync(ctext, ctext.length, skey, digest);

    rabbit.poly1305.verify(sig, verify, digest, function(err, ver){
      if(ver){
        rabbit.dec(ctext, secret, digest, function(err, plain){
          if(err){return console.error(err)};
          console.log(plain);
        });
      } else {
        console.error('rabbit poly1305 authentication failure')
      }
    });

  })
});
*/

//pdkf2 test
