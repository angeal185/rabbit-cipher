const rabbit = require('../');
crypto = require('crypto'),
cl = console.log,
ce = console.error,
utils = rabbit.utils;
secret = 'secret',
skey = utils.randomBytes(32),
salt = 'salt',
text = 'test',
digest = 'base64';
/*
//sync test
let sync = rabbit.encSync('test', secret, 'base64');
cl(sync)
sync = rabbit.decSync(sync, secret, 'base64')
cl(sync)
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
  if(err){return ce(err)};

  rabbit.poly1305.sign(ctext, ctext.length, skey, digest, function(err, sig){

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
*/