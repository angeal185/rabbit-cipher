utils = rabbit.utils;

const secret = Uint8Array.from([203,196,152,39,91,195,93,162,88,22,54,166,98,175,200,160,35,79,72,66,191,254,100,222,171,163,144,238,1,82,54,13]),
ssecret = Uint8Array.from([54, 234, 131, 116, 246, 28, 241, 135, 32, 61, 81, 55, 167, 112, 215, 15, 245, 75, 54, 86, 10, 127, 254, 103, 34, 204, 101, 198, 53, 14, 77, 230]),
salt = Uint8Array.from([160,186,222,162,146,27,253,129,227,204,174,58,3,229,212,222,162,165,218,43,113,85,155,108,118,101,89,167,203,1,215,235]),
text = 'test',
digest = 'base64';

console.log(ssecret)



//sync test
let sync = rabbit.encSync('test', secret, 'Uint8');
console.log(sync)
sync = rabbit.decSync(sync, secret, 'Uint8')
console.log(sync)



rabbit.PBKDF2(secret, salt, function(err,rkey){
  if(err){return console.error(err)};
  console.log(rkey);

  rabbit.enc(text, rkey, digest, function(err, ctext){
    if(err){return console.error(err)};

    let obj = {
      ctext: ctext,
      smac: rabbit.poly1305.sign(ctext, ctext.length, ssecret, digest)
    }
    console.log(obj);

  });
});

let encData = {ctext: "R8zSPPiLmVeVSMuC", smac: "VuEse1+D0/rJWHRZPXuftQ=="}

rabbit.PBKDF2(secret, salt, function(err,rkey){

  let verify = rabbit.poly1305.verify(
    encData.smac,
    rabbit.poly1305.sign(encData.ctext, encData.ctext.length, ssecret, digest),
    digest
  );

  if(verify){
    rabbit.dec(encData.ctext, rkey, digest, function(err, plain){
      if(err){return console.error(err)};
      console.log(plain);
    });
  } else {
    console.error('rabbit poly1305 authentication failure')
  }
});
