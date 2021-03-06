//rabbit cipher in javascript
const crypto = require('crypto');

function RABBIT(){

  const cnv = {
    bin2int : s => parseInt(s, 2),
    dec2bin : s => parseInt(s, 10).toString(2),
    hex2int : s => parseInt(s, 16)
  };

  const util = {
    u82s: function(STR) {
      let str = ''
      for (var i=0; i <  STR.byteLength; i++) {
          str += String.fromCharCode(STR[i])
      }
      return str;
    },
    s2u8: function(string) {
      let arrayBuffer = new ArrayBuffer(string.length * 1),
      newUint = new Uint8Array(arrayBuffer);
      newUint.forEach((_, i) => {
        newUint[i] = string.charCodeAt(i);
      });
      return newUint;
    },
    a2b: function(byteArray) {
      return Array.from(byteArray, function(byte) {
        return cnv.dec2bin(byte);
      })//.join('')
    },
    b2a: function(byteArray) {
      return Array.from(byteArray, function(byte) {
        return cnv.bin2int(byte);
      })//.join('')
    },
    s2h: function(byteArray) {
      return Array.from(byteArray, function(byte) {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
      }).join('')
    },
    u82a: function(uint8Array) {
      var array = [];
      for (var i = 0; i < uint8Array.byteLength; i++) {
        array[i] = uint8Array[i];
      }
      return array;
    },
    s2b: function(str) {
      var result = [];
      for (var i = 0; i < str.length; i++) {
        result.push(str.charCodeAt(i));
      }
      return result;
    },
    b2s:function(array) {
      return Buffer.from(array).toString('binary');
    },
    h2s: function(str){
      var hexString = str,
      arr = [];
        for (var x = 0; x < hexString.length; x += 2) {
          let num = hexString.substr(x, 2);
          arr.push(cnv.hex2int(num));
        }
      return arr;
    },
    h2u8: function(i){
      return new Uint8Array(util.h2s(i))
    },
    u82h: function(i){
      return util.s2h(util.a2b(i))
    },
    rotl: function (n, b) {
      return (n << b) | (n >>> (32 - b));
    },
    endian: function (n) {
      if (n.constructor == Number) {
        return util.rotl(n,  8) & 0x00FF00FF |
               util.rotl(n, 24) & 0xFF00FF00;
      }

      for (var i = 0; i < n.length; i++)
        n[i] = util.endian(n[i]);
      return n;

    },
    randomRange: function(max){
        const diff = max + 1;
        const numberBit = Math.ceil(Math.log2(diff));
        const numberBytes = Math.ceil(numberBit / 4);
        const mask = (1 << numberBit) - 1;
        let randomNumber;
        do {
            randomNumber = crypto.randomBytes(numberBytes).readUIntBE(0, numberBytes);
            randomNumber = randomNumber & mask;
        } while (randomNumber >= diff);
        return randomNumber + 0;
    },
    randomBytes: function (n) {
      for (var bytes = []; n > 0; n--)
        bytes.push(util.randomRange(256));
      return bytes;
    },
    bytesToWords: function (bytes) {
      for (var words = [], i = 0, b = 0; i < bytes.length; i++, b += 8)
        words[b >>> 5] |= bytes[i] << (24 - b % 32);
      return words;
    },
    isUint8: function(i){
      if(Object.prototype.toString.call(i) === '[object Uint8Array]' && typeof i === 'object'){
        return true
      }
      return false
    },
    isArray: function(i){
      if(Object.prototype.toString.call(i) === '[object Array]'  && typeof i === 'object'){
        return true
      }
      return false
    },
    isString: function(i){
      if(Object.prototype.toString.call(i) === '[object String]' && typeof i === 'string'){
        return true
      }
      return false
    },
    u8to16: function(p, pos) {
      return (p[pos] & 0xff) | ((p[pos+1] & 0xff) << 8);
    },
    u16to8: function(p, pos, v) {
      p[pos]   = v;
      p[pos+1] = v >>> 8;
    }
  };

  function checkKey(digest, i, cpt){
    digest = digest.toLowerCase();
    try {
      if(cpt === true){
        if(digest !== 'uint8'){
          i = util.u82a(i)
          if(digest === 'base64'){
            i = Buffer.from(i).toString('base64');
          } else if (digest === 'hex') {
            i = util.s2h(i);
          } else if (digest === 'binary') {
            i = util.a2b(i);
          } else if (digest === 'bytes') {
            i = util.b2s(i);
          } else {
            i = i
          }
          return i;
        }
        return i;
      } else {
        if(digest !== 'uint8'){
          if(digest === 'base64'){
            i = util.s2b(Buffer.from(i, 'base64').toString('binary'));
          } else if (digest === 'hex'){
            i = util.h2s(i);
          } else if (digest === 'binary'){
            i = util.b2a(i);
          } else if (digest === 'bytes'){
            i = util.s2b(i)
          }
          return new Uint8Array(i);
        }
        return i
      }
    } catch (err) {
      return 'rabbit encode mismatch';
    }

  }

  let x = [],c = [],b;

  const Rabbit = {
    _rabbit: function (m, k, iv) {

      Rabbit.keysetup(k);
      if (iv) Rabbit.ivsetup(iv);

      for (var s = [], i = 0; i < m.length; i++) {
        if (i % 16 == 0) {

          Rabbit.nextstate();
          // Generate 16 bytes of pseudo-random data
          s[0] = x[0] ^ (x[5] >>> 16) ^ (x[3] << 16);
          s[1] = x[2] ^ (x[7] >>> 16) ^ (x[5] << 16);
          s[2] = x[4] ^ (x[1] >>> 16) ^ (x[7] << 16);
          s[3] = x[6] ^ (x[3] >>> 16) ^ (x[1] << 16);

          for (var j = 0; j < 4; j++) {
            s[j] = ((s[j] <<  8) | (s[j] >>> 24)) & 0x00FF00FF |
                   ((s[j] << 24) | (s[j] >>>  8)) & 0xFF00FF00;
          }

          for (var b = 120; b >= 0; b -= 8) {
            s[b / 8] = (s[b >>> 5] >>> (24 - b % 32)) & 0xFF;
          }

        }

        m[i] ^= s[i % 16];

      }

    },
    keysetup: function (k) {

      x[0] = k[0];
      x[2] = k[1];
      x[4] = k[2];
      x[6] = k[3];
      x[1] = (k[3] << 16) | (k[2] >>> 16);
      x[3] = (k[0] << 16) | (k[3] >>> 16);
      x[5] = (k[1] << 16) | (k[0] >>> 16);
      x[7] = (k[2] << 16) | (k[1] >>> 16);

      c[0] = util.rotl(k[2], 16);
      c[2] = util.rotl(k[3], 16);
      c[4] = util.rotl(k[0], 16);
      c[6] = util.rotl(k[1], 16);
      c[1] = (k[0] & 0xFFFF0000) | (k[1] & 0xFFFF);
      c[3] = (k[1] & 0xFFFF0000) | (k[2] & 0xFFFF);
      c[5] = (k[2] & 0xFFFF0000) | (k[3] & 0xFFFF);
      c[7] = (k[3] & 0xFFFF0000) | (k[0] & 0xFFFF);

      b = 0;

      for (var i = 0; i < 4; i++){
        Rabbit.nextstate();
      }

      for (var i = 0; i < 8; i++) {
        c[i] ^= x[(i + 4) & 7];
      }
    },
    ivsetup: function (iv) {

      let i0 = util.endian(iv[0]),
      i2 = util.endian(iv[1]),
      i1 = (i0 >>> 16) | (i2 & 0xFFFF0000),
      i3 = (i2 <<  16) | (i0 & 0x0000FFFF);

      c[0] ^= i0;
      c[1] ^= i1;
      c[2] ^= i2;
      c[3] ^= i3;
      c[4] ^= i0;
      c[5] ^= i1;
      c[6] ^= i2;
      c[7] ^= i3;

      for (var i = 0; i < 4; i++){
        Rabbit.nextstate();
      }

    },
    nextstate: function() {

      for (var c_old = [], i = 0; i < 8; i++){
        c_old[i] = c[i];
      }

      c[0] = (c[0] + 0x4D34D34D + b) >>> 0;
      c[1] = (c[1] + 0xD34D34D3 + ((c[0] >>> 0) < (c_old[0] >>> 0) ? 1 : 0)) >>> 0;
      c[2] = (c[2] + 0x34D34D34 + ((c[1] >>> 0) < (c_old[1] >>> 0) ? 1 : 0)) >>> 0;
      c[3] = (c[3] + 0x4D34D34D + ((c[2] >>> 0) < (c_old[2] >>> 0) ? 1 : 0)) >>> 0;
      c[4] = (c[4] + 0xD34D34D3 + ((c[3] >>> 0) < (c_old[3] >>> 0) ? 1 : 0)) >>> 0;
      c[5] = (c[5] + 0x34D34D34 + ((c[4] >>> 0) < (c_old[4] >>> 0) ? 1 : 0)) >>> 0;
      c[6] = (c[6] + 0x4D34D34D + ((c[5] >>> 0) < (c_old[5] >>> 0) ? 1 : 0)) >>> 0;
      c[7] = (c[7] + 0xD34D34D3 + ((c[6] >>> 0) < (c_old[6] >>> 0) ? 1 : 0)) >>> 0;
      b = (c[7] >>> 0) < (c_old[7] >>> 0) ? 1 : 0;

      for (var g = [], i = 0; i < 8; i++) {

        let gx = (x[i] + c[i]) >>> 0,
        ga = gx & 0xFFFF,
        gb = gx >>> 16,
        gh = ((((ga * ga) >>> 17) + ga * gb) >>> 15) + gb * gb,
        gl = (((gx & 0xFFFF0000) * gx) >>> 0) + (((gx & 0x0000FFFF) * gx) >>> 0) >>> 0;

        g[i] = gh ^ gl;

      }

      x[0] = g[0] + ((g[7] << 16) | (g[7] >>> 16)) + ((g[6] << 16) | (g[6] >>> 16));
      x[1] = g[1] + ((g[0] <<  8) | (g[0] >>> 24)) + g[7];
      x[2] = g[2] + ((g[1] << 16) | (g[1] >>> 16)) + ((g[0] << 16) | (g[0] >>> 16));
      x[3] = g[3] + ((g[2] <<  8) | (g[2] >>> 24)) + g[1];
      x[4] = g[4] + ((g[3] << 16) | (g[3] >>> 16)) + ((g[2] << 16) | (g[2] >>> 16));
      x[5] = g[5] + ((g[4] <<  8) | (g[4] >>> 24)) + g[3];
      x[6] = g[6] + ((g[5] << 16) | (g[5] >>> 16)) + ((g[4] << 16) | (g[4] >>> 16));
      x[7] = g[7] + ((g[6] <<  8) | (g[6] >>> 24)) + g[5];

    },
    encrypt: function (plain, secret, digest) {
      let iv = util.randomBytes(8);

      if(!util.isUint8(secret)){
        if(util.isString(secret)){
          secret = util.s2u8(secret)
        }
        if(util.isArray(secret)){
          secret = new Uint8Array(secret)
        }
      }

      plain = util.s2b(plain);

      Rabbit._rabbit(plain, secret, util.bytesToWords(iv));
      return checkKey(digest, new Uint8Array(iv.concat(plain)), true);
    },
    decrypt: function (ctext, secret, digest) {
      ctext = checkKey(digest, ctext, false);

      if(!util.isUint8(secret)){
        if(util.isString(secret)){
          secret = util.s2u8(secret)
        }
        if(util.isArray(secret)){
          secret = new Uint8Array(secret)
        }
      }

      let iv = ctext.slice(0,8),
      ciphertext = ctext.slice(8);
      Rabbit._rabbit(ciphertext, secret, util.bytesToWords(iv));
      return util.b2s(ciphertext);
    }
  };

  // Poly1305KeySize = 32;
  // Poly1305TagSize = 16;

  var Poly1305 = function(key) {
    this.buffer = new Uint8Array(16);
    this.leftover = 0;
    this.r = new Uint16Array(10);
    this.h = new Uint16Array(10);
    this.pad = new Uint16Array(8);
    this.finished = 0;

    let t = new Uint16Array(8),
    i;

    for (i = 8; i--;){
      t[i] = util.u8to16(key, i * 2);
    }

    this.r[0] =   t[0]                         & 0x1fff;
    this.r[1] = ((t[0] >>> 13) | (t[1] <<  3)) & 0x1fff;
    this.r[2] = ((t[1] >>> 10) | (t[2] <<  6)) & 0x1f03;
    this.r[3] = ((t[2] >>>  7) | (t[3] <<  9)) & 0x1fff;
    this.r[4] = ((t[3] >>>  4) | (t[4] << 12)) & 0x00ff;
    this.r[5] =  (t[4] >>>  1)                 & 0x1ffe;
    this.r[6] = ((t[4] >>> 14) | (t[5] <<  2)) & 0x1fff;
    this.r[7] = ((t[5] >>> 11) | (t[6] <<  5)) & 0x1f81;
    this.r[8] = ((t[6] >>>  8) | (t[7] <<  8)) & 0x1fff;
    this.r[9] =  (t[7] >>>  5)                 & 0x007f;

    for (i = 8; i--;) {
      this.h[i]   = 0;
      this.pad[i] = util.u8to16(key, 16+(2*i));
    }

    this.h[8] = 0;
    this.h[9] = 0;
    this.leftover = 0;
    this.finished = 0;

  };

  Poly1305.prototype.blocks = function(m, mpos, bytes) {
    let hibit = this.finished ? 0 : (1 << 11);
    let t = new Uint16Array(8),
        d = new Uint32Array(10),
        c = 0, i = 0, j = 0;

    while (bytes >= 16) {

      for (i = 8; i--;){
        t[i] = util.u8to16(m, i * 2 + mpos);
      }

      this.h[0] +=   t[0]                         & 0x1fff;
      this.h[1] += ((t[0] >>> 13) | (t[1] <<  3)) & 0x1fff;
      this.h[2] += ((t[1] >>> 10) | (t[2] <<  6)) & 0x1fff;
      this.h[3] += ((t[2] >>>  7) | (t[3] <<  9)) & 0x1fff;
      this.h[4] += ((t[3] >>>  4) | (t[4] << 12)) & 0x1fff;
      this.h[5] +=  (t[4] >>>  1)                 & 0x1fff;
      this.h[6] += ((t[4] >>> 14) | (t[5] <<  2)) & 0x1fff;
      this.h[7] += ((t[5] >>> 11) | (t[6] <<  5)) & 0x1fff;
      this.h[8] += ((t[6] >>>  8) | (t[7] <<  8)) & 0x1fff;
      this.h[9] +=  (t[7] >>>  5)                 | hibit;

      for (i = 0, c = 0; i < 10; i++) {
        d[i] = c;
        for (j = 0; j < 10; j++) {
          d[i] += (this.h[j] & 0xffffffff) * ((j <= i) ? this.r[i-j] : (5 * this.r[i+10-j]));
          if (j === 4) {
            c = (d[i] >>> 13);
            d[i] &= 0x1fff;
          }
        }
        c += (d[i] >>> 13);
        d[i] &= 0x1fff;
      }
      c = ((c << 2) + c);
      c += d[0];
      d[0] = ((c & 0xffff) & 0x1fff);
      c = (c >>> 13);
      d[1] += c;

      for (i = 10; i--;){
        this.h[i] = d[i];
      }

      mpos += 16;
      bytes -= 16;

    }
  };

  Poly1305.prototype.update = function(m, bytes) {
    let want = 0, i = 0, mpos = 0;

    if (this.leftover) {
      want = 16 - this.leftover;
      if (want > bytes){
        want = bytes;
      }
      for (i = want; i--;) {
        this.buffer[this.leftover+i] = m[i+mpos];
      }
      bytes -= want;
      mpos += want;
      this.leftover += want;
      if (this.leftover < 16){
        return;
      }
      this.blocks(this.buffer, 0, 16);
      this.leftover = 0;
    }

    if (bytes >= 16) {
      want = (bytes & ~(16 - 1));
      this.blocks(m, mpos, want);
      mpos += want;
      bytes -= want;
    }

    if (bytes) {
      for (i = bytes; i--;) {
        this.buffer[this.leftover+i] = m[i+mpos];
      }
      this.leftover += bytes;
    }
  };

  Poly1305.prototype.finish = function() {
    let mac = new Uint8Array(16),
    g = new Uint16Array(10),
    c = 0, mask = 0, f = 0, i = 0;

    if (this.leftover) {
      i = this.leftover;
      this.buffer[i++] = 1;
      for (; i < 16; i++) {
        this.buffer[i] = 0;
      }
      this.finished = 1;
      this.blocks(this.buffer, 0, 16);
    }

    c = this.h[1] >>> 13;
    this.h[1] &= 0x1fff;
    for (i = 2; i < 10; i++) {
      this.h[i] += c;
      c = this.h[i] >>> 13;
      this.h[i] &= 0x1fff;
    }
    this.h[0] += (c * 5);
    c = this.h[0] >>> 13;
    this.h[0] &= 0x1fff;
    this.h[1] += c;
    c = this.h[1] >>> 13;
    this.h[1] &= 0x1fff;
    this.h[2] += c;

    g[0] = this.h[0] + 5;
    c = g[0] >>> 13;
    g[0] &= 0x1fff;
    for (i = 1; i < 10; i++) {
      g[i] = this.h[i] + c;
      c = g[i] >>> 13;
      g[i] &= 0x1fff;
    }
    g[9] -= (1 << 13);

    mask = (g[9] >>> 15) - 1;
    for (i = 10; i--;) {
      g[i] &= mask;
    }
    mask = ~mask;
    for (i = 10; i--;) {
      this.h[i] = (this.h[i] & mask) | g[i];
    }

    this.h[0] = (this.h[0]      ) | (this.h[1] << 13);
    this.h[1] = (this.h[1] >>  3) | (this.h[2] << 10);
    this.h[2] = (this.h[2] >>  6) | (this.h[3] <<  7);
    this.h[3] = (this.h[3] >>  9) | (this.h[4] <<  4);
    this.h[4] = (this.h[4] >> 12) | (this.h[5] <<  1) | (this.h[6] << 14);
    this.h[5] = (this.h[6] >>  2) | (this.h[7] << 11);
    this.h[6] = (this.h[7] >>  5) | (this.h[8] <<  8);
    this.h[7] = (this.h[8] >>  8) | (this.h[9] <<  5);

    f = (this.h[0] & 0xffffffff) + this.pad[0];
    this.h[0] = f;
    for (i = 1; i < 8; i++) {
      f = (this.h[i] & 0xffffffff) + this.pad[i] + (f >>> 16);
      this.h[i] = f;
    }

    for (i = 8; i--;) {
      util.u16to8(mac, i*2, this.h[i]);
      this.pad[i] = 0;
    }
    for (i = 10; i--;) {
      this.h[i] = 0;
      this.r[i] = 0;
    }

    return mac;
  };

  const poly1305 = {
    signSync: function(m, bytes, key, digest) {
      if(util.isString(key)){
        key = util.s2u8(key)
      }
      var ctx = new Poly1305(key);
      ctx.update(m, bytes);
      return checkKey(digest, ctx.finish(), true)
    },
    verifySync: function(mac1, mac2, digest) {
      mac1 = checkKey(digest, mac1, false);
      mac2 = checkKey(digest, mac2, false)
      var dif = 0;
      for (var i = 0; i < 16; i++) {
        dif |= (mac1[i] ^ mac2[i]);
      }
      dif = (dif - 1) >>> 31;
      return (dif & 1);
    },
    sign: function(m, bytes, key, digest, cb) {
      try {
        let res = poly1305.signSync(m, bytes, key, digest);
        cb(false, res);
        return;
      } catch (err) {
        cb(err, null)
      }
    },
    verify: function(mac1, mac2, digest, cb) {
      try {
        let res = poly1305.verifySync(mac1, mac2, digest);
        cb(false, res);
        return;
      } catch (err) {
        cb(err, null)
      }
    }
  }

  return {
    enc: function(plain, secret, digest, cb){
      try {
        cb(false, Rabbit.encrypt(plain, secret, digest))
        return;
      } catch (err) {
        cb(err, null)
      }
    },
    encP: function(plain, secret, digest){
      return new Promise(function(resolve, reject){
        try {
          let res = Rabbit.encrypt(plain, secret, digest);
          resolve(res);
        } catch (err) {
          reject('rabbit encrypt error');
        }
      })
    },
    encPoly: function(plain, secret, skey, digest, cb){
      try {
        let obj = {
          ctext: Rabbit.encrypt(plain, secret, digest)
        }
        let ctext = Rabbit.encrypt(plain, secret, digest)
        poly1305.sign(obj.ctext, obj.ctext.length, skey, digest, function(err, sig){
          if(err){return cb(err, null)}
          obj.sig = sig;
          cb(false, obj)
        })
        return;
      } catch (err) {
        cb(err, null)
      }
    },
    encPolyP: function(plain, secret, skey, digest){
      return new Promise(function(resolve, reject){
        try {
          let obj = {
            ctext: Rabbit.encrypt(plain, secret, digest)
          }
          let ctext = Rabbit.encrypt(plain, secret, digest)
          poly1305.sign(obj.ctext, obj.ctext.length, skey, digest, function(err, sig){
            if(err){return reject(err)}
            obj.sig = sig;
            resolve(obj)
          })
          return;
        } catch (err) {
          reject(err)
        }
      })
    },
    dec: function(ctext, secret, digest, cb){
      try {
        cb(false, Rabbit.decrypt(ctext, secret, digest))
        return;
      } catch (err) {
        cb(err, null)
      }
    },
    decP: function(ctext, secret, digest){
      return new Promise(function(resolve, reject){
        try {
          let res = Rabbit.decrypt(ctext, secret, digest);
          resolve(res);
        } catch (err) {
          reject('rabbit encrypt error');
        }
      })
    },
    decPoly: function(ctext, secret, skey, skey2, digest, cb){
      try {
        poly1305.verify(skey, skey2, digest, function(err, ver){
          if(ver){
            cb(false, Rabbit.decrypt(ctext, secret, digest))
            return;
          } else {
            cb('rabbit poly1305 authentication failure', null)
          }
        });
      } catch (err) {
        cb(err, null)
      }
    },
    decPolyP: function(ctext, secret, skey, skey2, digest, cb){
      return new Promise(function(resolve, reject){
        try {
          poly1305.verify(skey, skey2, digest, function(err, ver){
            if(ver){
              resolve(Rabbit.decrypt(ctext, secret, digest))
              return;
            } else {
              reject('poly1305 authentication failure')
            }
          });
        } catch (err) {
          reject('rabbit decrypt error');
        }
      })
    },
    encSync: Rabbit.encrypt,
    decSync: Rabbit.decrypt,
    poly1305: poly1305,
    utils: util
  }
}


module.exports = RABBIT();
