/*
 * Browser-based Web Push client for the application server piece.
 *
 * Uses the WebCrypto API.  Polyfill: http://polycrypt.net/
 * Uses the fetch API.  Polyfill: https://github.com/github/fetch
 */

(function (g) {
  'use strict';

  var P256DH = {
    name: 'ECDH',
    namedCurve: 'P-256'
  };
  var webCrypto = g.crypto.subtle;
  var INFO = new TextEncoder('utf-8').encode("Content-Encoding: aesgcm128");

  function chunkArray(array, size) {
    var index = 0;
    var result = [];
    while(index + size <= array.length) {
      result.push(array.slice(index, index + size));
      index += size;
    }
    if (index < array.length) {
      result.push(array.slice(index));
    }
    if (result.length === 0) {
      result.push(new Uint8Array(0));
    }
    return result;
  }

  /* I can't believe that this is needed here, in this day and age ... */
  var base64url = {
    _strmap: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
    encode: function(data) {
      var len = Math.ceil(data.length * 4 / 3);
      return chunkArray(data, 3).map(chunk => [
        chunk[0] >>> 2,
        ((chunk[0] & 0x3) << 4) | (chunk[1] >>> 4),
        ((chunk[1] & 0xf) << 2) | (chunk[2] >>> 6),
        chunk[2] & 0x3f
      ].map(v => base64url._strmap[v]).join('')).join('').slice(0, len);
    },
    _lookup: function(s, i) {
      return base64url._strmap.indexOf(s.charAt(i));
    },
    decode: function(str) {
      var v = new Uint8Array(Math.floor(str.length * 3 / 4));
      var vi = 0;
      for (var si = 0; si < str.length;) {
        var w = base64url._lookup(str, si++);
        var x = base64url._lookup(str, si++);
        var y = base64url._lookup(str, si++);
        var z = base64url._lookup(str, si++);
        v[vi++] = w << 2 | x >>> 4;
        v[vi++] = x << 4 | y >>> 2;
        v[vi++] = y << 6 | z;
      }
      return v;
    }
  };

  /* Coerces data into a Uint8Array */
  function ensureView(data) {
    if (typeof data === 'string') {
      return new TextEncoder('utf-8').encode(data);
    }
    if (data instanceof ArrayBuffer) {
      return new Uint8Array(data);
    }
    if (ArrayBuffer.isView(data)) {
      return new Uint8Array(data.buffer);
    }
    throw new Error('webpush() needs a string or BufferSource');
  }

  function concatArrayViews(arrays) {
    var size = arrays.reduce((total, a) => total + a.length, 0);
    var result = new Uint8Array(size);
    var index = 0;
    arrays.forEach(a => {
      result.set(a, index);
      index += a.length;
    });
    return result;
  }

  function hmac(key) {
    this.keyPromise = webCrypto.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' },
                                          false, ['sign']);
  }
  hmac.prototype.hash = function(input) {
    return this.keyPromise.then(k => webCrypto.sign('HMAC', k, input));
  }

  function hkdf(salt, ikm, info, len) {
    return new hmac(salt).hash(ikm)
      .then(prk => new hmac(prk))
      .then(prkh => {
        var output = [];
        var counter = new Uint8Array(1);

        function hkdf_iter(t) {
          if (++counter[0] === 0) {
            throw new Error('Too many hmac invocations for hkdf');
          }
          return prkh.hash(concatArrayViews([t, info, counter]))
            .then(tnext => {
              tnext = new Uint8Array(tnext);
              output.push(tnext);
              if (output.reduce((sum, a) => sum + a.length, 0) >= len) {
                return output;
              }
              return hkdf_iter(tnext);
            });
        }

        return hkdf_iter(new Uint8Array(0));
      })
      .then(chunks => concatArrayViews(chunks).slice(0, len));
  }

  /* generate a 96-bit IV for use in GCM, 48-bits of which are populated */
  function generateIV(index) {
    var iv = new Uint8Array(12);
    for (var i = 0; i < 6; ++i) {
      iv[iv.length - 1 - i] = (index / Math.pow(256, i)) & 0xff;
    }
    return iv;
  }

  // DER encoding describing an ECDH public key on P-256
  var spkiPrefix = Uint8Array.from([
    48, 86, 48, 16, 6, 4, 43, 129, 4, 112, 6, 8,
    42, 134, 72, 206, 61, 3, 1, 7, 3, 66, 0
  ]);

  function encrypt(localKey, remoteShare, salt, data) {
    return webCrypto.importKey('spki', concatArrayViews([spkiPrefix, remoteShare]),
                               P256DH, false, ['deriveBits'])
      .then(remoteKey =>
            webCrypto.deriveBits({ name: P256DH.name, public: remoteKey },
                                 localKey, 256))
      .then(rawKey =>
            hkdf(salt, new Uint8Array(rawKey), INFO, 16))
      .then(gcmBits =>
            webCrypto.importKey('raw', gcmBits, 'AES-GCM', false, ['encrypt']))
      .then(gcmKey => {
        // 4096 is the default size, though we burn 1 for padding
        return Promise.all(chunkArray(data, 4095).map((slice, index) => {
          var padded = concatArrayViews([new Uint8Array(1), slice]);
          return webCrypto.encrypt({ name: 'AES-GCM', iv: generateIV(index) },
                                   gcmKey, padded);
        }));
      }).then(r => concatArrayViews(r.map(a => new Uint8Array(a))));
  }

  /*
   * Request push for a message.  This returns a promise that resolves when the
   * push has been delivered to the push service.
   *
   * @param subscription A PushSubscription that contains endpoint and p256dh
   *                     parameters.
   * @param data         The message to send.
   */
  function webpush(subscription, data) {
    data = ensureView(data);

    var salt = g.crypto.getRandomValues(new Uint8Array(16));
    return webCrypto.generateKey(P256DH, false, ['deriveBits'])
      .then(localKey => {
        return Promise.all([
          encrypt(localKey.privateKey, subscription.p256dh, salt, data),
          // 1337 p-256 specific haxx to get the raw value out of the spki value
          webCrypto.exportKey('spki', localKey.publicKey)
            .then(spki => new Uint8Array(spki, spkiPrefix.length))
        ]);
      }).then(results => {
        return fetch(subscription.endpoint, {
          method: 'PUT',
          headers: {
            'Encryption-Key': 'keyid=p256dh;dh=' + base64url.encode(results[1]),
            Encryption: 'keyid=p256dh;salt=' + base64url.encode(salt)
          },
          body: results[0]
        });
      }).then(response => {
        if (response.status / 100 !== 2) {
          throw new Error('Unable to deliver message');
        }
      });
  }

  g.webpush = webpush;
}(this));
