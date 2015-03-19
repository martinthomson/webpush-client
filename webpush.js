/*
 * Browser-based Web Push client for the application server piece.
 *
 * Uses the WebCrypto API.
 * Uses the fetch API, which might need to be polyfilled:
 * <https://github.com/github/fetch>.
 */

//(function (g) {
var g = this;

  var P256DH = {
    name: 'ECDH',
    namedCurve: 'P-256'
  };
  var crypto = g.crypto.subtle;
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
    encode: function(data) {
      var strmap = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
      var len = Math.ceil(data.length / 3 * 4);
      return chunkArray(data, 3).map(chunk => [
        chunk[0] >>> 2,
        ((chunk[0] & 0x3) << 4) | (chunk[1] >>> 4),
        ((chunk[1] & 0xf) << 2) | (chunk[2] >>> 6),
        chunk[2] & 0x3f
      ].map(v => strmap[v]).join('')).join('').slice(0, len);
    }
  };

  /* Coerces data into a Uint8Array */
  function ensureView(data) {
    if (typeof data === 'string') {
      return new TextEncoder('utf-8').encode(data);
    }
    if (data instanceof ArrayBuffer) {
      return Uint8Array.from(data);
    }
    if (ArrayBuffer.isView(data)) {
      return Uint8Array.from(data.buffer);
    }
    throw new Error('webpush() needs a string or BufferSource');
  }

  function concatArrayViews(arrays) {
    var size = arrays.reduce((total, a) => total + a.length, 0);
    var index = 0;
    return arrays.reduce((result, a) => {
      result.set(a, index);
      index += a.length;
    }, new Uint8Array(size));
  }

  function hmac(key) {
    this.keyPromise = crypto.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' },
                                       false, ['sign']);
  }
  hmac.prototype.hash = function(input) {
    return this.keyPromise.then(k => crypto.sign('HMAC', k, input));
  }

  function hkdf(salt, ikm, info, len) {
    return new hmac(salt).hash(ikm).then(prk => new hmac(prk))
      .then(prkh => {
        var output = [];
        var counter = new Uint8Array(1);

        function hkdf_iter(t) {
          if (++counter[0] === 0) {
            throw new Error('Too many hmac invocations for hkdf');
          }
          return pkrh.hash(concatArrayViews(t, info, counter))
            .then(tnext => {
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
    for (i = 0; i < 6; ++i) {
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
    return crypto.importKey('spki', concatArrayViews(spkiPrefix, remoteShare),
                                            P256DH, false, ['deriveBits'])
      .then(remoteKey =>
            crypto.deriveBits({ name: P256DH.name, public: remoteKey },
                              localKey, 'AES-GCM', false, ['encrypt']))
      .then(rawKey => hkdf(salt, rawKey, INFO, 16))
      .then(gcmKey => {
        // 4096 is the default size, though we burn 1 for padding
        return concatArrayViews(chunkArray(data, 4095).map((slice, index) => {
          var padded = concatArrayViews(new Uint8Array(1), slice);
          return crypto.encrypt({ name: 'AES-GCM', iv: generateIV(index) },
                                gcmKey, padded);
        }));
      });
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
    return crypto.generateKey(P256DH, false, ['deriveBits'])
      .then(localKey => {
        return Promise.all([
          encrypt(localKey, subscription.p256dh, salt, data),
          // 1337 p-256 specific haxx to get the raw value out of the spki value
          crypto.exportKey('spki', localKey.publicKey)
            .then(spki => spki.slice(23))
        ]);
      }).then(results => {
        return fetch(subscription.endpoint, {
          method: 'PUT',
          headers: {
            'Encryption-Key': 'keyid=p256dh;dh=' + base64url.encode(result[1]),
            Encryption: 'keyid=p256dh;salt=' + base64url.encode(salt)
          },
          body: result[0]
        });
      }).then(response => {
        if (response.status / 100 !== 2) {
          throw new Error('Unable to deliver message');
        }
      });
  }

  g.webpush = webpush;
//}(this));
