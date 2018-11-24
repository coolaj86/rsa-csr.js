'use strict';

var crypto = require('crypto');
var ASN1 = require('./asn1.js');
var Enc = require('./encoding.js');
var PEM = require('./pem.js');
var X509 = require('./x509.js');
var RSA = {};

/*global Promise*/
var CSR = module.exports = function rsacsr(opts) {
  // We're using a Promise here to be compatible with the browser version
  // which will probably use the webcrypto API for some of the conversions
  return Promise.resolve().then(function () {
    var Rasha;
    opts = JSON.parse(JSON.stringify(opts));
    var pem, jwk;

    // We do a bit of extra error checking for user convenience
    if (!opts) { throw new Error("You must pass options with key and domains to rsacsr"); }
    if (!Array.isArray(opts.domains) || 0 === opts.domains.length) {
      new Error("You must pass options.domains as a non-empty array");
    }

    // I need to check that 例.中国 is a valid domain name
    if (!opts.domains.every(function (d) {
      // allow punycode? xn--
      if ('string' === typeof d /*&& /\./.test(d) && !/--/.test(d)*/) {
        return true;
      }
    })) {
      throw new Error("You must pass options.domains as strings");
    }

    if (opts.pem) {
      pem = opts.pem;
    } else if (opts.jwk) {
      jwk = opts.jwk;
    } else {
      if (!opts.key) {
        throw new Error("You must pass options.key as a JSON web key");
      } else if (opts.key.kty) {
        jwk = opts.key;
      } else {
        pem = opts.key;
      }
    }

    if (pem) {
      try {
        Rasha = require('rasha');
      } catch(e) {
        throw new Error("Rasha.js is an optional dependency for PEM-to-JWK.\n"
          + "Install it if you'd like to use it:\n"
          + "\tnpm install --save rasha\n"
          + "Otherwise supply a jwk as the private key."
        );
      }
      jwk = Rasha.importSync({ pem: pem });
    }

    opts.jwk = jwk;
    return CSR.create(opts).then(function (bytes) {
      return PEM.packBlock({
        type: "CERTIFICATE REQUEST"
      , bytes: bytes /* { jwk: jwk, domains: opts.domains } */
      });
    });
  });
};

CSR.create = function createCsr(opts) {
  var hex = CSR.request(opts.jwk, opts.domains);
  return CSR.sign(opts.jwk, hex).then(function (csr) {
    return Enc.hexToBuf(csr);
  });
};

CSR.request = function createCsrBodyEc(jwk, domains) {
  var asn1pub = X509.packCsrPublicKey(jwk);
  return X509.packCsr(asn1pub, domains);
};

CSR.sign = function csrEcSig(jwk, request) {
  var keypem = PEM.packBlock({ type: "RSA PRIVATE KEY", bytes: X509.packPkcs1(jwk) });

  return RSA.sign(keypem, Enc.hexToBuf(request)).then(function (sig) {
    var sty = ASN1('30'
      // 1.2.840.113549.1.1.11 sha256WithRSAEncryption (PKCS #1)
    , ASN1('06', '2a864886f70d01010b')
    , ASN1('05')
    );
    return ASN1('30'
      // The Full CSR Request Body
    , request
      // The Signature Type
    , sty
      // The Signature
    , ASN1.BitStr(Enc.bufToHex(sig))
    );
  });
};

//
// RSA
//

// Took some tips from https://gist.github.com/codermapuche/da4f96cdb6d5ff53b7ebc156ec46a10a
RSA.sign = function signRsa(keypem, ab) {
  return Promise.resolve().then(function () {
    // Signer is a stream
    var sign = crypto.createSign('SHA256');
    sign.write(new Uint8Array(ab));
    sign.end();

    // The signature is ASN1 encoded, as it turns out
    var sig = sign.sign(keypem);

    // Convert to a JavaScript ArrayBuffer just because
    return new Uint8Array(sig.buffer.slice(sig.byteOffset, sig.byteOffset + sig.byteLength));
  });
};
