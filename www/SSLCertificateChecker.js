"use strict";
var exec = require('cordova/exec');

function SSLCertificateChecker() {
}

SSLCertificateChecker.prototype.check = function (successCallback, errorCallback, environment, serverURL, allowedFingerprint) {
  if (environment !== 'prod') {
    successCallback("CONNECTION_NOT_PROD");
    return;
  }
  exec(successCallback, errorCallback, "SSLCertificateChecker", "check", [serverURL, allowedFingerprint]);
};

var sslCertificateChecker = new SSLCertificateChecker();
module.exports = sslCertificateChecker;
