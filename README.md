# PhoneGap SSL Certificate Checker plugin

1. [Description](#1-description)
2. [Installation](#2-installation)
3. [Usage](#3-usage)
4. [Credits](#4-credits)

## 1. Description

This plugin can be used to add an extra layer of security by preventing 'Man in the Middle' attacks.
When correctly used, it will be very hard for hackers to intercept communication between your app and your server,
because you can actively verify the SSL certificate of the server by comparing actual and expected fingerprints.

You may want to check the connection when the app is started, but you can choose to invoke this plugin
everytime you communicate with the server. In either case, you can add your logic to the success and error callbacks.

* This version is for PhoneGap 3.0 and higher.
* PhoneGap 2.9 and lower is available in the [pre-phonegap-3 tree](https://github.com/EddyVerbruggen/SSLCertificateChecker-PhoneGap-Plugin/tree/pre-phonegap-3).
* Compatible with [Cordova Plugman](https://github.com/apache/cordova-plugman).
* [Officially supported by PhoneGap Build](https://build.phonegap.com/plugins).

## 2. Installation

from Github:
```
$ cordova plugin add https://github.com/kunder-lab/cordova-plugin-kunder-sslcertificatechecker
```

## 3. Usage

First obtain the fingerprint of the SSL certificate of your server(s).
You can find it f.i. by opening the server URL in Chrome. Then click the green certificate in front of the URL, click 'Connection',
'Certificate details', expand the details and scroll down to the **SHA256** fingerprint.

```javascript
  var environment = "prod"; // use anything else for testing, plugin will always call successCallback with message "CONNECTION_NOT_PROD"
  var server = "https://build.phonegap.com";
  var fingerprint = "C6 2D 93 39 C2 9F 82 8E 1E BE FD DC 2D 7B 7D 24 31 1A 59 E1 0B 4B C8 04 6E 21 F6 FA A2 37 11 45";

  window.plugins.sslCertificateChecker.check(
          successCallback,
          errorCallback,
          server,
          fingerprint);

   function successCallback(message) {
     console.log(message);
     // Message can be: CONNECTION_SECURE or CONNECTION_NOT_PROD.
     // Now do something with the trusted/not_prod server.
   }

   function errorCallback(message) {
     console.log(message);
     if (message === "CONNECTION_NOT_SECURE") {
       // There is likely a man in the middle attack going on, be careful!
     } else if (message.indexOf("CONNECTION_FAILED") >- 1) {
       // There was no connection (yet). Internet may be down. Try again (a few times) after a little timeout.
     }
   }
```

## 4. Credits
The iOS code was inspired by a closed-source, purely native certificate pinning implementation by Rob Bosman.

[Jacob Weber](https://github.com/EddyVerbruggen/SSLCertificateChecker-PhoneGap-Plugin/issues/9) did some great work to support checking multiple certificates on iOS, thanks!
