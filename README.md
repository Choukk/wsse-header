# wsse-header
wsse is a simple and easy way to generate WSSE authentication header in JavaScript (e.g Symfony2 applications)
# Installation
```sh
npm install wsse-header
```
# Usage
```js
var wsse = require('wsse-header');
/**
 * Default options
 * passwordEncodingIterations: 5000,
 * passwordEncodingAsBase64: true,
 * passwordEncodingAsBase64: true,
 * secondsToSubtract: 0,
 * useSaltOnDigest: false
 */
wsse.setup();
var salt = 'nuc42b7tt28kogkcsw08cswwkco0c0s';
var encodePassword = wsse.encodePassword('123456', salt);
// e.g k8fq4zJQTJgV9ne64pmXnKRPC+JnWKWB3W/WCrcGZjwUWg8jS4Wlgq0ibp9xuXsiBhHb9q4xvTAm0dNAL0sDeA==
console.log(encodePassword);
var credentials = {
  username: 'oumarpoulo',
  passwordEncoded: encodePassword
};
var headerToken = wsse.buildWsse(credentials);
// e.g 'UsernameToken Username="oumarpoulo", PasswordDigest="2mQO9bW09K0gA7qpDPHNmcNSCdA=", Nonce="ZnMxcTAyMXFoczVkYm82cg==", Created="2015-09-24T13:30:19+02:00"'
console.log(headerToken);
var httpHeader = wsse.buildHttpHeader(credentials);
/**
 * e.g
 * { Authorization: 'WSSE profile="UsernameToken"',
  'X-WSSE': 'UsernameToken Username="oumarpoulo", PasswordDigest="cSqBypCjILzC11ZpDxEqtyysYYc=", Nonce="a3ppZWdsMnBkMHBzYzNkaQ==", Created="2015-09-24T13:34:28+02:00"' }
 */
console.log(httpHeader);
```
_version 1.0.1_
_licence MIT_

**Author:** Diallo Alpha Oumar Binta (<aob.diallo@gmail.com>)
