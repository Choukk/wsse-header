/*!
 * wsse
 * https://github.com/oumarPoulo/wsse-header
 *
 * Copyright 2015 Diallo Alpha Oumar Binta
 * Released under the MIT license
 */

'use strict';

(function () {

  var CryptoJS = require("crypto-js");
  var moment = require("moment");

  var wsse = {};

  // global on the server, window in the browser
  var previous_wsse;
  // Establish the root object, `window` (`self`) in the browser, `global`
  // on the server, or `this` in some virtual machines. We use `self`
  // instead of `window` for `WebWorker` support.

  var root = typeof self === 'object' && self.self === self && self
   || typeof global === 'object' && global.global === global && global || this;

  if (root != null) {
    previous_wsse = root.wsse;
  }

  wsse.noConflict = function () {
    root.wsse = previous_wsse;
    return wsse;
  };

  wsse.buildWsseHeader = function(credentials) {
    var username = credentials.username;
    var passwordEncoded = credentials.passwordEncoded;
    var nonce = wsse.generateNonce();
    var createdDate = wsse.generateCreatedDate();
    var passwordDigest = wsse.generatePasswordDigest(nonce, createdDate, passwordEncoded);
    
    return 'UsernameToken Username="' + username + '", PasswordDigest="' + passwordDigest + '", Nonce="' + nonce + '", Created="' + createdDate + '"';
  };

  wsse.generateNonce = function() {
    var nonce = Math.random().toString(36).substring(2);
    
    return CryptoJS.enc.Utf8.parse(nonce).toString(CryptoJS.enc.Base64);
  };

  wsse.generatePasswordDigest = function(nonce, createdDate, passwordEncoded) {
    var raw = nonce.concat(createdDate).concat(passwordEncoded);
    raw = (wsse.useSaltOnDigest && typeof wsse.salt !== 'undefined' && wsse.salt.length) ? raw + '{' + wsse.salt + '}' : raw;
    var _sha1 = CryptoJS.SHA1(raw);
    var result = _sha1.toString(CryptoJS.enc.Base64);
    
    return result;
  };

  wsse.encodePassword = function(password, salt) {
    wsse.salt = (wsse.useSaltOnDigest) ? salt : undefined;
    var salted = (typeof salt !== 'undefined' && salt.length) ? password + '{' + salt + '}' : password;
    var passwordEncoded = CryptoJS.SHA512(salted);

    for(var i = 1; i < wsse.passwordEncodingIterations; i++) {
      passwordEncoded = CryptoJS.SHA512(passwordEncoded.concat(CryptoJS.enc.Utf8.parse(salted)));
    }

    var result = wsse.passwordEncodingAsBase64 ? passwordEncoded.toString(CryptoJS.enc.Base64) : passwordEncoded;
    
    return result;
  };

  wsse.generateCreatedDate = function() {
    return moment().subtract(30, 'seconds').format();
  };

  wsse.setup = function(options) {
    options = options || {};
    wsse.passwordEncodingIterations = options.passwordEncodingIterations || 5000;
    wsse.passwordEncodingAsBase64 = options.passwordEncodingAsBase64 === false ? false : true;
    wsse.useSaltOnDigest = (options.useSaltOnDigest === true) ? true : false;
  };

  wsse.buildHttpHeader = function(credentials) {
    var _wsseHeader = wsse.buildWsseHeader(credentials);
    var header = {
      'Authorization': 'WSSE profile="UsernameToken"',
      'X-WSSE': _wsseHeader
    };
    
    return header;
  };

  // Node.js
  if (typeof module === 'object' && module.exports) {
    module.exports = wsse;
  }
  // AMD / RequireJS
  else if (typeof define === 'function' && define.amd) {
    define([], function () {
      return wsse;
    });
  }
  // included directly via <script> tag
  else {
    root.wsse = wsse;
  }

}());