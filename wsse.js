/**
 * wsse
 * https://github.com/oumarPoulo/wsse-header
 *
 * Copyright 2015 Diallo Alpha Oumar Binta
 * Released under the MIT license
 */
(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define(['crypto-js', 'moment'], factory);
  } else if (typeof exports === 'object') {
    module.exports = factory(require('crypto-js'), require('moment'));
  } else{
    root.wsse = factory(root.CryptoJS, root.moment);
  }
}(this, function (CryptoJS, moment) {
  'use strict';

  var wsse = {};

  wsse.buildWsseHeader = function(credentials) {
    var username = credentials.username;
    var passwordEncoded = credentials.passwordEncoded;
    var nonce = wsse.generateNonce();
    var createdDate = wsse.generateCreatedDate();
    var passwordDigest = wsse.generatePasswordDigest(Buffer.from(nonce, 'base64').toString('ascii'), createdDate, passwordEncoded);

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
    return wsse.secondsToSubtract ? moment().subtract(wsse.secondsToSubtract , 'seconds').format() : moment().format();
  };

  wsse.setup = function(options) {
    options = options || {};
    wsse.passwordEncodingIterations = options.passwordEncodingIterations || 5000;
    wsse.secondsToSubtract = options.secondsToSubtract || 0;
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

  return wsse;
}));
