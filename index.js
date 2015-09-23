(function () {
  'use strict';

  var CryptoJS = require("crypto-js");

  var WsseHeader = module.exports = {};

  WsseHeader.buildWsseHeader = function(credentials) {
      var username = credentials.username;
      var passwordEncoded = credentials.passwordEncoded;
      var nonce = this.generateNonce();
      var createdDate = this.generateCreatedDate();
      var passwordDigest = this.generatePasswordDigest(nonce, createdDate, passwordEncoded);
      return 'UsernameToken Username="' + username + '", PasswordDigest="' + passwordDigest + '", Nonce="' + nonce + '", Created="' + createdDate + '"';
  };

  WsseHeader.generateNonce = function() {
      var nonce = Math.random().toString(36).substring(2);
      return CryptoJS.enc.Utf8.parse(nonce).toString(CryptoJS.enc.Base64);
  };

  WsseHeader.generatePasswordDigest = function(nonce, createdDate, passwordEncoded) {
      var nonce_64 = CryptoJS.enc.Base64.parse(nonce);
      var _sha1 = CryptoJS.SHA1(nonce_64.concat(CryptoJS.enc.Utf8.parse(createdDate).concat(CryptoJS.enc.Utf8.parse(passwordEncoded))));
      var result = _sha1.toString(CryptoJS.enc.Base64);
      return result;
  };

  WsseHeader.encodePassword = function(password, salt) {
      var salted = password + '{' + salt + '}';
      var passwordEncoded = CryptoJS.SHA512(salted);
      for(var i = 1; i < this.passwordEncodingIterations; i++) {
        passwordEncoded = CryptoJS.SHA512(passwordEncoded.concat(CryptoJS.enc.Utf8.parse(salted)));
      }
      return this.passwordEncodingAsBase64 ? passwordEncoded.toString(CryptoJS.enc.Base64) : passwordEncoded;
  };

  WsseHeader.generateCreatedDate = function() {
      return new Date().toISOString();
  };

  WsseHeader.setup = function(options) {
    options = options || {};
    this.passwordEncodingIterations = options.passwordEncodingIterations || 5000;
    this.passwordEncodingAsBase64 = options.passwordEncodingAsBase64 === 'false' ? false : true;
  };
}());