(function () {
  'use strict';

  var CryptoJS = require("crypto-js");
  var moment = require("moment");

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
    
    var raw = nonce.concat(createdDate).concat(passwordEncoded);
    raw = (this.useSaltOnDigest) ? raw + '{' + this.salt + '}' : raw;
    var _sha1 = CryptoJS.SHA1(raw);
    var result = _sha1.toString(CryptoJS.enc.Base64);
    return result;
  };

  WsseHeader.encodePassword = function(password, salt) {
    this.salt = salt;
    var salted = (typeof salt !== 'undefined') ? password + '{' + salt + '}' : salt;
    var passwordEncoded = CryptoJS.SHA512(salted);
    for(var i = 1; i < this.passwordEncodingIterations; i++) {
      passwordEncoded = CryptoJS.SHA512(passwordEncoded.concat(CryptoJS.enc.Utf8.parse(salted)));
    }
    var result = this.passwordEncodingAsBase64 ? passwordEncoded.toString(CryptoJS.enc.Base64) : passwordEncoded;
    return result;
  };

  WsseHeader.generateCreatedDate = function() {
    return moment().subtract(30, 'seconds').format();
  };

  WsseHeader.setup = function(options) {
    options = options || {};
    this.passwordEncodingIterations = options.passwordEncodingIterations || 5000;
    this.passwordEncodingAsBase64 = options.passwordEncodingAsBase64 === false ? false : true;
    this.useSaltOnDigest = (options.useSaltOnDigest === true) ? true : false;
  };

  WsseHeader.buildHttpHeader = function(credentials) {
    var _wsseHeader = this.buildWsseHeader(credentials);
    var header = {
      'Authorization': 'WSSE profile="UsernameToken"',
      'X-WSSE': _wsseHeader
    };
    return header;
  };

}());