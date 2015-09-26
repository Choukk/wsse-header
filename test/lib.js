'use strict';

var should = require('chai').should(),
    wsse = require('../');

describe('#encodePassword', function() {

  wsse.setup({passwordEncodingAsBase64:true});

  it('encode password as Base64', function() {
    var salt = 'nuc42b7tt28kogkcsw08cswwkco0c0s';
    var encodePassword = wsse.encodePassword('123456', salt);
    console.log(encodePassword);
    encodePassword.should.equal('k8fq4zJQTJgV9ne64pmXnKRPC+JnWKWB3W/WCrcGZjwUWg8jS4Wlgq0ibp9xuXsiBhHb9q4xvTAm0dNAL0sDeA==');
  });
});