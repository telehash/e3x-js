var expect = require('chai').expect;
var e3x = require('../index.js');


describe('e3x', function(){

  it('should export an object', function(){
    expect(e3x).to.be.a('object');
  });

  it('should have cipher sets loaded', function(){
    expect(Object.keys(e3x.cs).length).to.be.equal(1);
  });

});
