
var gulp = require('gulp');
var mocha = require('gulp-mocha');
var watch = require('gulp-watch')
var chext = require("chext");
var jsdoc = require("gulp-jsdoc");
var glob  = require("glob");

var unitTests =  ['test/cs1a.test.js', 'test/cs2a.test.js', 'test/cs3a.test.js', 'test/e3x.test.js'];
var srcFiles = ['ciphers/**/*.js', "e3x.js"]

gulp.task('mocha', function() {
  return  gulp.src( unitTests, { read: false })
              .pipe(mocha({ reporter: 'list' }))
              .on('error', function(){
              })
              .on('end', function(){

              });
});

var plato = require('plato');

var files = glob.sync("ciphers/*/*.js").concat(['e3x.js']);

var outputDir = './plato';
// null options for this example
var options = {
  title: 'Your title here'
};

var callback = function (report){
// once done the analysis,
// execute this
};


gulp.task('doc', function(){

  plato.inspect(files, outputDir, {}, callback);
  gulp.src(["./lib/*.js", "./ext/*.js"])
  .pipe(jsdoc('./doc'))
})


gulp.task('dev', function() {
  var ch = new chext()

  ch.watchify(unitTests)

  ch.onresults = function(results){
    //console.log("tests complete", results)
  }

  gulp.watch(unitTests.concat(srcFiles), ["mocha"])
})
