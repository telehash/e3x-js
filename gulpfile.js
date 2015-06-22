
var gulp = require('gulp');
var mocha = require('gulp-mocha');

gulp.task('mocha', function() {
  return  gulp.src(['test/cs1a.test.js', 'test/cs2a.test.js', 'test/cs3a.test.js', 'test/e3x.test.js'], { read: false })
              .pipe(mocha({ reporter: 'list' }))
              .on('error', function(){
              })
              .on('end', function(){

              });
});

gulp.task('dev', ['mocha'], function() {

})
