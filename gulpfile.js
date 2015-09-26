var gulp = require('gulp');
var browserify = require('gulp-browserify');
var del = require('del');
var rename = require('gulp-rename');
var uglify = require('gulp-uglify');
var using = require('gulp-using');

var dist = './dist';

gulp.task('clean', function () {
	return del([dist, 'wsse.js']);
});

gulp.task('wsse_index', ['clean'], function () {
  var srcFiles = [
    './src/wsse.js'
  ];

	var stream = gulp.src(srcFiles)
	.pipe(rename('wsse.js'))
	.pipe(gulp.dest('./'));
  return stream;
});

gulp.task('wsse_min', ['clean'], function() {
  var srcFiles = [
    './src/wsse.js'
  ];

  var stream = gulp.src(srcFiles)
  .pipe(uglify())
  .pipe(rename('wsse.min.js'))
  .pipe(gulp.dest(dist));
  return stream;
});

gulp.task('bundle', ['clean'], function() {
  var stream = gulp.src('./src/wsse.js')
  .pipe(browserify())
  .pipe(rename('bundle.js'))
  .pipe(gulp.dest(dist));
  return stream;
});

gulp.task('build', ['wsse_index', 'wsse_min', 'bundle']);
gulp.task('default', ['build']);
