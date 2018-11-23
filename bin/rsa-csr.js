#!/usr/bin/env node
'use strict';

var fs = require('fs');
var rsacsr = require('../index.js');

var keyname = process.argv[2];
var domains = process.argv[3].split(/,/);

var keypem = fs.readFileSync(keyname, 'ascii');

rsacsr({ key: keypem, domains: domains }).then(function (csr) {
  // Using error so that we can redirect stdout to file
  //console.error("CN=" + domains[0]);
  //console.error("subjectAltName=" + domains.join(','));
  console.log(csr);
});
