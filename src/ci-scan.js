#!/usr/bin/env node
'use strict';

// shortcut: the 1.0 bin name, kept for 1.1.x only; delete this file and its bin entry in 1.2.0.
require('./cli')
  .legacyMain()
  .then((code) => {
    process.exitCode = code;
  });
