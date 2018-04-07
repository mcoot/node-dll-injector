'use strict';

// Only works on Windows!
if (process.platform !== 'win32') return;

const injector = require('bindings')('injector');

const inject = (processName, dllFile) => {
    return injector.inject(processName, dllFile);
};

const isProcessRunning = (processName) => {
    return injector.isProcessRunning(processName);
};

module.exports = {
    inject,
    isProcessRunning
};