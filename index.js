'use strict';

// Only works on Windows!
if (process.platform !== 'win32') return;

const injector = require('bindings')('injector');

const inject = (processName, dllFile) => {
    return injector.inject(processName, dllFile);
};

const injectPID = (pid, dllFile) => {
    return injector.injectPID(pid, dllFile);
};

const isProcessRunning = (processName) => {
    return injector.isProcessRunning(processName);
};

const isProcessRunningPID = (pid) => {
    return injector.isProcessRunningPID(pid);
};

module.exports = {
    inject,
    injectPID,
    isProcessRunning,
    isProcessRunningPID
};