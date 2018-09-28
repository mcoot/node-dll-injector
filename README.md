# node-dll-injector

Native node addon for dll injection in windows.

Requires a working `node-gyp` setup to compile the native addon.

## Usage

```javascript
const injector = require('node-dll-injector');

const isNotepadRunning = injector.isProcessRunning('notepad.exe');

if (isNotePadRunning) {
    const success = injector.inject('notepad.exe', 'mydll.dll');

    if (success) {
        console.log('Successfully injected!');
    } else {
        console.log('Injection failed. :(');
    }
}

```

There are alternative versions of each function `injectPID` and `isProcessRunningPID` that inject based on process id.