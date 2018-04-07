/// <reference types="node" />

declare module 'node-dll-injector' {

    export function inject(processName: string, dllFile: string): boolean;
    export function isProcessRunning(processName: string): boolean;

}