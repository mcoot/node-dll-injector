#include <SDKDDKVer.h>
#define WIN32_LEAN_AND_MEAN 
#include <windows.h>
#define UNICODE // Using unicode - so windows functions take wchars
#include <TlHelp32.h>
#include <wchar.h>


#include <nan.h>

using namespace v8;

///////////////// Prototypes

static HANDLE getProcess(const char* processName);
static HANDLE getProcessPID(DWORD pid);
static int injectHandle(HANDLE process, const char* dllFile);

int injectInternal(const char* processName, const char* dllFile);
bool isProcessRunningInternal(const char* processName);

int injectInternalPID(DWORD pid, const char* dllFile);
bool isProcessRunningInternalPID(DWORD pid);

///////////////// Functions

// Get a handle to a running process based on name
static HANDLE getProcess(const char* processName) {
    wchar_t wProcessName[MAX_PATH];
    mbstate_t mbstate;
    mbsrtowcs_s(NULL, wProcessName, &processName, MAX_PATH, &mbstate);

    // Take a snapshot of processes currently running
    HANDLE runningProcesses = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (runningProcesses == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    // Find the desired process
    BOOL res = Process32First(runningProcesses, &pe);
    while (res) {
        if (wcscmp(pe.szExeFile, wProcessName) == 0) {
            // Found the process
            CloseHandle(runningProcesses);
            HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);
            if (process == NULL) {
                // Process failed to open
                return NULL;
            }
            // Return a handle to this process
            return process;
        }
        res = Process32Next(runningProcesses, &pe);
    }

    // Couldn't find the process
    CloseHandle(runningProcesses);
    return NULL;
}

static HANDLE getProcessPID(DWORD pid) {
    // Take a snapshot of processes currently running
    HANDLE runningProcesses = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (runningProcesses == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    // Find the desired process
    BOOL res = Process32First(runningProcesses, &pe);
    while (res) {
        if (pe.th32ProcessID == pid) {
            // Found the process
            CloseHandle(runningProcesses);
            HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);
            if (process == NULL) {
                // Process failed to open
                return NULL;
            }
            // Return a handle to this process
            return process;
        }
        res = Process32Next(runningProcesses, &pe);
    }

    // Couldn't find the process
    CloseHandle(runningProcesses);
    return NULL;
}

// Inject a DLL file into the given process
static int injectHandle(HANDLE process, const char* dllFile) {
    if (process == NULL) {
        // Process is not open
        return 1;
    }

    // Get full DLL path
    char dllPath[MAX_PATH];
    DWORD r = GetFullPathNameA(dllFile, MAX_PATH, dllPath, NULL);
    if (r == 0) {
        // Getting path name failed
        CloseHandle(process);
        return 2;
    } else if (r > MAX_PATH) {
        // Buffer too small for path name
        CloseHandle(process);
        return 3;
    }

    // Get the LoadLibraryA method from the kernel32 dll
    LPVOID LoadLib = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

    // Allocate memory in the processs for the DLL path, and then write it there
    LPVOID remotePathSpace = VirtualAllocEx(process, NULL, strlen(dllPath) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!remotePathSpace) {
        CloseHandle(process);
        // Failed to allocate memory
        return 4;
    }

    if (!WriteProcessMemory(process, remotePathSpace, dllPath, strlen(dllPath) + 1, NULL)) {
        // Failed to write memory
        CloseHandle(process);
        return 5;
    }

    // Load the DLL with CreateRemoteThread + LoadLibraryA
    HANDLE remoteThread = CreateRemoteThread(process, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLib, (LPVOID)remotePathSpace, NULL, NULL);

    if (remoteThread == NULL) {
        // Failed to create remote thread to load the DLL
        CloseHandle(process);
        return 6;
    }

    // Close the handle to the process
    CloseHandle(process);
    return 0;
}

// Returns true iff a process with the given name is running
bool isProcessRunningInternal(const char* processName) {
    HANDLE process = getProcess(processName);
    if (process == NULL) {
        return false;
    }
    CloseHandle(process);
    return true;
}

// Returns true iff a process with the given pid is running
bool isProcessRunningInternalPID(DWORD pid) {
    HANDLE process = getProcessPID(pid);
    if (process == NULL) {
        return false;
    }
    CloseHandle(process);
    return true;
}

// Inject a DLL file into the process with the given name
int injectInternal(const char* processName, const char* dllFile) {
    return injectHandle(getProcess(processName), dllFile);
}

// Inject a DLL file into the process with the given pid
int injectInternalPID(DWORD pid, const char* dllFile) {
    return injectHandle(getProcessPID(pid), dllFile);
}


///////////////// NAN methods

NAN_METHOD(inject) {
    if (info.Length() != 2) {
        return;
    }
    if (!info[0]->IsString() || !info[1]->IsString()) {
        return;
    }

    String::Utf8Value arg0(info[0]->ToString());
    String::Utf8Value arg1(info[1]->ToString());

    if (!(*arg0) || !(*arg1)) {
        return;
    }

    const char* processName = *arg0;
    const char* dllName = *arg1;

    int val = injectInternal(processName, dllName);

    Local<Int32> res = Nan::New(val);
    info.GetReturnValue().Set(res);
}


NAN_METHOD(injectPID) {
    if (info.Length() != 2) {
        Local<Int32> res = Nan::New<Int32>(8);
        info.GetReturnValue().Set(res);
        return;
    }
    if (!info[0]->IsNumber() || !info[1]->IsString()) {
        Local<Int32> res = Nan::New(9);
    info.GetReturnValue().Set(res);
        return;
    }

    DWORD arg0(info[0]->Uint32Value());
    String::Utf8Value arg1(info[1]->ToString());

    if (!(*arg1)) {
        Local<Int32> res = Nan::New(10);
        info.GetReturnValue().Set(res);
        return;
    }
    const char* dllName = *arg1;

    int val = injectInternalPID(arg0, dllName);

    Local<Int32> res = Nan::New(val);
    info.GetReturnValue().Set(res);
}

NAN_METHOD(isProcessRunning) {
    if (info.Length() != 1) {
        return;
    }
    if (!info[0]->IsString()) {
        return;
    }

    String::Utf8Value arg(info[0]->ToString());

    if (!(*arg)) {
        return;
    }

    const char* processName = *arg;

    bool val = isProcessRunningInternal(processName);

    Local<Boolean> res = Nan::New(val);
    info.GetReturnValue().Set(res);
}

NAN_METHOD(isProcessRunningPID) {
    if (info.Length() != 1) {
        return;
    }
    if (!info[0]->IsUint32()) {
        return;
    }

    DWORD arg(info[0]->Uint32Value());

    bool val = isProcessRunningInternalPID(arg);

    Local<Boolean> res = Nan::New(val);
    info.GetReturnValue().Set(res);
}

///////////////// NAN setup

NAN_MODULE_INIT(InitModule) {
    NAN_EXPORT(target, inject);
    NAN_EXPORT(target, injectPID);
    NAN_EXPORT(target, isProcessRunning);
    NAN_EXPORT(target, isProcessRunningPID);
}

// Create the module called "addon" and initialize it with `Initialize` function (created with NAN_MODULE_INIT macro)
NODE_MODULE(injector, InitModule);