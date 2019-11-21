/*
 * Copyright (c) 2009, Jay Loden, Giampaolo Rodola'. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Windows platform-specific module methods for _psutil_windows
 */

// Fixes clash between winsock2.h and windows.h
#define WIN32_LEAN_AND_MEAN

#include <Python.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <signal.h>

// Link with Iphlpapi.lib
#pragma comment(lib, "IPHLPAPI.lib")

#include "_psutil_common.h"


/*
 * ============================================================================
 * Public Python API
 * ============================================================================
 */

// Raised by Process.wait().
static PyObject *TimeoutExpired;
static PyObject *TimeoutAbandoned;

static ULONGLONG (*psutil_GetTickCount64)(void) = NULL;

/*
 * Return a Python float representing the system uptime expressed in seconds
 * since the epoch.
 */
static PyObject *
psutil_boot_time(PyObject *self, PyObject *args) {
#if (_WIN32_WINNT >= 0x0600)  // Windows Vista
    ULONGLONG uptime;
#else
    double uptime;
#endif
    time_t pt;
    FILETIME fileTime;
    long long ll;
    HINSTANCE hKernel32;
    psutil_GetTickCount64 = NULL;

    GetSystemTimeAsFileTime(&fileTime);

    /*
    HUGE thanks to:
    http://johnstewien.spaces.live.com/blog/cns!E6885DB5CEBABBC8!831.entry

    This function converts the FILETIME structure to the 32 bit
    Unix time structure.
    The time_t is a 32-bit value for the number of seconds since
    January 1, 1970. A FILETIME is a 64-bit for the number of
    100-nanosecond periods since January 1, 1601. Convert by
    subtracting the number of 100-nanosecond period betwee 01-01-1970
    and 01-01-1601, from time_t the divide by 1e+7 to get to the same
    base granularity.
    */
#if (_WIN32_WINNT >= 0x0600)  // Windows Vista
    ll = (((ULONGLONG)
#else
    ll = (((LONGLONG)
#endif
        (fileTime.dwHighDateTime)) << 32) + fileTime.dwLowDateTime;
    pt = (time_t)((ll - 116444736000000000ull) / 10000000ull);

    // GetTickCount64() is Windows Vista+ only. Dinamically load
    // GetTickCount64() at runtime. We may have used
    // "#if (_WIN32_WINNT >= 0x0600)" pre-processor but that way
    // the produced exe/wheels cannot be used on Windows XP, see:
    // https://github.com/giampaolo/psutil/issues/811#issuecomment-230639178
    hKernel32 = GetModuleHandleW(L"KERNEL32");
    psutil_GetTickCount64 = (void*)GetProcAddress(hKernel32, "GetTickCount64");
    if (psutil_GetTickCount64 != NULL) {
        // Windows >= Vista
        uptime = psutil_GetTickCount64() / (ULONGLONG)1000.00f;
        return Py_BuildValue("K", pt - uptime);
    }
    else {
        // Windows XP.
        // GetTickCount() time will wrap around to zero if the
        // system is run continuously for 49.7 days.
        uptime = GetTickCount() / (LONGLONG)1000.00f;
        return Py_BuildValue("L", pt - uptime);
    }
}

/*
 * Return a Python list of all the PIDs running on the system.
 */
static PyObject *
psutil_pids(PyObject *self, PyObject *args) {
    DWORD *proclist = NULL;
    DWORD numberOfReturnedPIDs;
    DWORD i;
    PyObject *py_pid = NULL;
    PyObject *py_retlist = PyList_New(0);

    if (py_retlist == NULL)
        return NULL;
    proclist = psutil_get_pids(&numberOfReturnedPIDs);
    if (proclist == NULL)
        goto error;

    for (i = 0; i < numberOfReturnedPIDs; i++) {
        py_pid = Py_BuildValue("I", proclist[i]);
        if (!py_pid)
            goto error;
        if (PyList_Append(py_retlist, py_pid))
            goto error;
        Py_DECREF(py_pid);
    }

    // free C array allocated for PIDs
    free(proclist);
    return py_retlist;

error:
    Py_XDECREF(py_pid);
    Py_DECREF(py_retlist);
    if (proclist != NULL)
        free(proclist);
    return NULL;
}


/*
 * Kill a process given its PID.
 */
static PyObject *
psutil_proc_kill(PyObject *self, PyObject *args) {
    HANDLE hProcess;
    DWORD err;
    long pid;

    if (! PyArg_ParseTuple(args, "l", &pid))
        return NULL;
    if (pid == 0)
        return AccessDenied("");

    hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProcess == NULL) {
        if (GetLastError() == ERROR_INVALID_PARAMETER) {
            // see https://github.com/giampaolo/psutil/issues/24
            psutil_debug("OpenProcess -> ERROR_INVALID_PARAMETER turned "
                         "into NoSuchProcess");
            NoSuchProcess("");
        }
        else {
            PyErr_SetFromWindowsErr(0);
        }
        return NULL;
    }

    // kill the process
    if (! TerminateProcess(hProcess, SIGTERM)) {
        err = GetLastError();
        // See: https://github.com/giampaolo/psutil/issues/1099
        if (err != ERROR_ACCESS_DENIED) {
            PyErr_SetFromWindowsErr(err);
            CloseHandle(hProcess);
            return NULL;
        }
    }

    CloseHandle(hProcess);
    Py_RETURN_NONE;
}


/*
 * Return 1 if PID exists in the current process list, else 0.
 */
static PyObject *
psutil_pid_exists(PyObject *self, PyObject *args) {
    long pid;
    int status;

    if (! PyArg_ParseTuple(args, "l", &pid))
        return NULL;

    status = psutil_pid_is_running(pid);
    if (-1 == status)
        return NULL; // exception raised in psutil_pid_is_running()
    return PyBool_FromLong(status);
}

/*
 * Return a {pid:ppid, ...} dict for all running processes.
 */
static PyObject *
psutil_ppid_map(PyObject *self, PyObject *args) {
    PyObject *py_pid = NULL;
    PyObject *py_ppid = NULL;
    PyObject *py_retdict = PyDict_New();
    HANDLE handle = NULL;
    PROCESSENTRY32 pe = {0};
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (py_retdict == NULL)
        return NULL;
    handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (handle == INVALID_HANDLE_VALUE) {
        PyErr_SetFromWindowsErr(0);
        Py_DECREF(py_retdict);
        return NULL;
    }

    if (Process32First(handle, &pe)) {
        do {
            py_pid = Py_BuildValue("I", pe.th32ProcessID);
            if (py_pid == NULL)
                goto error;
            py_ppid = Py_BuildValue("I", pe.th32ParentProcessID);
            if (py_ppid == NULL)
                goto error;
            if (PyDict_SetItem(py_retdict, py_pid, py_ppid))
                goto error;
            Py_DECREF(py_pid);
            Py_DECREF(py_ppid);
        } while (Process32Next(handle, &pe));
    }

    CloseHandle(handle);
    return py_retdict;

error:
    Py_XDECREF(py_pid);
    Py_XDECREF(py_ppid);
    Py_DECREF(py_retdict);
    CloseHandle(handle);
    return NULL;
}

/*
 * Return a Python float indicating the process create time expressed in
 * seconds since the epoch.
 */
static PyObject *
psutil_proc_create_time(PyObject *self, PyObject *args) {
    long        pid;
    long long   unix_time;
    HANDLE      hProcess;
    FILETIME    ftCreate, ftExit, ftKernel, ftUser;

    if (! PyArg_ParseTuple(args, "l", &pid))
        return NULL;

    // special case for PIDs 0 and 4, return system boot time
    if (0 == pid || 4 == pid)
        return psutil_boot_time(NULL, NULL);

    hProcess = psutil_handle_from_pid(pid, PROCESS_QUERY_LIMITED_INFORMATION);
    if (hProcess == NULL)
        return NULL;
    if (! GetProcessTimes(hProcess, &ftCreate, &ftExit, &ftKernel, &ftUser)) {
        if (GetLastError() == ERROR_ACCESS_DENIED) {
            // usually means the process has died so we throw a
            // NoSuchProcess here
            NoSuchProcess("");
        }
        else {
            PyErr_SetFromWindowsErr(0);
        }
        CloseHandle(hProcess);
        return NULL;
    }

    CloseHandle(hProcess);

    /*
    // Make sure the process is not gone as OpenProcess alone seems to be
    // unreliable in doing so (it seems a previous call to p.wait() makes
    // it unreliable).
    // This check is important as creation time is used to make sure the
    // process is still running.
    ret = GetExitCodeProcess(hProcess, &exitCode);
    CloseHandle(hProcess);
    if (ret != 0) {
        if (exitCode != STILL_ACTIVE)
            return NoSuchProcess("");
    }
    else {
        // Ignore access denied as it means the process is still alive.
        // For all other errors, we want an exception.
        if (GetLastError() != ERROR_ACCESS_DENIED)
            return PyErr_SetFromWindowsErr(0);
    }
    */

    // Convert the FILETIME structure to a Unix time.
    // It's the best I could find by googling and borrowing code here
    // and there. The time returned has a precision of 1 second.
    unix_time = ((LONGLONG)ftCreate.dwHighDateTime) << 32;
    unix_time += ftCreate.dwLowDateTime - 116444736000000000LL;
    unix_time /= 10000000;
    return Py_BuildValue("d", (double)unix_time);
}

/*
 Accept a filename's drive in native  format like "\Device\HarddiskVolume1\"
 and return the corresponding drive letter (e.g. "C:\\").
 If no match is found return an empty string.
*/
static PyObject *
psutil_win32_QueryDosDevice(PyObject *self, PyObject *args) {
    LPCTSTR   lpDevicePath;
    TCHAR d = TEXT('A');
    TCHAR     szBuff[5];

    if (!PyArg_ParseTuple(args, "s", &lpDevicePath))
        return NULL;

    while (d <= TEXT('Z')) {
        TCHAR szDeviceName[3] = {d, TEXT(':'), TEXT('\0')};
        TCHAR szTarget[512] = {0};
        if (QueryDosDevice(szDeviceName, szTarget, 511) != 0) {
            if (_tcscmp(lpDevicePath, szTarget) == 0) {
                _stprintf_s(szBuff, _countof(szBuff), TEXT("%c:"), d);
                return Py_BuildValue("s", szBuff);
            }
        }
        d++;
    }
    return Py_BuildValue("s", "");
}


/*
 * Return process executable path.
 */
static PyObject *
psutil_proc_exe(PyObject *self, PyObject *args) {
    long pid;
    HANDLE hProcess;
    wchar_t exe[MAX_PATH];

    if (! PyArg_ParseTuple(args, "l", &pid))
        return NULL;
    hProcess = psutil_handle_from_pid(pid, PROCESS_QUERY_LIMITED_INFORMATION);
    if (NULL == hProcess)
        return NULL;
    if (GetProcessImageFileNameW(hProcess, exe, MAX_PATH) == 0) {
        PyErr_SetFromWindowsErr(0);
        CloseHandle(hProcess);
        return NULL;
    }
    CloseHandle(hProcess);
    return PyUnicode_FromWideChar(exe, wcslen(exe));
}


/*
 * Return process cmdline as a Python list of cmdline arguments.
 */
static PyObject *
psutil_proc_cmdline(PyObject *self, PyObject *args) {
    long pid;
    int pid_return;

    if (! PyArg_ParseTuple(args, "l", &pid))
        return NULL;
    if ((pid == 0) || (pid == 4))
        return Py_BuildValue("[]");

    pid_return = psutil_pid_is_running(pid);
    if (pid_return == 0)
        return NoSuchProcess("");
    if (pid_return == -1)
        return NULL;

    return psutil_get_cmdline(pid);
}

// ------------------------ Python init ---------------------------

static PyMethodDef
PsutilMethods[] = {
    // --- per-process functions

    {"proc_cmdline", psutil_proc_cmdline, METH_VARARGS,
     "Return process cmdline as a list of cmdline arguments"},
    {"proc_exe", psutil_proc_exe, METH_VARARGS,
     "Return path of the process executable"},
    {"proc_kill", psutil_proc_kill, METH_VARARGS,
     "Kill the process identified by the given PID"},
    {"proc_create_time", psutil_proc_create_time, METH_VARARGS,
     "Return a float indicating the process create time expressed in "
     "seconds since the epoch"},
    // --- system-related functions
    {"pids", psutil_pids, METH_VARARGS,
     "Returns a list of PIDs currently running on the system"},
    {"ppid_map", psutil_ppid_map, METH_VARARGS,
     "Return a {pid:ppid, ...} dict for all running processes"},
    {"pid_exists", psutil_pid_exists, METH_VARARGS,
     "Determine if the process exists in the current process list."},
    {"boot_time", psutil_boot_time, METH_VARARGS,
     "Return the system boot time expressed in seconds since the epoch."},

    // --- windows API bindings
    {"win32_QueryDosDevice", psutil_win32_QueryDosDevice, METH_VARARGS,
     "QueryDosDevice binding"},

    {NULL, NULL, 0, NULL}
};

struct module_state {
    PyObject *error;
};

#if PY_MAJOR_VERSION >= 3
#define GETSTATE(m) ((struct module_state*)PyModule_GetState(m))
#else
#define GETSTATE(m) (&_state)
static struct module_state _state;
#endif

#if PY_MAJOR_VERSION >= 3

static int psutil_windows_traverse(PyObject *m, visitproc visit, void *arg) {
    Py_VISIT(GETSTATE(m)->error);
    return 0;
}

static int psutil_windows_clear(PyObject *m) {
    Py_CLEAR(GETSTATE(m)->error);
    return 0;
}

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    "psutil_windows",
    NULL,
    sizeof(struct module_state),
    PsutilMethods,
    NULL,
    psutil_windows_traverse,
    psutil_windows_clear,
    NULL
};

#define INITERROR return NULL

PyMODINIT_FUNC PyInit__psutil_windows(void)

#else
#define INITERROR return
void init_psutil_windows(void)
#endif
{
    struct module_state *st = NULL;
#if PY_MAJOR_VERSION >= 3
    PyObject *module = PyModule_Create(&moduledef);
#else
    PyObject *module = Py_InitModule("_psutil_windows", PsutilMethods);
#endif

    if (module == NULL) {
        INITERROR;
    }

    st = GETSTATE(module);
    st->error = PyErr_NewException("_psutil_windows.Error", NULL, NULL);
    if (st->error == NULL) {
        Py_DECREF(module);
        INITERROR;
    }

    // Exceptions.
    TimeoutExpired = PyErr_NewException(
        "_psutil_windows.TimeoutExpired", NULL, NULL);
    Py_INCREF(TimeoutExpired);
    PyModule_AddObject(module, "TimeoutExpired", TimeoutExpired);

    TimeoutAbandoned = PyErr_NewException(
        "_psutil_windows.TimeoutAbandoned", NULL, NULL);
    Py_INCREF(TimeoutAbandoned);
    PyModule_AddObject(module, "TimeoutAbandoned", TimeoutAbandoned);

    // version constant
    PyModule_AddIntConstant(module, "version", PSUTIL_VERSION);

    // process status constants
    // http://msdn.microsoft.com/en-us/library/ms683211(v=vs.85).aspx
    PyModule_AddIntConstant(
        module, "ABOVE_NORMAL_PRIORITY_CLASS", ABOVE_NORMAL_PRIORITY_CLASS);
    PyModule_AddIntConstant(
        module, "BELOW_NORMAL_PRIORITY_CLASS", BELOW_NORMAL_PRIORITY_CLASS);
    PyModule_AddIntConstant(
        module, "HIGH_PRIORITY_CLASS", HIGH_PRIORITY_CLASS);
    PyModule_AddIntConstant(
        module, "IDLE_PRIORITY_CLASS", IDLE_PRIORITY_CLASS);
    PyModule_AddIntConstant(
        module, "NORMAL_PRIORITY_CLASS", NORMAL_PRIORITY_CLASS);
    PyModule_AddIntConstant(
        module, "REALTIME_PRIORITY_CLASS", REALTIME_PRIORITY_CLASS);

    // connection status constants
    // http://msdn.microsoft.com/en-us/library/cc669305.aspx
    PyModule_AddIntConstant(
        module, "MIB_TCP_STATE_CLOSED", MIB_TCP_STATE_CLOSED);
    PyModule_AddIntConstant(
        module, "MIB_TCP_STATE_CLOSING", MIB_TCP_STATE_CLOSING);
    PyModule_AddIntConstant(
        module, "MIB_TCP_STATE_CLOSE_WAIT", MIB_TCP_STATE_CLOSE_WAIT);
    PyModule_AddIntConstant(
        module, "MIB_TCP_STATE_LISTEN", MIB_TCP_STATE_LISTEN);
    PyModule_AddIntConstant(
        module, "MIB_TCP_STATE_ESTAB", MIB_TCP_STATE_ESTAB);
    PyModule_AddIntConstant(
        module, "MIB_TCP_STATE_SYN_SENT", MIB_TCP_STATE_SYN_SENT);
    PyModule_AddIntConstant(
        module, "MIB_TCP_STATE_SYN_RCVD", MIB_TCP_STATE_SYN_RCVD);
    PyModule_AddIntConstant(
        module, "MIB_TCP_STATE_FIN_WAIT1", MIB_TCP_STATE_FIN_WAIT1);
    PyModule_AddIntConstant(
        module, "MIB_TCP_STATE_FIN_WAIT2", MIB_TCP_STATE_FIN_WAIT2);
    PyModule_AddIntConstant(
        module, "MIB_TCP_STATE_LAST_ACK", MIB_TCP_STATE_LAST_ACK);
    PyModule_AddIntConstant(
        module, "MIB_TCP_STATE_TIME_WAIT", MIB_TCP_STATE_TIME_WAIT);
    PyModule_AddIntConstant(
        module, "MIB_TCP_STATE_TIME_WAIT", MIB_TCP_STATE_TIME_WAIT);
    PyModule_AddIntConstant(
        module, "MIB_TCP_STATE_DELETE_TCB", MIB_TCP_STATE_DELETE_TCB);
    PyModule_AddIntConstant(
        module, "PSUTIL_CONN_NONE", PSUTIL_CONN_NONE);

    // service status constants
    /*
    PyModule_AddIntConstant(
        module, "SERVICE_CONTINUE_PENDING", SERVICE_CONTINUE_PENDING);
    PyModule_AddIntConstant(
        module, "SERVICE_PAUSE_PENDING", SERVICE_PAUSE_PENDING);
    PyModule_AddIntConstant(
        module, "SERVICE_PAUSED", SERVICE_PAUSED);
    PyModule_AddIntConstant(
        module, "SERVICE_RUNNING", SERVICE_RUNNING);
    PyModule_AddIntConstant(
        module, "SERVICE_START_PENDING", SERVICE_START_PENDING);
    PyModule_AddIntConstant(
        module, "SERVICE_STOP_PENDING", SERVICE_STOP_PENDING);
    PyModule_AddIntConstant(
        module, "SERVICE_STOPPED", SERVICE_STOPPED);
    */

    // ...for internal use in _psutil_windows.py
    PyModule_AddIntConstant(
        module, "INFINITE", INFINITE);
    PyModule_AddIntConstant(
        module, "ERROR_ACCESS_DENIED", ERROR_ACCESS_DENIED);
    PyModule_AddIntConstant(
        module, "ERROR_INVALID_NAME", ERROR_INVALID_NAME);
    PyModule_AddIntConstant(
        module, "ERROR_SERVICE_DOES_NOT_EXIST", ERROR_SERVICE_DOES_NOT_EXIST);

    // set SeDebug for the current process
    psutil_set_se_debug();
    psutil_setup();

#if PY_MAJOR_VERSION >= 3
    return module;
#endif
}
