#include <ntddk.h>

NTSTATUS HvProbeAndLockPagesSafe(PMDL mdl, KPROCESSOR_MODE access_mode, LOCK_OPERATION operation)
{
    __try {
        MmProbeAndLockPages(mdl, access_mode, operation);
        return STATUS_SUCCESS;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
}
