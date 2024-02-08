#include <ntifs.h>
#include "IOCTL.h"

typedef struct _READ_MEMORY {
	ULONG ProcessId;
	ULONGLONG addressSrc;
	PVOID addressDst;
	ULONG size;
} READ_MEMORY;

typedef struct _WRITE_MEMORY {
	ULONG ProcessId;
	PVOID addressSrc;
	ULONGLONG addressDst;
	ULONG size;
} WRITE_MEMORY;

// Undocumented function exposed by the kernel
extern "C" NTSTATUS NTAPI MmCopyVirtualMemory
(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);

void DriverUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS CreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS DeviceIoControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);


UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\BypassDriver");
UNICODE_STRING symlink = RTL_CONSTANT_STRING(L"\\??\\BypassDriver");

void DriverUnload(PDRIVER_OBJECT DriverObject) {
	IoDeleteSymbolicLink(&symlink);
	IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS CreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS KeReadVirtualMemory(PEPROCESS Process, PVOID addressSrc, PVOID TargetAddr, SIZE_T Size) {
	NTSTATUS status = STATUS_SUCCESS;
	SIZE_T Bytes = NULL;
	// Copy the virtual memory of the targeted process to the virtual memory of the client
	__try {
		MmCopyVirtualMemory(Process, addressSrc, PsGetCurrentProcess(), TargetAddr, Size, KernelMode, &Bytes);
		return STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("Memory read failed\n");
		status = GetExceptionCode();
		return status;
	}
}

NTSTATUS KeWriteVirtualMemory(PEPROCESS Process, PVOID addressSrc, PVOID TargetAddr, SIZE_T Size) {
	NTSTATUS status = STATUS_SUCCESS;
	SIZE_T Bytes = NULL;
	// Copy the virtual memory of the client to the virtual memory of the targeted process
	__try {
		MmCopyVirtualMemory(PsGetCurrentProcess(), addressSrc, Process, TargetAddr, Size, KernelMode, &Bytes);
		return STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("Memory write failed\n");
		status = GetExceptionCode();
		return status;
	}
}

NTSTATUS DeviceIoControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	ULONG IoControlCode = stack->Parameters.DeviceIoControl.IoControlCode;
	HANDLE GamePid = 0;
	PEPROCESS processObject = NULL;
	READ_MEMORY* ReadMemory = NULL;
	WRITE_MEMORY* WriteMemory = NULL;
	PVOID SourceAddress;
	PVOID DestinationAddress;

	switch (IoControlCode) {
	case BYPASS_DRIVER_READ_GAME_MEMORY:
		if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(READ_MEMORY)) {
			status = STATUS_BUFFER_TOO_SMALL;
			DbgPrint("[!] STATUS_BUFFER_TOO_SMALL");
			break;
		}

		ReadMemory = (READ_MEMORY*)Irp->AssociatedIrp.SystemBuffer;
		GamePid = (HANDLE)ReadMemory->ProcessId;
		SourceAddress = (PVOID)ReadMemory->addressSrc;
		DestinationAddress = ReadMemory->addressDst;

		// Looking for the targeted process and perform the read operation
		status = PsLookupProcessByProcessId(GamePid, &processObject);
		if (NT_SUCCESS(status) && SourceAddress != NULL && DestinationAddress != NULL) {
			status = KeReadVirtualMemory(processObject, SourceAddress, DestinationAddress, ReadMemory->size);
		}
		else {
			DbgPrint("Memory read setting failed\n");
		}

		ObDereferenceObject(processObject);
		break;

	case BYPASS_DRIVER_WRITE_GAME_MEMORY:
		if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(WRITE_MEMORY)) {
			status = STATUS_BUFFER_TOO_SMALL;
			DbgPrint("[!] STATUS_BUFFER_TOO_SMALL\n");
			break;
		}

		WriteMemory = (WRITE_MEMORY*)Irp->AssociatedIrp.SystemBuffer;
		GamePid = (HANDLE)WriteMemory->ProcessId;
		SourceAddress = WriteMemory->addressSrc;
		DestinationAddress = (PVOID)WriteMemory->addressDst;

		// Looking for the targeted process and perform the write operation
		status = PsLookupProcessByProcessId(GamePid, &processObject);
		if (NT_SUCCESS(status) && SourceAddress != NULL && DestinationAddress != NULL) {
			status = KeWriteVirtualMemory(processObject, SourceAddress, DestinationAddress, WriteMemory->size);
		}
		else {
			DbgPrint("Memory write setting failed\n");
		}

		ObDereferenceObject(processObject);
		break;

	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		DbgPrint("Incorrect IOCTL\n");
		break;
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIoControl;
	DriverObject->DriverUnload = DriverUnload;

	PDEVICE_OBJECT DeviceObject;
	NTSTATUS status = IoCreateDevice(DriverObject,
		0,
		&DeviceName,
		FILE_DEVICE_UNKNOWN,
		0,
		FALSE,
		&DeviceObject);

	if (!NT_SUCCESS(status)) {
		DbgPrint("Failed to create the device object (0x%08x)\n", status);
	}

	status = IoCreateSymbolicLink(&symlink, &DeviceName);

	if (!NT_SUCCESS(status)) {
		DbgPrint("Failed to create the symbolic link (0x%08x)\n", status);
		IoDeleteDevice(DriverObject->DeviceObject);
		return status;
	}

	return STATUS_SUCCESS;
}

