///////////////////////////////////////////////////////////////////////////////
//
//	File system filter driver project file
//
//	fsfltr.cpp - contain driver code
//
//		Author:		Baranov Artem
//		Creation date:	11.03.2008
//		Last modify:	25.04.2008
//
//
///////////////////////////////////////////////////////////////////////////////

extern "C" {
#include <ntifs.h>
#include <ntdddisk.h>
#include <fsfltr_data.h>
#include <fsfltr.h>
}

///////////////////////////////////////////////////////////////////////////////
// Modified/new function list for test
//
// FsFltrNotification +
// FsFltrDispatchFileSystemControl - assert was change
// FsFltrFastIoDetachDevice - for non-our dev success
// IoCompletionMount +
// GetDosDeviceNameByVolumeDeviceObject - change index in buffer for DOS name
// FsFltrDetachFromFsCtrlDevStack +
// FsFltrAttachToFsCtrlDevStack +
// FsFltrFastIoDetachDevice
// test on unmount
//
//////////////////////////////////////////////////////////////////////////////

#pragma warning(error:4100)   // Unreferenced formal parameter
#pragma warning(error:4101)   // Unreferenced local variable

//is my dev?
#define IS_MY_DEV_OBJ( DevObj ) \
	( ( ( DevObj ) != NULL ) && \
	  (	( DevObj )->DriverObject == FsFltrDriverObject ) && \
	  ( ( DevObj )->DeviceExtension != NULL ) )
//is my control dev?
#define IS_MY_CTRL_DEV_OBJ( DevObj ) \
	( ( DevObj ) == FsFltrCDO && \
	( ( DevObj )->DeviceExtension != NULL ) )

//ptr to driver
PDRIVER_OBJECT FsFltrDriverObject = NULL;
//ptr to Control Device Object of filter
PDEVICE_OBJECT FsFltrCDO = NULL;

//all possible drives for hook
ULONG maxDrivesToHookMask = 0; 
//current drives hook
ULONG curDrivesToHookMask = 0;
//if true, send opened files in user mode
LONG IsAvxActive = 0;

//buf of ptrs to device attached to fs stack 
PDEVICE_OBJECT DriveHookDevicesTable[MAX_DRIVES_FOR_HOOK]; 

#define GetSizeOfPendingFileInformation( cbStr ) \
	( ( cbStr ) + sizeof( PENDING_FILE_INFORMATION ) - sizeof( WCHAR ) )

extern "C" {

__declspec(dllimport) 
NTSTATUS 
__stdcall ZwQueryInformationProcess(
	IN HANDLE hProcess,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);

//entry point
NTSTATUS
DriverEntry( 
	IN PDRIVER_OBJECT DriverObj, 
	IN PUNICODE_STRING RegPath );

//post-dispatch for StartIo
VOID
FsFltrDeviceControlCompleteWorker(
	IN PDEVICE_OBJECT DeviceObject,
	IN PVOID Context
	);

//StartIo
VOID
FsFltrStartIo(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	);

//scan file antivirus
VOID AvxCheckFile(
	IN PDEVICE_EXTENSION pdx,
	IN PIRP Irp,
	IN BOOLEAN IsFastIoRequestor
	);
	
//initialize and register fast I/O
NTSTATUS
FsFltrFastIoInitOrUninit( 
	IN PDRIVER_OBJECT DriverObj, 
	IN ULONG IsInit 
	);

//stub for dispatch I/O requests, that not filtered by driver
NTSTATUS
FsFltrDispatchIoRequest(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	);

BOOLEAN
CheckPidForTrusted(
   IN HANDLE Pid
   );

BOOLEAN
CheckPidForTrustedUnsafe(
	IN HANDLE Pid
   );

//query disks for hooking
NTSTATUS 
GetDrivesToHook(  );

//create device object and attach it to specified volume 'A'+DeviceIndex
NTSTATUS 
FsFltrAttachDeviceToDeviceStackByDevIndex( 
	IN UCHAR DeviceIndex 
	);

//retrive object full name by ptr to it
NTSTATUS
FsFltrQueryNameString(
	IN PVOID Object,
	OUT UNICODE_STRING **ObjectName
	);

//unhook drives, not implemented
VOID 
FsFltrUnhookDrive(
	IN UCHAR DeviceIndex 
	); 

//in conformity of global mask maxDrivesToHookMask try hook drives
ULONG 
FsFltrHookOrUnhookDrives( 
	IN ULONG IsHook 
	);

//set completion function for post-dispatch IRP_MJ_DIRECTORY_CONTROL request
NTSTATUS 
FsFltrDispatchDirectoryControlRequest( 
	IN PDEVICE_OBJECT DeviceObject, 
	IN PIRP Irp 
	);

//walk by all files, that copied in Irp->UserBuffer and check it on hide
NTSTATUS
FsFltrCompletionForDirControl(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp,
	IN OPTIONAL PVOID Context
);

//return true if file need for hide
BOOLEAN 
CheckFileOnHide(  
	IN PFILE_OBJECT FileObject,
	IN PFILE_BOTH_DIR_INFORMATION BothDirInfo,
	IN UCHAR DriveLetter
	);

//for QueryFileObject return name of file
NTSTATUS
QueryFileSystemForFileName(
    PFILE_OBJECT QueryFileObject,
	PDEVICE_OBJECT DeviceObject,
	WCHAR **FileName
	);

//IoCompletion for QueryFileSystemForFileName request
NTSTATUS
FsFltrQueryFileInfoCompletion(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp,
	PKEVENT Event
	);

//cancel IO function for IOCTL_LISTEN_CREATE_REQUEST request
VOID
Cancel(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp
	);

//return 4-bytes checksum, which calculate with CRC32
ULONG 
CreateChkSumForStr( 
	IN PANSI_STRING StrForCalcChkSum 
	);

//return count hide files from \parameters subkey, HideFiles parameter
ULONG 
CheckHideFilesInRegistry( 
	IN PUNICODE_STRING DriverRegPath 
	);

//alloc mem block with specified for FILE_FOR_HIDE struct size and tag
PFILE_FOR_HIDE
FsFltrAllocateForHideFileStruct(  
	);

//free mem under FILE_FOR_HIDE
VOID
FsFltrFreeForHideFileStruct(
	IN PFILE_FOR_HIDE p
	);

//calculate number of chars in string
ULONG 
str_len( 
	IN PWSTR str 
	);

//insert/delete entry from list of hide files and return string length with NULL in bytes 
//(next string offset in REG_MULTI_SZ)
ULONG
InsertOrDeleteEntryInListOfHideFiles( 
	IN PWCHAR FileName,
	IN BOOLEAN IsInsert
	);

//delete struct from list of hide files; string must already in upper case
BOOLEAN
DeleteEntryFromListOfHideFiles( 
	IN PANSI_STRING FileName 
	);

//return ptr to elem with specified in arg checksum
PFILE_FOR_HIDE
LookupHideFileInListOfHideFilesByChkSum(
   IN ULONG ChkSum
   );

//convert all chars in str to upper case
VOID
UpcaseAnsiString(
	IN PANSI_STRING StrForUpper
	);

//dispatch IRP_MJ_CREATE, IRP_MJ_CLOSE, IRP_MJ_CLEANUP and if need set completion routine
NTSTATUS
FsFltrDispatchCreateOrCloseOrCleanupRequest(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	);

//function for completion IRP_MJ_CREATE request; return STATUS_MORE_PROCESSING_REQUIRED
NTSTATUS
FsFltrCreateCompletion(
   IN PDEVICE_OBJECT DeviceObject,
   IN PIRP Irp,
   IN OPTIONAL PVOID Context
   );

//create full path for file object; after using, must call FsFltrFreeFullPath
NTSTATUS
FsFltrCreateFullPath(
	 IN PFILE_OBJECT FileObject,
	 OUT WCHAR** FullPath,
	 IN CHAR VolLetter,
	 IN PDEVICE_EXTENSION pdx
	);

//free buffer that create in FsFltrCreateFullPath
__inline
VOID
FsFltrFreeFullPath(
   PWSTR FullPath
	);

//dispatch IRP_MJ_DEVICE_CONTROL
NTSTATUS
FsFltrDispatchDeviceControl(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp 
	);

//dispatch control request from user mode
NTSTATUS 
FsFltrpDispatchDeviceControl(
	 IN PIO_STACK_LOCATION IoStack,
	 OUT PIO_STATUS_BLOCK piosb,
	 IN OPTIONAL PMDL Mdl
	);

//return count elements in list of hide files
ULONG
GetCountElementsInListOfHideFiles(
	 );

//return ptr to entry by index
BOOLEAN
GetElementFromListByIndexUnsafe(
	IN ULONG Index,
	OUT LIST_ENTRY **FileForHide
	);

//routine to be called whenever a file system registers or unregisters itself as an active file system
VOID
FsFltrNotification(
   IN PDEVICE_OBJECT DeviceObject,
   IN BOOLEAN FsActive
   );

//check file that opened by IRP_MJ_CREATE request on hide and modified IoStatus if it mark as hide
VOID 
DrmDispatchOpenOrCreateFile(
	 PDEVICE_OBJECT DeviceObject,
	 PIRP Irp
	 );

//attach DeviceObject to file system control device object
VOID
FsFltrAttachToFsCtrlDevStack(
   IN PDEVICE_OBJECT DeviceObject
   );

//detach DeviceObject from file system control device object
VOID 
FsFltrDetachFromFsCtrlDevStack(
	IN PDEVICE_OBJECT DeviceObject
	);

//dispatch IRP_MJ_FILE_SYSTEM_CONTROL; if mount request, set completion routine, otherwise skip IRP
NTSTATUS
FsFltrDispatchFileSystemControl(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	);

//set event by ptr Context and return STATUS_MORE_PROCESSING_REQUIRED
NTSTATUS
IoCompletionMount(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp,
	IN PVOID Context
	);

//on input, ptr to volume device object/partition device object, on output letter of volume
NTSTATUS
GetDosDeviceNameByVolumeDeviceObject(
	IN PVOID VolumeDeviceObject,
	OUT CHAR* pVolLetter
	);

//check device object in DriveHookDevicesTable
ULONG
CheckDeviceInHookDeviceBuffer(
	PDEVICE_OBJECT DeviceObject
	);

//dispatch add/remove/query pids for list of trusted pids
NTSTATUS
FsFltrDispatchTrustedProcessOp(
   IN PULONG InputBuffer,
   IN ULONG InputBufferLength,
   OUT PULONG OutputBuffer,
   IN ULONG OutputBufferLength,
   IN ULONG IoControlCode,
   IN PIO_STATUS_BLOCK iosb
   );

//skip request
BOOLEAN FsFltrFastIoCheckIfPossible( 
	IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN BOOLEAN Wait,
    IN ULONG LockKey,
    IN BOOLEAN CheckForReadOperation,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );

//skip request
BOOLEAN
FsFltrFastIoRead (
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN BOOLEAN Wait,
    IN ULONG LockKey,
    OUT PVOID Buffer,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );

//skip request
BOOLEAN
FsFltrFastIoWrite (
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN BOOLEAN Wait,
    IN ULONG LockKey,
    IN PVOID Buffer,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );

//skip request
BOOLEAN
FsFltrFastIoQueryBasicInfo (
    IN PFILE_OBJECT FileObject,
    IN BOOLEAN Wait,
    OUT PFILE_BASIC_INFORMATION Buffer,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );

//skip request
BOOLEAN
FsFltrFastIoQueryStandardInfo (
    IN PFILE_OBJECT FileObject,
    IN BOOLEAN Wait,
    OUT PFILE_STANDARD_INFORMATION Buffer,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );

//skip request
BOOLEAN
FsFltrFastIoLock (
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN PLARGE_INTEGER Length,
    IN PEPROCESS ProcessId,
    IN ULONG Key,
    IN BOOLEAN FailImmediately,
    IN BOOLEAN ExclusiveLock,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );

//skip request
BOOLEAN
FsFltrFastIoUnlockSingle (
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN PLARGE_INTEGER Length,
    IN PEPROCESS ProcessId,
    IN ULONG Key,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );

//skip request
BOOLEAN
FsFltrFastIoUnlockAll (
    IN PFILE_OBJECT FileObject,
    IN PEPROCESS ProcessId,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );

//skip request
BOOLEAN
FsFltrFastIoUnlockAllByKey (
    IN PFILE_OBJECT FileObject,
    IN PVOID ProcessId,
    IN ULONG Key,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );

//skip request
BOOLEAN
FsFltrFastIoDeviceControl (
    IN PFILE_OBJECT FileObject,
    IN BOOLEAN Wait,
    IN PVOID InputBuffer,
    IN ULONG InputBufferLength,
    OUT PVOID OutputBuffer,
    IN ULONG OutputBufferLength,
    IN ULONG IoControlCode,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );

//detach from TargetDevice and delete SourceDevice
VOID
FsFltrFastIoDetachDevice (
    IN PDEVICE_OBJECT SourceDevice,
    IN PDEVICE_OBJECT TargetDevice
    );

//skip request
BOOLEAN
FsFltrFastIoQueryNetworkOpenInfo (
    IN PFILE_OBJECT FileObject,
    IN BOOLEAN Wait,
    OUT PFILE_NETWORK_OPEN_INFORMATION Buffer,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );

//skip request
BOOLEAN
FsFltrFastIoMdlRead (
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN ULONG LockKey,
    OUT PMDL *MdlChain,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );

//skip request
BOOLEAN
FsFltrFastIoMdlReadComplete (
    IN PFILE_OBJECT FileObject,
    IN PMDL MdlChain,
    IN PDEVICE_OBJECT DeviceObject
    );

//skip request
BOOLEAN
FsFltrFastIoPrepareMdlWrite (
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN ULONG LockKey,
    OUT PMDL *MdlChain,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );

//skip request
BOOLEAN
FsFltrFastIoMdlWriteComplete (
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN PMDL MdlChain,
    IN PDEVICE_OBJECT DeviceObject
    );

//skip request
BOOLEAN
FsFltrFastIoReadCompressed (
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN ULONG LockKey,
    OUT PVOID Buffer,
    OUT PMDL *MdlChain,
    OUT PIO_STATUS_BLOCK IoStatus,
    OUT struct _COMPRESSED_DATA_INFO *CompressedDataInfo,
    IN ULONG CompressedDataInfoLength,
    IN PDEVICE_OBJECT DeviceObject
    );

//skip request
BOOLEAN
FsFltrFastIoWriteCompressed (
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN ULONG LockKey,
    IN PVOID Buffer,
    OUT PMDL *MdlChain,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN struct _COMPRESSED_DATA_INFO *CompressedDataInfo,
    IN ULONG CompressedDataInfoLength,
    IN PDEVICE_OBJECT DeviceObject
    );

//skip request
BOOLEAN
FsFltrFastIoMdlReadCompleteCompressed (
    IN PFILE_OBJECT FileObject,
    IN PMDL MdlChain,
    IN PDEVICE_OBJECT DeviceObject
    );

//skip request
BOOLEAN
FsFltrFastIoMdlWriteCompleteCompressed (
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN PMDL MdlChain,
    IN PDEVICE_OBJECT DeviceObject
    );

//dispatch open fast I/O, check on hide files
BOOLEAN
FsFltrFastIoQueryOpen (
    IN PIRP Irp,
    OUT PFILE_NETWORK_OPEN_INFORMATION NetworkInformation,
    IN PDEVICE_OBJECT DeviceObject
    );

//for support only
NTSTATUS
FsFltrPreFsFltrPassThrough (
    IN PFS_FILTER_CALLBACK_DATA Data,
    OUT PVOID *CompletionContext
    );

//for support only
VOID
FsFltrPostFsFltrPassThrough (
    IN PFS_FILTER_CALLBACK_DATA Data,
    IN NTSTATUS OperationStatus,
    IN PVOID CompletionContext
    );

NTSTATUS
FsFltrReadMBRSynch(
	);

NTSTATUS FsFltrReadMBRAsynch(
	);

NTSTATUS
IoCompletionRead(
	 IN PDEVICE_OBJECT DeviceObject,
	 IN PIRP Irp,
	 IN OPTIONAL PVOID Context
	);
}

#ifdef ALLOC_PRAGMA
	#pragma alloc_text( INIT, DriverEntry )
	#pragma alloc_text( INIT, FsFltrAttachDeviceToDeviceStackByDevIndex )
	#pragma alloc_text( INIT, CheckHideFilesInRegistry )
	#pragma alloc_text( INIT, GetDrivesToHook )

	#pragma alloc_text( PAGE, FsFltrDispatchTrustedProcessOp )
	#pragma alloc_text( PAGE, CheckPidForTrusted )
	#pragma alloc_text( PAGE, CheckPidForTrustedUnsafe )
	#pragma alloc_text( PAGE, FsFltrFastIoInitOrUninit )
	#pragma alloc_text( PAGE, FsFltrUnhookDrive )
	#pragma alloc_text( PAGE, FsFltrHookOrUnhookDrives )
	#pragma alloc_text( PAGE, FsFltrDispatchIoRequest )
	#pragma alloc_text( PAGE, FsFltrDispatchDirectoryControlRequest )
	#pragma alloc_text( PAGE, CheckFileOnHide )
	#pragma alloc_text( PAGE, CreateChkSumForStr )
	#pragma alloc_text( PAGE, FsFltrAllocateForHideFileStruct )
	#pragma alloc_text( PAGE, FsFltrFreeForHideFileStruct )
	#pragma alloc_text( PAGE, InsertOrDeleteEntryInListOfHideFiles )
	#pragma alloc_text( PAGE, DeleteEntryFromListOfHideFiles )
	#pragma alloc_text( PAGE, FsFltrDispatchCreateOrCloseOrCleanupRequest )
	#pragma alloc_text( PAGE, FsFltrCreateFullPath )
	#pragma alloc_text( PAGE, FsFltrFreeFullPath )
	#pragma alloc_text( PAGE, FsFltrCreateCompletion )
	#pragma alloc_text( PAGE, LookupHideFileInListOfHideFilesByChkSum )
	#pragma alloc_text( PAGE, FsFltrDispatchDeviceControl )
	#pragma alloc_text( PAGE, FsFltrpDispatchDeviceControl )
	#pragma alloc_text( PAGE, FsFltrNotification )
	#pragma alloc_text( PAGE, FsFltrAttachToFsCtrlDevStack )
	#pragma alloc_text( PAGE, FsFltrDetachFromFsCtrlDevStack )
	#pragma alloc_text( PAGE, FsFltrDispatchFileSystemControl )
	#pragma alloc_text( PAGE, GetDosDeviceNameByVolumeDeviceObject )
	#pragma alloc_text( PAGE, IoCompletionMount )
	#pragma alloc_text( PAGE, GetCountElementsInListOfHideFiles )
	#pragma alloc_text( PAGE, GetElementFromListByIndexUnsafe )
	#pragma alloc_text( PAGE, CheckDeviceInHookDeviceBuffer )
	#pragma alloc_text( PAGE, FsFltrQueryNameString )
	#pragma alloc_text( PAGE, FsFltrDeviceControlCompleteWorker )
	#pragma alloc_text( PAGE, AvxCheckFile )
	#pragma alloc_text( PAGE, QueryFileSystemForFileName )
	#pragma alloc_text( PAGE, FsFltrQueryFileInfoCompletion )
	#pragma alloc_text( PAGE, DrmDispatchOpenOrCreateFile )
	
  	#pragma alloc_text( PAGE, FsFltrFastIoCheckIfPossible )
	#pragma alloc_text( PAGE, FsFltrFastIoRead )
	#pragma alloc_text( PAGE, FsFltrFastIoWrite )
	#pragma alloc_text( PAGE, FsFltrFastIoQueryBasicInfo )
	#pragma alloc_text( PAGE, FsFltrFastIoQueryStandardInfo )
	#pragma alloc_text( PAGE, FsFltrFastIoLock )
	#pragma alloc_text( PAGE, FsFltrFastIoUnlockSingle )
	#pragma alloc_text( PAGE, FsFltrFastIoUnlockAll )
	#pragma alloc_text( PAGE, FsFltrFastIoUnlockAllByKey )
	#pragma alloc_text( PAGE, FsFltrFastIoDeviceControl )
	#pragma alloc_text( PAGE, FsFltrFastIoDetachDevice )
	#pragma alloc_text( PAGE, FsFltrFastIoQueryNetworkOpenInfo )
	#pragma alloc_text( PAGE, FsFltrFastIoMdlRead )
	#pragma alloc_text( PAGE, FsFltrFastIoMdlReadComplete )
	#pragma alloc_text( PAGE, FsFltrFastIoPrepareMdlWrite )
	#pragma alloc_text( PAGE, FsFltrFastIoMdlWriteComplete )
	#pragma alloc_text( PAGE, FsFltrFastIoReadCompressed )
	#pragma alloc_text( PAGE, FsFltrFastIoWriteCompressed )
	#pragma alloc_text( PAGE, FsFltrFastIoMdlReadCompleteCompressed )
	#pragma alloc_text( PAGE, FsFltrFastIoMdlWriteCompleteCompressed )
	#pragma alloc_text( PAGE, FsFltrFastIoQueryOpen )
#endif

/****************************************************************************/
/*  Function Name: DriverEntry                                              */
/*  Section: INIT                                                           */
/*  Description: initializes driver object, registers fast I/O,             */
/*               registers callbacks, creates CDO, creates symbolic link,   */
/*               initializes list of hide files and synch fast mutex, sets  */
/*               global	mask of hooked drive, attachs to all support mount  */
/*               volumes, registers file system registration change         */
/*               function, checks parameter HideFiles (REG_MULTI_SZ) in     */
/*               subkey \parameter.                                         */
/*  Return: NT status                                                       */
/****************************************************************************/

NTSTATUS DriverEntry( PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath )
{
	UNICODE_STRING unDevFullName = { 0 };
	UNICODE_STRING unSymLinkOfCDOName = { 0 };
	NTSTATUS status = STATUS_SUCCESS;
	ULONG cHookedDrives = 0;
	PDEVICE_EXTENSION_CDO pdx_cdo = NULL;
	RTL_OSVERSIONINFOW os_ver = { 0 };
	BOOLEAN IsSupportVer = FALSE;
	
	enum CodeFailed {
		Success,
		CreateCDO,
		CreateSymLink,
		GetDrives,
		HookDrives 
	} FailedCode = Success;

	//check NT version
	status = RtlGetVersion( &os_ver );
	ASSERT( NT_SUCCESS( status ) );

	if( ( os_ver.dwMajorVersion == 5 && os_ver.dwMinorVersion >= 1 ) ||
		( os_ver.dwMajorVersion > 5 && os_ver.dwMajorVersion < 7 ) )
	{
		IsSupportVer = TRUE;
	}

	if( !IsSupportVer )
	{
		KdPrint( ( "OS version not support\n" ) );
		return STATUS_NOT_SUPPORTED;
	}
	
	FsFltrDriverObject = DriverObject;

	for( register ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++ )
		DriverObject->MajorFunction[i] = FsFltrDispatchIoRequest;

	DriverObject->MajorFunction[IRP_MJ_DIRECTORY_CONTROL] = 
		FsFltrDispatchDirectoryControlRequest;
	
	DriverObject->MajorFunction[IRP_MJ_CREATE] = 
		DriverObject->MajorFunction[IRP_MJ_CLOSE] =
			DriverObject->MajorFunction[IRP_MJ_CLEANUP] = 
		FsFltrDispatchCreateOrCloseOrCleanupRequest;

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = 
		FsFltrDispatchDeviceControl;

	DriverObject->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL] =
		FsFltrDispatchFileSystemControl;

	//FsFltrDriverObject->DriverUnload = FsFltrUnload;
		
	FsFltrFastIoInitOrUninit( DriverObject, 1 );

	DriverObject->DriverStartIo = FsFltrStartIo;

	RtlInitUnicodeString( &unDevFullName, L"\\FileSystem\\Filters\\FsFltrCDO" );
	RtlInitUnicodeString( &unSymLinkOfCDOName, L"\\??\\FsFltr" );

	__try
	{
		status = IoCreateDevice( DriverObject,
			sizeof( DEVICE_EXTENSION_CDO ), //no dev ext
			&unDevFullName,
			FILE_DEVICE_DISK_FILE_SYSTEM, //dev type
			FILE_DEVICE_SECURE_OPEN, //dev characteristics
			FALSE,
			&FsFltrCDO );

		if( !NT_SUCCESS( status ) )
		{
			FailedCode = CreateCDO;
			KdPrint( ( "FsFltr!DriverEntry: Error creating control device object \"%wZ\",status=%08x\n", &unDevFullName, status ) );
			__leave;
		}

		KeInitializeDeviceQueue( &FsFltrCDO->DeviceQueue );

		IoSetStartIoAttributes( FsFltrCDO, 
			TRUE, //deferred start I/O
			FALSE //non cancel routine
			);

		status = IoCreateSymbolicLink( &unSymLinkOfCDOName, &unDevFullName );
		if( !NT_SUCCESS( status ) )
		{
			FailedCode = CreateSymLink;
			KdPrint( ( "FsFltr!DriverEntry: Error creating symbolic link \"%wZ\",status=%08x\n", 
				&unSymLinkOfCDOName, status ) );
			__leave;
		}

		pdx_cdo = (PDEVICE_EXTENSION_CDO)FsFltrCDO->DeviceExtension;
		RtlZeroMemory( pdx_cdo, sizeof( DEVICE_EXTENSION_CDO ) );

		InitializeListHead( &pdx_cdo->ListOfHideFiles );
		ExInitializeFastMutex( &pdx_cdo->MutexForGuardList );
		KeInitializeSemaphore( &pdx_cdo->SemGuardPendingCreate, 0, 0x7FFFFFFF );
		KeInitializeSpinLock( &pdx_cdo->LockGuardPendingCreate );
		InitializeListHead( &pdx_cdo->ListOfPendingCreate );
		KeInitializeEvent( &pdx_cdo->SynchEvent, SynchronizationEvent, FALSE );
		KeInitializeEvent( &pdx_cdo->CancelIrpEvent, SynchronizationEvent, FALSE );
		InitializeListHead( &pdx_cdo->ListOfTrustedProcesses );
		ExInitializeFastMutex( &pdx_cdo->MutexGuardListOfTrustedProc );

		status = GetDrivesToHook(  );

		if( !NT_SUCCESS( status ) )
		{
			FailedCode = GetDrives;
			KdPrint( ( "FsFltr!DriverEntry: GetDrivesToHook failed, status=%08x\n",status ) );
			__leave;
		}

		cHookedDrives = FsFltrHookOrUnhookDrives( TRUE );
		if( cHookedDrives == 0 )
		{
			status = STATUS_UNSUCCESSFUL;
			FailedCode = HookDrives;
			KdPrint( ( "FsFltr!DriverEntry: FsFltrHookOrUnhookDrives no devices for hooking\n" ) );
			__leave;
		}

		IoRegisterFsRegistrationChange( DriverObject, FsFltrNotification );

		CheckHideFilesInRegistry( RegPath );
	}
	__finally
	{ //cleanup if failure
		if( FailedCode != Success )
		{
			switch( FailedCode )
			{
				case HookDrives:
				case GetDrives:
				{
					IoDeleteSymbolicLink( &unSymLinkOfCDOName );
				}
				case CreateSymLink:
				{
					IoDeleteDevice( FsFltrCDO );
				}
				case CreateCDO:
				{
					FsFltrFastIoInitOrUninit( DriverObject, 0 );
					break;
				}
				default:
				{
					ASSERT( 0 );
					break;
				}
			}
		}
	}
	
	return status;
}

//execute at DISPATCH_LEVEL, must release global cancel spinlock
VOID
Cancel(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp
	)
{
	ASSERT( IS_MY_CTRL_DEV_OBJ( DeviceObject ) );
	ASSERT( Irp );
	
	if( Irp == DeviceObject->CurrentIrp )
	{
		PDEVICE_EXTENSION_CDO pdx_cdo = 
			( PDEVICE_EXTENSION_CDO )DeviceObject->DeviceExtension;

		IoReleaseCancelSpinLock( Irp->CancelIrql );

		KeSetEvent( &pdx_cdo->CancelIrpEvent, IO_NO_INCREMENT, FALSE );
		return;
	}
	else
	{
		if( KeRemoveEntryDeviceQueue( &DeviceObject->DeviceQueue, 
			&Irp->Tail.Overlay.DeviceQueueEntry ) == TRUE )
		{

			Irp->IoStatus.Status = STATUS_CANCELLED;
			Irp->IoStatus.Information = 0;

			IoReleaseCancelSpinLock( Irp->CancelIrql );

			IoCompleteRequest( Irp, IO_NO_INCREMENT );

			return;
		}
		else
		{
			IoReleaseCancelSpinLock( Irp->CancelIrql );

			return;
		}
	}

	return;
}

//called at PASSIVE_LEVEL
VOID
FsFltrDeviceControlCompleteWorker(
	IN PDEVICE_OBJECT DeviceObject,
	IN PVOID Context
	)
{
	PIO_WORKITEM WorkItem = ( PIO_WORKITEM )Context;
	PIRP Irp = DeviceObject->CurrentIrp; //pending packet
	PPENDING_FILE_INFORMATION PendingFileInfo = NULL;
	ULONG cbPendingFileInformation = 0;
	
	PDEVICE_EXTENSION_CDO pdx_cdo = NULL;
	PLIST_ENTRY QueryEntry = NULL;
	PFILE_PENDING_CREATE FilePending;
	PIO_STACK_LOCATION IoStack = NULL;

	VOID *WaitBuf[2];
	NTSTATUS WaitStatus;

	PAGED_CODE(  );

	ASSERT( Context );
	ASSERT( Irp );
	ASSERT( IS_MY_CTRL_DEV_OBJ( DeviceObject ) );

	pdx_cdo = ( PDEVICE_EXTENSION_CDO ) DeviceObject->DeviceExtension;
	IoStack = IoGetCurrentIrpStackLocation( Irp );

	ASSERT( IoStack->MajorFunction == IRP_MJ_DEVICE_CONTROL );
	ASSERT( IoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_LISTEN_CREATE_REQUEST );

	WaitBuf[0] = &pdx_cdo->SemGuardPendingCreate;
	WaitBuf[1] = &pdx_cdo->CancelIrpEvent;

	WaitStatus = KeWaitForMultipleObjects( 2, WaitBuf, WaitAny, Executive, 
		KernelMode, FALSE, NULL, NULL );
	
	if( WaitStatus == STATUS_WAIT_1 )
	{
		ASSERT( Irp->Cancel );

		Irp->IoStatus.Status = STATUS_CANCELLED;
		Irp->IoStatus.Information = 0;

		IoCompleteRequest( Irp, IO_NO_INCREMENT );

		IoFreeWorkItem( WorkItem );

		KIRQL OldIrql = KeRaiseIrqlToDpcLevel(  );
		ASSERT( OldIrql == PASSIVE_LEVEL );

		IoStartNextPacket( DeviceObject, FALSE );

		KeLowerIrql( PASSIVE_LEVEL );

		return;
	}

	ASSERT( WaitStatus == STATUS_WAIT_0 );

	//check buffer size
	FilePending = CONTAINING_RECORD( pdx_cdo->ListOfPendingCreate.Flink, 
		FILE_PENDING_CREATE, NextStruct );

	cbPendingFileInformation = 
		GetSizeOfPendingFileInformation( FilePending->FileName.MaximumLength );

	if( IoStack->Parameters.DeviceIoControl.OutputBufferLength < cbPendingFileInformation )
	{
		Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		Irp->IoStatus.Information = 0;

		IoCompleteRequest( Irp, IO_NO_INCREMENT );

		KIRQL OldIrql = KeRaiseIrqlToDpcLevel(  );
		ASSERT( OldIrql == PASSIVE_LEVEL );

		IoStartNextPacket( DeviceObject, TRUE );

		KeLowerIrql( PASSIVE_LEVEL );

		return;
	}
	
	QueryEntry = ExInterlockedRemoveHeadList( &pdx_cdo->ListOfPendingCreate,
		&pdx_cdo->LockGuardPendingCreate );

	FilePending = CONTAINING_RECORD( QueryEntry, FILE_PENDING_CREATE, NextStruct );

	PendingFileInfo = ( PPENDING_FILE_INFORMATION )Irp->AssociatedIrp.SystemBuffer;

	RtlZeroMemory( PendingFileInfo, cbPendingFileInformation );

	RtlCopyMemory( &PendingFileInfo->FileName, FilePending->FileName.Buffer, 
		FilePending->FileName.MaximumLength );

	PendingFileInfo->Internal.RequestorId = FilePending->Requestor;
	RtlCopyMemory( &PendingFileInfo->Cid.UniqueProcess, 
		&FilePending->Cid.UniqueProcess, sizeof( CLIENT_ID ) );
	PendingFileInfo->CreateDisposition = FilePending->CreateDisposition;
	PendingFileInfo->cbFile = FilePending->FileName.MaximumLength;

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = cbPendingFileInformation;

	IoSetCancelRoutine( Irp, NULL );

	IoCompleteRequest( Irp, IO_NO_INCREMENT );

	KeWaitForSingleObject( &pdx_cdo->SynchEvent, Executive, 
		KernelMode, FALSE, NULL ); //wait reply from user mode through dev control dispatch func

	*FilePending->FinalStatus = pdx_cdo->ReceivedStatus;

	KeSetEvent( FilePending->SynchEvent, IO_NO_INCREMENT, FALSE );

	//cleanup
	ExFreePoolWithTag( FilePending->FileName.Buffer, FS_FLTR_STD_TAG );
	ExFreePoolWithTag( FilePending, FS_FLTR_STD_TAG );

	IoFreeWorkItem( WorkItem );

	KIRQL OldIrql = KeRaiseIrqlToDpcLevel(  );
	ASSERT( OldIrql == PASSIVE_LEVEL );

	IoStartNextPacket( DeviceObject, FALSE );

	KeLowerIrql( PASSIVE_LEVEL );

	return;
}

//called at DISPATCH_LEVEL
VOID
FsFltrStartIo(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	)
{
	PIO_WORKITEM WorkItem = NULL;

	ASSERT( IS_MY_CTRL_DEV_OBJ( DeviceObject ) );
	UNREFERENCED_PARAMETER( Irp );

	WorkItem = IoAllocateWorkItem( DeviceObject );

	//if( WorkItem == NULL )
	IoQueueWorkItem( WorkItem, FsFltrDeviceControlCompleteWorker,
		DelayedWorkQueue, WorkItem );

	return;
}

/****************************************************************************/
/*  Function Name: FsFltrNotification                                       */
/*  Section: PAGED                                                          */
/*  Description: if file system is registered in I/O manager, call          */
/*               function for attach to it CDO, otherwise detach from it.   */
/*  Return: VOID                                                            */
/****************************************************************************/

VOID
FsFltrNotification(
	PDEVICE_OBJECT DeviceObject,
	BOOLEAN FsActive
   )
{
	PAGED_CODE(  );

	if( FsActive )
	{//IoRegisterFileSystem was called
		FsFltrAttachToFsCtrlDevStack( DeviceObject );
	}
	else
	{//IoUnregisterFileSystem was called
		FsFltrDetachFromFsCtrlDevStack( DeviceObject );
	}
}

/****************************************************************************/
/*  Function Name: FsFltrAttachToFsCtrlDevStack                             */
/*  Section: PAGED                                                          */
/*  Description: first, checks name of driver, that create DeviceObject,    */
/*               if it recognizer, skip attach, else creates device object  */
/*               and attachs it to CDO of fs.                               */
/*  Return: VOID                                                            */
/****************************************************************************/

VOID
FsFltrAttachToFsCtrlDevStack(
   PDEVICE_OBJECT DeviceObject
   )
{
	UNICODE_STRING fsrecName;
	POBJECT_NAME_INFORMATION ObjectInfo;
	ULONG cb;
	NTSTATUS status;
	PDEVICE_EXTENSION_FS_CDO fspdx;
	PDEVICE_OBJECT SourceDevice;

	PAGED_CODE(  );

	if( !IS_SUPPORTED_DEVICE_TYPE( DeviceObject->DeviceType ) )
		return;

	ObjectInfo = ( POBJECT_NAME_INFORMATION )
		ExAllocatePoolWithTag( PagedPool, 512, FS_FLTR_STD_TAG );

	if( !ObjectInfo ) return;
	RtlZeroMemory( ObjectInfo, 512 );

	RtlInitUnicodeString( &fsrecName, L"\\FileSystem\\Fs_Rec" );

	status = ObQueryNameString( DeviceObject->DriverObject,
		ObjectInfo, 512, &cb );

	if( !NT_SUCCESS( status ) )
	{
		ExFreePoolWithTag( ObjectInfo, FS_FLTR_STD_TAG );
		return;
	}

	if( RtlEqualUnicodeString( &fsrecName, &ObjectInfo->Name, TRUE ) == TRUE )
	{
		ExFreePoolWithTag( ObjectInfo, FS_FLTR_STD_TAG );
		return;
	}

	status = IoCreateDevice(
		FsFltrDriverObject,
		sizeof( DEVICE_EXTENSION_FS_CDO ), //ext size
		NULL, //dev name
		DeviceObject->DeviceType,
		0,
		FALSE,
		&SourceDevice );

	if( !NT_SUCCESS( status ) )
	{
		ExFreePoolWithTag( ObjectInfo, FS_FLTR_STD_TAG );
		return;
	}

	SetFlag( SourceDevice->Flags,
		FlagOn( DeviceObject->Flags,
		( DO_BUFFERED_IO |
		  DO_DIRECT_IO |
		  DO_SUPPORTS_TRANSACTIONS ) ) );

	SetFlag( SourceDevice->Characteristics,
		FlagOn( DeviceObject->Characteristics,
		( FILE_DEVICE_SECURE_OPEN ) ) );

	fspdx = (PDEVICE_EXTENSION_FS_CDO)SourceDevice->DeviceExtension;

	fspdx->NextDevInChain = 
		IoAttachDeviceToDeviceStack( SourceDevice, DeviceObject );

	if( !fspdx->NextDevInChain )
	{
		IoDeleteDevice( SourceDevice );
		ExFreePoolWithTag( ObjectInfo, FS_FLTR_STD_TAG );
	}

	ClearFlag( SourceDevice->Flags, DO_DEVICE_INITIALIZING );

	status = ObQueryNameString( DeviceObject,
		ObjectInfo, 512, &cb );

	if( !NT_SUCCESS( status ) )
	{
		KdPrint( ( "fsfltr!FsFltrAttachToFsCtrlDevStack: Successfully attach to unnamed CDO\n" ) );
	}
	else
	{
		KdPrint( ( "fsfltr!FsFltrAttachToFsCtrlDevStack: Successfully attach to CDO: %wZ\n", &ObjectInfo->Name ) );
	}

	ExFreePoolWithTag( ObjectInfo, FS_FLTR_STD_TAG );

	return;
}

NTSTATUS
FsFltrQueryNameString(
	PVOID Object,
	UNICODE_STRING **ObjectName
	)
{
	NTSTATUS status;
	ULONG cb;
	POBJECT_NAME_INFORMATION ObjectInfo;

	PAGED_CODE(  );

	ObjectInfo = ( POBJECT_NAME_INFORMATION )
		ExAllocatePoolWithTag( PagedPool, 512, FS_FLTR_STD_TAG );

	status = ObQueryNameString( Object,
		ObjectInfo, 512, &cb );

	if( NT_SUCCESS( status ) )
		*ObjectName = &ObjectInfo->Name;
	else
		*ObjectName = NULL;

	return status;
}

/****************************************************************************/
/*  Function Name: FsFltrDetachFromFsCtrlDevStack                           */
/*  Section: PAGED                                                          */
/*  Description: searches device object, that we attached, and then if      */
/*               found detach.                                              */
/*  Return: VOID                                                            */
/****************************************************************************/

VOID 
FsFltrDetachFromFsCtrlDevStack(
	PDEVICE_OBJECT DeviceObject
	)
{
	PDEVICE_OBJECT OurDev = NULL;
	PUNICODE_STRING DevName;
	NTSTATUS status;

	PAGED_CODE(  );

	OurDev = DeviceObject->AttachedDevice;

	while( OurDev != NULL )
	{
		if( IS_MY_DEV_OBJ( OurDev ) )
		{
			status = FsFltrQueryNameString( DeviceObject, &DevName );

			IoDetachDevice( DeviceObject );
			IoDeleteDevice( OurDev );

			if( NT_SUCCESS( status ) )
			{
				KdPrint( ( "fsfltr!FsFltrDetachFromFsCtrlDevStack: Successfully detach from CDO: %wZ\n", DevName ) );
			}
			else
			{
				KdPrint( ( "fsfltr!FsFltrDetachFromFsCtrlDevStack: Successfully detach from unnamed CDO\n" ) );
			}

			ExFreePoolWithTag( DevName, FS_FLTR_STD_TAG );
			return;
		}
		DeviceObject = OurDev;
		OurDev = DeviceObject->AttachedDevice;
	}
}

/****************************************************************************/
/*  Function Name: CheckHideFilesInRegistry                                 */
/*  Section: INIT                                                           */
/*  Description: gets file names from HideFiles (REG_MULTI_SZ) parameter    */
/*               in \parameters subkey and inserts it in list of hide files.*/
/*  Return: VOID                                                            */
/****************************************************************************/

ULONG 
CheckHideFilesInRegistry( 
	PUNICODE_STRING DriverRegPath 
	)
{
	PWCHAR pwszPathToParameters = NULL;
	WCHAR wszParameters[]=L"\\Parameters";
	UNICODE_STRING unPathToParameters = { 0 };
	HANDLE hParameters = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES ObjAttr = { 0 };
	ULONG numHideFiles = 0;
	UNICODE_STRING unValueName = { 0 };
	ULONG cbRegData;
	PKEY_VALUE_PARTIAL_INFORMATION pValuePartialData = NULL;
	ULONG next_offset = 0;

	pwszPathToParameters = (PWCHAR)ExAllocatePoolWithTag(
		PagedPool, DriverRegPath->Length + sizeof( wszParameters ), 
		FS_FLTR_STD_TAG );
	RtlZeroMemory( pwszPathToParameters, DriverRegPath->Length + sizeof( wszParameters ) );

	if( !pwszPathToParameters )
	{
		KdPrint(("fsfltr!CheckHideFilesInRegistry: No enough memory\n"));
		return 0;
	}
	__try
	{
		RtlCopyMemory( pwszPathToParameters, DriverRegPath->Buffer, DriverRegPath->Length );
		RtlCopyMemory( (PUCHAR)pwszPathToParameters + DriverRegPath->Length, 
			&wszParameters, sizeof( wszParameters ) );

		RtlInitUnicodeString( &unPathToParameters, pwszPathToParameters );
		InitializeObjectAttributes( &ObjAttr, &unPathToParameters, OBJ_CASE_INSENSITIVE,
			NULL, NULL );

		status = ZwOpenKey( &hParameters, KEY_QUERY_VALUE, &ObjAttr );
		if( status != STATUS_SUCCESS )
		{
			hParameters = NULL;
			__leave;
		}

		RtlInitUnicodeString( &unValueName, L"HideFiles" );
		status = ZwQueryValueKey( hParameters,
			&unValueName, KeyValuePartialInformation, NULL, 0,
			&cbRegData );

		if( status == STATUS_OBJECT_NAME_NOT_FOUND || cbRegData == 0L )
			__leave;

		cbRegData = min( cbRegData, PAGE_SIZE );

		pValuePartialData = (PKEY_VALUE_PARTIAL_INFORMATION)
			ExAllocatePoolWithTag( PagedPool, cbRegData, FS_FLTR_STD_TAG );

		if( !pValuePartialData ) __leave;

		status = ZwQueryValueKey( hParameters,
			&unValueName, KeyValuePartialInformation, pValuePartialData,
			cbRegData, &cbRegData );

		if( status != STATUS_SUCCESS || pValuePartialData->Type != REG_MULTI_SZ )
			__leave;

		for( PWCHAR QueryStr = (PWCHAR)&pValuePartialData->Data;
			 QueryStr[0];
			 QueryStr = ( PWCHAR )( (PUCHAR)QueryStr + next_offset )  )
		{
			next_offset = InsertOrDeleteEntryInListOfHideFiles( QueryStr, 1 );
			numHideFiles++;
		}
	}
	__finally
	{
		if( pwszPathToParameters ) 
			ExFreePoolWithTag( pwszPathToParameters, FS_FLTR_STD_TAG );
		if( hParameters )
			ZwClose( hParameters );
		if( pValuePartialData )
			ExFreePoolWithTag( pValuePartialData, FS_FLTR_STD_TAG );
	}

	return numHideFiles;
}

/****************************************************************************/
/*  Function Name: FsFltrFastIoInitOrUninit                                 */
/*  Section: PAGED                                                          */
/*  Description: if initialize request, allocates buffer under              */
/*               fast I/O struct, initializes it and registers callbacks    */
/*               otherwise uninitializes fast I/O, frees buffer.            */
/*  Return: NT status                                                       */
/****************************************************************************/

NTSTATUS 
FsFltrFastIoInitOrUninit( 
	PDRIVER_OBJECT DriverObj, 
	ULONG IsInit )
{
	static PFAST_IO_DISPATCH FastIoDispatch = NULL;
	FS_FILTER_CALLBACKS FsFltrCallbacks;
	
	PAGED_CODE(  );

	if( !IsInit )
	{
		DriverObj->FastIoDispatch = NULL;
		ExFreePoolWithTag( FastIoDispatch, FS_FLTR_FAST_IO_TAG );
		return STATUS_SUCCESS;
	}

	FastIoDispatch = (PFAST_IO_DISPATCH)
		ExAllocatePoolWithTag( NonPagedPool, sizeof( FAST_IO_DISPATCH ), FS_FLTR_FAST_IO_TAG );

	if( !FastIoDispatch )
		return STATUS_INSUFFICIENT_RESOURCES;

	RtlZeroMemory( FastIoDispatch, sizeof( FAST_IO_DISPATCH ) );

	FastIoDispatch->SizeOfFastIoDispatch = sizeof( FAST_IO_DISPATCH );
	FastIoDispatch->FastIoCheckIfPossible = FsFltrFastIoCheckIfPossible;
	FastIoDispatch->FastIoRead = FsFltrFastIoRead;
	FastIoDispatch->FastIoWrite = FsFltrFastIoWrite;
	FastIoDispatch->FastIoQueryBasicInfo = FsFltrFastIoQueryBasicInfo;
	FastIoDispatch->FastIoQueryStandardInfo = FsFltrFastIoQueryStandardInfo;
	FastIoDispatch->FastIoLock = FsFltrFastIoLock;
	FastIoDispatch->FastIoUnlockSingle = FsFltrFastIoUnlockSingle;
	FastIoDispatch->FastIoUnlockAll = FsFltrFastIoUnlockAll;
	FastIoDispatch->FastIoUnlockAllByKey = FsFltrFastIoUnlockAllByKey;
	FastIoDispatch->FastIoDeviceControl = FsFltrFastIoDeviceControl;
	FastIoDispatch->FastIoDetachDevice = FsFltrFastIoDetachDevice;
	FastIoDispatch->FastIoQueryNetworkOpenInfo = FsFltrFastIoQueryNetworkOpenInfo;
	FastIoDispatch->MdlRead = FsFltrFastIoMdlRead;
	FastIoDispatch->MdlReadComplete = FsFltrFastIoMdlReadComplete;
	FastIoDispatch->PrepareMdlWrite = FsFltrFastIoPrepareMdlWrite;
	FastIoDispatch->MdlWriteComplete = FsFltrFastIoMdlWriteComplete;
	FastIoDispatch->FastIoReadCompressed = FsFltrFastIoReadCompressed;
	FastIoDispatch->FastIoWriteCompressed = FsFltrFastIoWriteCompressed;
	FastIoDispatch->MdlReadCompleteCompressed = FsFltrFastIoMdlReadCompleteCompressed;
	FastIoDispatch->MdlWriteCompleteCompressed = FsFltrFastIoMdlWriteCompleteCompressed;
	FastIoDispatch->FastIoQueryOpen = FsFltrFastIoQueryOpen;

	DriverObj->FastIoDispatch = FastIoDispatch;

	FsFltrCallbacks.SizeOfFsFilterCallbacks = sizeof( FS_FILTER_CALLBACKS );
	FsFltrCallbacks.PreAcquireForSectionSynchronization =
		FsFltrPreFsFltrPassThrough;
	FsFltrCallbacks.PostAcquireForSectionSynchronization =
		FsFltrPostFsFltrPassThrough;
	FsFltrCallbacks.PreReleaseForSectionSynchronization =
		FsFltrPreFsFltrPassThrough;
	FsFltrCallbacks.PostReleaseForSectionSynchronization =
		FsFltrPostFsFltrPassThrough;
	FsFltrCallbacks.PreAcquireForCcFlush = FsFltrPreFsFltrPassThrough;
	FsFltrCallbacks.PostAcquireForCcFlush = FsFltrPostFsFltrPassThrough;
	FsFltrCallbacks.PreReleaseForCcFlush = FsFltrPreFsFltrPassThrough;
	FsFltrCallbacks.PostReleaseForCcFlush = FsFltrPostFsFltrPassThrough;
	FsFltrCallbacks.PreAcquireForModifiedPageWriter = FsFltrPreFsFltrPassThrough;
	FsFltrCallbacks.PostAcquireForModifiedPageWriter = FsFltrPostFsFltrPassThrough;
	FsFltrCallbacks.PreReleaseForModifiedPageWriter = FsFltrPreFsFltrPassThrough;
	FsFltrCallbacks.PostReleaseForModifiedPageWriter = FsFltrPostFsFltrPassThrough;

	FsRtlRegisterFileSystemFilterCallbacks( DriverObj, &FsFltrCallbacks );

	return STATUS_SUCCESS;
}

/****************************************************************************/
/*  Function Name: FsFltrDispatchIoRequest                                  */
/*  Section: PAGED                                                          */
/*  Description: skip IRP to next lower driver                              */
/*  Return: NT status                                                       */
/****************************************************************************/

NTSTATUS
FsFltrDispatchIoRequest(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	)
{
	PDEVICE_EXTENSION pdx = NULL;

	PAGED_CODE(  );
	ASSERT( IS_MY_DEV_OBJ( DeviceObject ) );
	
	pdx = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

	IoSkipCurrentIrpStackLocation( Irp );
	return IoCallDriver( pdx->NextDevInChain, Irp );
}

/****************************************************************************/
/*  Function Name: FsFltrUnload                                             */
/*  Section: PAGED                                                          */
/*  Description: not implemented                                            */
/*  Return: VOID                                                            */
/****************************************************************************/

VOID 
FsFltrUnload( 
	IN PDRIVER_OBJECT DriverObject 
	)
{
	UNREFERENCED_PARAMETER( DriverObject );
}

/****************************************************************************/
/*  Function Name: FsFltrFastIoCheckIfPossible                              */
/*  Section: PAGED                                                          */
/*  Description: skip request to next lower driver                          */
/*  Return: TRUE - fast I/O operation was completed, FALSE - otherwise      */
/****************************************************************************/

BOOLEAN 
FsFltrFastIoCheckIfPossible( 
	IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN BOOLEAN Wait,
    IN ULONG LockKey,
    IN BOOLEAN CheckForReadOperation,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	PDEVICE_OBJECT NextDevInChain;
	PFAST_IO_DISPATCH FastIoDispatch;

	PAGED_CODE(  );
	
	ASSERT( IS_MY_DEV_OBJ( DeviceObject ) );

	NextDevInChain = ((PDEVICE_EXTENSION)DeviceObject->DeviceExtension)->NextDevInChain;

	ASSERT( NextDevInChain );

	FastIoDispatch = NextDevInChain->DriverObject->FastIoDispatch;

	if( VALID_FAST_IO_DISPATCH_HANDLER( FastIoDispatch, FastIoCheckIfPossible ) )
	{
		return (FastIoDispatch->FastIoCheckIfPossible)( 
			FileObject,
			FileOffset,
			Length,
			Wait,
			LockKey,
			CheckForReadOperation,
			IoStatus,
			NextDevInChain );
	}
	
	return FALSE;
}

/****************************************************************************/
/*  Function Name: FsFltrFastIoRead                                         */
/*  Section: PAGED                                                          */
/*  Description: skip request to next lower driver                          */
/*  Return: TRUE - fast I/O operation was completed, FALSE - otherwise      */
/****************************************************************************/

BOOLEAN
FsFltrFastIoRead (
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN BOOLEAN Wait,
    IN ULONG LockKey,
    OUT PVOID Buffer,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	PDEVICE_OBJECT NextDevInChain;
	PFAST_IO_DISPATCH FastIoDispatch;

	PAGED_CODE(  );
	
	ASSERT( IS_MY_DEV_OBJ( DeviceObject ) );

	NextDevInChain = ((PDEVICE_EXTENSION)DeviceObject->DeviceExtension)->NextDevInChain;

	ASSERT( NextDevInChain );

	FastIoDispatch = NextDevInChain->DriverObject->FastIoDispatch;

	if( VALID_FAST_IO_DISPATCH_HANDLER( FastIoDispatch, FastIoRead ) )
	{
		return (FastIoDispatch->FastIoRead)( 
			FileObject,
			FileOffset,
			Length,
			Wait,
			LockKey,
			Buffer,
			IoStatus,
			NextDevInChain );
	}
	
	return FALSE;
}

/****************************************************************************/
/*  Function Name: FsFltrFastIoWrite                                        */
/*  Section: PAGED                                                          */
/*  Description: skip request to next lower driver                          */
/*  Return: TRUE - fast I/O operation was completed, FALSE - otherwise      */
/****************************************************************************/

BOOLEAN
FsFltrFastIoWrite (
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN BOOLEAN Wait,
    IN ULONG LockKey,
    IN PVOID Buffer,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	PDEVICE_OBJECT NextDevInChain;
	PFAST_IO_DISPATCH FastIoDispatch;

	PAGED_CODE(  );
	
	ASSERT( IS_MY_DEV_OBJ( DeviceObject ) );

	NextDevInChain = ((PDEVICE_EXTENSION)DeviceObject->DeviceExtension)->NextDevInChain;

	ASSERT( NextDevInChain );

	FastIoDispatch = NextDevInChain->DriverObject->FastIoDispatch;

	if( VALID_FAST_IO_DISPATCH_HANDLER( FastIoDispatch, FastIoWrite ) )
	{
		return (FastIoDispatch->FastIoWrite)( 
			FileObject,
			FileOffset,
			Length,
			Wait,
			LockKey,
			Buffer,
			IoStatus,
			NextDevInChain );
	}
	
	return FALSE;
}

/****************************************************************************/
/*  Function Name: FsFltrFastIoQueryBasicInfo                               */
/*  Section: PAGED                                                          */
/*  Description: skip request to next lower driver                          */
/*  Return: TRUE - fast I/O operation was completed, FALSE - otherwise      */
/****************************************************************************/

BOOLEAN
FsFltrFastIoQueryBasicInfo (
    IN PFILE_OBJECT FileObject,
    IN BOOLEAN Wait,
    OUT PFILE_BASIC_INFORMATION Buffer,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	PDEVICE_OBJECT NextDevInChain;
	PFAST_IO_DISPATCH FastIoDispatch;

	PAGED_CODE(  );
	
	ASSERT( IS_MY_DEV_OBJ( DeviceObject ) );

	NextDevInChain = ((PDEVICE_EXTENSION)DeviceObject->DeviceExtension)->NextDevInChain;

	ASSERT( NextDevInChain );

	FastIoDispatch = NextDevInChain->DriverObject->FastIoDispatch;

	if( VALID_FAST_IO_DISPATCH_HANDLER( FastIoDispatch, FastIoQueryBasicInfo ) )
	{
		return (FastIoDispatch->FastIoQueryBasicInfo)( 
			FileObject,
			Wait,
			Buffer,
			IoStatus,
			NextDevInChain );
	}
	
	return FALSE;
}

/****************************************************************************/
/*  Function Name: FsFltrFastIoQueryStandardInfo                            */
/*  Section: PAGED                                                          */
/*  Description: skip request to next lower driver                          */
/*  Return: TRUE - fast I/O operation was completed, FALSE - otherwise      */
/****************************************************************************/

BOOLEAN
FsFltrFastIoQueryStandardInfo (
    IN PFILE_OBJECT FileObject,
    IN BOOLEAN Wait,
    OUT PFILE_STANDARD_INFORMATION Buffer,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	PDEVICE_OBJECT NextDevInChain;
	PFAST_IO_DISPATCH FastIoDispatch;

	PAGED_CODE(  );
	
	ASSERT( IS_MY_DEV_OBJ( DeviceObject ) );

	NextDevInChain = ((PDEVICE_EXTENSION)DeviceObject->DeviceExtension)->NextDevInChain;

	ASSERT( NextDevInChain );

	FastIoDispatch = NextDevInChain->DriverObject->FastIoDispatch;

	if( VALID_FAST_IO_DISPATCH_HANDLER( FastIoDispatch, FastIoQueryStandardInfo ) )
	{
		return (FastIoDispatch->FastIoQueryStandardInfo)( 
			FileObject,
			Wait,
			Buffer,
			IoStatus,
			NextDevInChain );
	}
	
	return FALSE;
}

/****************************************************************************/
/*  Function Name: FsFltrFastIoLock                                         */
/*  Section: PAGED                                                          */
/*  Description: skip request to next lower driver                          */
/*  Return: TRUE - fast I/O operation was completed, FALSE - otherwise      */
/****************************************************************************/

BOOLEAN
FsFltrFastIoLock (
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN PLARGE_INTEGER Length,
    IN PEPROCESS ProcessId,
    IN ULONG Key,
    IN BOOLEAN FailImmediately,
    IN BOOLEAN ExclusiveLock,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	PDEVICE_OBJECT NextDevInChain;
	PFAST_IO_DISPATCH FastIoDispatch;

	PAGED_CODE(  );
	
	ASSERT( IS_MY_DEV_OBJ( DeviceObject ) );

	NextDevInChain = ((PDEVICE_EXTENSION)DeviceObject->DeviceExtension)->NextDevInChain;

	ASSERT( NextDevInChain );

	FastIoDispatch = NextDevInChain->DriverObject->FastIoDispatch;

	if( VALID_FAST_IO_DISPATCH_HANDLER( FastIoDispatch, FastIoLock ) )
	{
		return (FastIoDispatch->FastIoLock)( 
			FileObject,
			FileOffset,
			Length,
			ProcessId,
			Key,
			FailImmediately,
			ExclusiveLock,
			IoStatus,
			NextDevInChain );
	}
	
	return FALSE;
}

/****************************************************************************/
/*  Function Name: FsFltrFastIoUnlockSingle                                 */
/*  Section: PAGED                                                          */
/*  Description: skip request to next lower driver                          */
/*  Return: TRUE - fast I/O operation was completed, FALSE - otherwise      */
/****************************************************************************/

BOOLEAN
FsFltrFastIoUnlockSingle (
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN PLARGE_INTEGER Length,
    IN PEPROCESS ProcessId,
    IN ULONG Key,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	PDEVICE_OBJECT NextDevInChain;
	PFAST_IO_DISPATCH FastIoDispatch;

	PAGED_CODE(  );
	
	ASSERT( IS_MY_DEV_OBJ( DeviceObject ) );

	NextDevInChain = ((PDEVICE_EXTENSION)DeviceObject->DeviceExtension)->NextDevInChain;

	ASSERT( NextDevInChain );

	FastIoDispatch = NextDevInChain->DriverObject->FastIoDispatch;

	if( VALID_FAST_IO_DISPATCH_HANDLER( FastIoDispatch, FastIoUnlockSingle ) )
	{
		return (FastIoDispatch->FastIoUnlockSingle)( 
			FileObject,
			FileOffset,
			Length,
			ProcessId,
			Key,
			IoStatus,
			NextDevInChain );
	}
	
	return FALSE;
}

/****************************************************************************/
/*  Function Name: FsFltrFastIoUnlockAll                                    */
/*  Section: PAGED                                                          */
/*  Description: skip request to next lower driver                          */
/*  Return: TRUE - fast I/O operation was completed, FALSE - otherwise      */
/****************************************************************************/

BOOLEAN
FsFltrFastIoUnlockAll (
    IN PFILE_OBJECT FileObject,
    IN PEPROCESS ProcessId,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	PDEVICE_OBJECT NextDevInChain;
	PFAST_IO_DISPATCH FastIoDispatch;

	PAGED_CODE(  );
	
	ASSERT( IS_MY_DEV_OBJ( DeviceObject ) );

	NextDevInChain = ((PDEVICE_EXTENSION)DeviceObject->DeviceExtension)->NextDevInChain;

	ASSERT( NextDevInChain );

	FastIoDispatch = NextDevInChain->DriverObject->FastIoDispatch;

	if( VALID_FAST_IO_DISPATCH_HANDLER( FastIoDispatch, FastIoUnlockAll ) )
	{
		return (FastIoDispatch->FastIoUnlockAll)( 
			FileObject,
			ProcessId,
			IoStatus,
			NextDevInChain );
	}
	
	return FALSE;
}

/****************************************************************************/
/*  Function Name: FsFltrFastIoUnlockAllByKey                               */
/*  Section: PAGED                                                          */
/*  Description: skip request to next lower driver                          */
/*  Return: TRUE - fast I/O operation was completed, FALSE - otherwise      */
/****************************************************************************/

BOOLEAN
FsFltrFastIoUnlockAllByKey (
    IN PFILE_OBJECT FileObject,
    IN PVOID ProcessId,
    IN ULONG Key,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	PDEVICE_OBJECT NextDevInChain;
	PFAST_IO_DISPATCH FastIoDispatch;

	PAGED_CODE(  );
	
	ASSERT( IS_MY_DEV_OBJ( DeviceObject ) );

	NextDevInChain = ((PDEVICE_EXTENSION)DeviceObject->DeviceExtension)->NextDevInChain;

	ASSERT( NextDevInChain );

	FastIoDispatch = NextDevInChain->DriverObject->FastIoDispatch;

	if( VALID_FAST_IO_DISPATCH_HANDLER( FastIoDispatch, FastIoUnlockAllByKey ) )
	{
		return (FastIoDispatch->FastIoUnlockAllByKey)( 
			FileObject,
			ProcessId,
			Key,
			IoStatus,
			NextDevInChain );
	}
	
	return FALSE;
}

/****************************************************************************/
/*  Function Name: FsFltrFastIoDeviceControl                                */
/*  Section: PAGED                                                          */
/*  Description: skip request to next lower driver                          */
/*  Return: TRUE - fast I/O operation was completed, FALSE - otherwise      */
/****************************************************************************/

BOOLEAN
FsFltrFastIoDeviceControl (
    IN PFILE_OBJECT FileObject,
    IN BOOLEAN Wait,
    IN PVOID InputBuffer,
    IN ULONG InputBufferLength,
    OUT PVOID OutputBuffer,
    IN ULONG OutputBufferLength,
    IN ULONG IoControlCode,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	PDEVICE_OBJECT NextDevInChain;
	PFAST_IO_DISPATCH FastIoDispatch;

	PAGED_CODE(  );
	
	ASSERT( IS_MY_DEV_OBJ( DeviceObject ) );

	if( IS_MY_CTRL_DEV_OBJ( DeviceObject ) )
		return FALSE;
	
	NextDevInChain = ((PDEVICE_EXTENSION)DeviceObject->DeviceExtension)->NextDevInChain;

	ASSERT( NextDevInChain );

	FastIoDispatch = NextDevInChain->DriverObject->FastIoDispatch;

	if( VALID_FAST_IO_DISPATCH_HANDLER( FastIoDispatch, FastIoDeviceControl ) )
	{
		return (FastIoDispatch->FastIoDeviceControl)( 
			FileObject,
			Wait,
			InputBuffer,
			InputBufferLength,
			OutputBuffer,
			OutputBufferLength,
			IoControlCode,
			IoStatus,
			NextDevInChain );
	}
	
	return FALSE;
}

/****************************************************************************/
/*  Function Name: FsFltrFastIoDetachDevice                                 */
/*  Section: PAGED                                                          */
/*  Description: detachs our device from target device                      */
/*  Return: VOID                                                            */
/****************************************************************************/

VOID
FsFltrFastIoDetachDevice (
    IN PDEVICE_OBJECT SourceDevice,
    IN PDEVICE_OBJECT TargetDevice
    )
{
	ULONG DriveIndex;

	PAGED_CODE(  );
	
	ASSERT( IS_MY_DEV_OBJ( SourceDevice ) );

	DriveIndex = CheckDeviceInHookDeviceBuffer( SourceDevice );
	ASSERT( DriveIndex != 0xFFFFFFFF );

	IoDetachDevice( TargetDevice );
	IoDeleteDevice( SourceDevice );

	ClearFlag( curDrivesToHookMask, 1 << DriveIndex );
	DriveHookDevicesTable[DriveIndex] = NULL;

	KdPrint( ( "fsfltr!FsFltrFastIoDetachDevice: Successfully detach from %c:\n", 'A' + DriveIndex ) );
}

/****************************************************************************/
/*  Function Name: FsFltrFastIoQueryNetworkOpenInfo                         */
/*  Section: PAGED                                                          */
/*  Description: skip request to next lower driver                          */
/*  Return: TRUE - fast I/O operation was completed, FALSE - otherwise      */
/****************************************************************************/

BOOLEAN
FsFltrFastIoQueryNetworkOpenInfo (
    IN PFILE_OBJECT FileObject,
    IN BOOLEAN Wait,
    OUT PFILE_NETWORK_OPEN_INFORMATION Buffer,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	PDEVICE_OBJECT NextDevInChain;
	PFAST_IO_DISPATCH FastIoDispatch;

	PAGED_CODE(  );
	
	ASSERT( IS_MY_DEV_OBJ( DeviceObject ) );

	NextDevInChain = ((PDEVICE_EXTENSION)DeviceObject->DeviceExtension)->NextDevInChain;

	ASSERT( NextDevInChain );

	FastIoDispatch = NextDevInChain->DriverObject->FastIoDispatch;

	if( VALID_FAST_IO_DISPATCH_HANDLER( FastIoDispatch, FastIoQueryNetworkOpenInfo ) )
	{
		return (FastIoDispatch->FastIoQueryNetworkOpenInfo)( 
			FileObject,
			Wait,
			Buffer,
			IoStatus,
			NextDevInChain );
	}
	
	return FALSE;
}

/****************************************************************************/
/*  Function Name: FsFltrFastIoMdlRead                                      */
/*  Section: PAGED                                                          */
/*  Description: skip request to next lower driver                          */
/*  Return: TRUE - fast I/O operation was completed, FALSE - otherwise      */
/****************************************************************************/

BOOLEAN
FsFltrFastIoMdlRead (
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN ULONG LockKey,
    OUT PMDL *MdlChain,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	PDEVICE_OBJECT NextDevInChain;
	PFAST_IO_DISPATCH FastIoDispatch;

	PAGED_CODE(  );
	
	ASSERT( IS_MY_DEV_OBJ( DeviceObject ) );

	NextDevInChain = ((PDEVICE_EXTENSION)DeviceObject->DeviceExtension)->NextDevInChain;

	ASSERT( NextDevInChain );

	FastIoDispatch = NextDevInChain->DriverObject->FastIoDispatch;

	if( VALID_FAST_IO_DISPATCH_HANDLER( FastIoDispatch, MdlRead ) )
	{
		return (FastIoDispatch->MdlRead)( 
			FileObject,
			FileOffset,
			Length,
			LockKey,
			MdlChain,
			IoStatus,
			NextDevInChain );
	}
	
	return FALSE;
}

/****************************************************************************/
/*  Function Name: FsFltrFastIoMdlReadComplete                              */
/*  Section: PAGED                                                          */
/*  Description: skip request to next lower driver                          */
/*  Return: TRUE - fast I/O operation was completed, FALSE - otherwise      */
/****************************************************************************/

BOOLEAN
FsFltrFastIoMdlReadComplete ( 
    IN PFILE_OBJECT FileObject,
    IN PMDL MdlChain,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	PDEVICE_OBJECT NextDevInChain;
	PFAST_IO_DISPATCH FastIoDispatch;

	PAGED_CODE(  );
	
	ASSERT( IS_MY_DEV_OBJ( DeviceObject ) );

	NextDevInChain = ((PDEVICE_EXTENSION)DeviceObject->DeviceExtension)->NextDevInChain;

	ASSERT( NextDevInChain );

	FastIoDispatch = NextDevInChain->DriverObject->FastIoDispatch;

	if( VALID_FAST_IO_DISPATCH_HANDLER( FastIoDispatch, MdlReadComplete ) )
	{
		return (FastIoDispatch->MdlReadComplete)( 
			FileObject,
			MdlChain,
			NextDevInChain );
	}
	
	return FALSE;
}

/****************************************************************************/
/*  Function Name: FsFltrFastIoPrepareMdlWrite                              */
/*  Section: PAGED                                                          */
/*  Description: skip request to next lower driver                          */
/*  Return: TRUE - fast I/O operation was completed, FALSE - otherwise      */
/****************************************************************************/

BOOLEAN
FsFltrFastIoPrepareMdlWrite (
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN ULONG LockKey,
    OUT PMDL *MdlChain,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	PDEVICE_OBJECT NextDevInChain;
	PFAST_IO_DISPATCH FastIoDispatch;

	PAGED_CODE(  );
	
	ASSERT( IS_MY_DEV_OBJ( DeviceObject ) );

	NextDevInChain = ((PDEVICE_EXTENSION)DeviceObject->DeviceExtension)->NextDevInChain;

	ASSERT( NextDevInChain );

	FastIoDispatch = NextDevInChain->DriverObject->FastIoDispatch;

	if( VALID_FAST_IO_DISPATCH_HANDLER( FastIoDispatch,  PrepareMdlWrite ) )
	{
		return (FastIoDispatch-> PrepareMdlWrite)( 
			FileObject,
			FileOffset,
			Length,
			LockKey,
			MdlChain,
			IoStatus,
			NextDevInChain );
	}
	
	return FALSE;
}

/****************************************************************************/
/*  Function Name: FsFltrFastIoMdlWriteComplete                             */
/*  Section: PAGED                                                          */
/*  Description: skip request to next lower driver                          */
/*  Return: TRUE - fast I/O operation was completed, FALSE - otherwise      */
/****************************************************************************/

BOOLEAN
FsFltrFastIoMdlWriteComplete (
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN PMDL MdlChain,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	PDEVICE_OBJECT NextDevInChain;
	PFAST_IO_DISPATCH FastIoDispatch;

	PAGED_CODE(  );
	
	ASSERT( IS_MY_DEV_OBJ( DeviceObject ) );

	NextDevInChain = ((PDEVICE_EXTENSION)DeviceObject->DeviceExtension)->NextDevInChain;

	ASSERT( NextDevInChain );

	FastIoDispatch = NextDevInChain->DriverObject->FastIoDispatch;

	if( VALID_FAST_IO_DISPATCH_HANDLER( FastIoDispatch,  MdlWriteComplete ) )
	{
		return ( FastIoDispatch-> MdlWriteComplete )( 
			FileObject,
			FileOffset,
			MdlChain,
			NextDevInChain );
	}
	
	return FALSE;
}

/****************************************************************************/
/*  Function Name: FsFltrFastIoReadCompressed                               */
/*  Section: PAGED                                                          */
/*  Description: skip request to next lower driver                          */
/*  Return: TRUE - fast I/O operation was completed, FALSE - otherwise      */
/****************************************************************************/

BOOLEAN
FsFltrFastIoReadCompressed (
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN ULONG LockKey,
    OUT PVOID Buffer,
    OUT PMDL *MdlChain,
    OUT PIO_STATUS_BLOCK IoStatus,
    OUT struct _COMPRESSED_DATA_INFO *CompressedDataInfo,
    IN ULONG CompressedDataInfoLength,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	PDEVICE_OBJECT NextDevInChain;
	PFAST_IO_DISPATCH FastIoDispatch;

	PAGED_CODE(  );
	
	ASSERT( IS_MY_DEV_OBJ( DeviceObject ) );

	NextDevInChain = ((PDEVICE_EXTENSION)DeviceObject->DeviceExtension)->NextDevInChain;

	ASSERT( NextDevInChain );

	FastIoDispatch = NextDevInChain->DriverObject->FastIoDispatch;

	if( VALID_FAST_IO_DISPATCH_HANDLER( FastIoDispatch,  FastIoReadCompressed ) )
	{
		return ( FastIoDispatch-> FastIoReadCompressed )( 
			FileObject,
			FileOffset,
			Length,
			LockKey,
			Buffer,
			MdlChain,
			IoStatus,
			CompressedDataInfo,
			CompressedDataInfoLength,
			NextDevInChain );
	}
	
	return FALSE;
}

/****************************************************************************/
/*  Function Name: FsFltrFastIoWriteCompressed                              */
/*  Section: PAGED                                                          */
/*  Description: skip request to next lower driver                          */
/*  Return: TRUE - fast I/O operation was completed, FALSE - otherwise      */
/****************************************************************************/

BOOLEAN
FsFltrFastIoWriteCompressed (
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN ULONG LockKey,
    IN PVOID Buffer,
    OUT PMDL *MdlChain,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN struct _COMPRESSED_DATA_INFO *CompressedDataInfo,
    IN ULONG CompressedDataInfoLength,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	PDEVICE_OBJECT NextDevInChain;
	PFAST_IO_DISPATCH FastIoDispatch;

	PAGED_CODE(  );
	
	ASSERT( IS_MY_DEV_OBJ( DeviceObject ) );

	NextDevInChain = ((PDEVICE_EXTENSION)DeviceObject->DeviceExtension)->NextDevInChain;

	ASSERT( NextDevInChain );

	FastIoDispatch = NextDevInChain->DriverObject->FastIoDispatch;

	if( VALID_FAST_IO_DISPATCH_HANDLER( FastIoDispatch,  FastIoWriteCompressed ) )
	{
		return ( FastIoDispatch->FastIoWriteCompressed )( 
			FileObject,
			FileOffset,
			Length,
			LockKey,
			Buffer,
			MdlChain,
			IoStatus,
			CompressedDataInfo,
			CompressedDataInfoLength,
			NextDevInChain );
	}
	
	return FALSE;
}

/****************************************************************************/
/*  Function Name: FsFltrFastIoMdlReadCompleteCompressed                    */
/*  Section: PAGED                                                          */
/*  Description: skip request to next lower driver                          */
/*  Return: TRUE - fast I/O operation was completed, FALSE - otherwise      */
/****************************************************************************/

BOOLEAN
FsFltrFastIoMdlReadCompleteCompressed (
    IN PFILE_OBJECT FileObject,
    IN PMDL MdlChain,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	PDEVICE_OBJECT NextDevInChain;
	PFAST_IO_DISPATCH FastIoDispatch;

	PAGED_CODE(  );
	
	ASSERT( IS_MY_DEV_OBJ( DeviceObject ) );

	NextDevInChain = ((PDEVICE_EXTENSION)DeviceObject->DeviceExtension)->NextDevInChain;

	ASSERT( NextDevInChain );

	FastIoDispatch = NextDevInChain->DriverObject->FastIoDispatch;

	if( VALID_FAST_IO_DISPATCH_HANDLER( FastIoDispatch,  MdlReadCompleteCompressed ) )
	{
		return ( FastIoDispatch->MdlReadCompleteCompressed )( 
			FileObject,
			MdlChain,
			NextDevInChain );
	}
	
	return FALSE;
}

/****************************************************************************/
/*  Function Name: FsFltrFastIoMdlWriteCompleteCompressed                   */
/*  Section: PAGED                                                          */
/*  Description: skip request to next lower driver                          */
/*  Return: TRUE - fast I/O operation was completed, FALSE - otherwise      */
/****************************************************************************/

BOOLEAN
FsFltrFastIoMdlWriteCompleteCompressed (
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN PMDL MdlChain,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	PDEVICE_OBJECT NextDevInChain;
	PFAST_IO_DISPATCH FastIoDispatch;

	PAGED_CODE(  );
	
	ASSERT( IS_MY_DEV_OBJ( DeviceObject ) );

	NextDevInChain = ((PDEVICE_EXTENSION)DeviceObject->DeviceExtension)->NextDevInChain;

	ASSERT( NextDevInChain );

	FastIoDispatch = NextDevInChain->DriverObject->FastIoDispatch;

	if( VALID_FAST_IO_DISPATCH_HANDLER( FastIoDispatch,  MdlWriteCompleteCompressed ) )
	{
		return ( FastIoDispatch->MdlWriteCompleteCompressed )( 
			FileObject,
			FileOffset,
			MdlChain,
			NextDevInChain );
	}
	
	return FALSE;
}

/****************************************************************************/
/*  Function Name: FsFltrFastIoQueryOpen                                    */
/*  Section: PAGED                                                          */
/*  Description: checks open files on hide and modifies I/O status if hide  */
/*  Return: TRUE - fast I/O operation was completed, FALSE - otherwise      */
/****************************************************************************/

BOOLEAN
FsFltrFastIoQueryOpen (
    IN PIRP Irp,
    OUT PFILE_NETWORK_OPEN_INFORMATION NetworkInformation,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	PDEVICE_OBJECT NextDevInChain;
	PFAST_IO_DISPATCH FastIoDispatch;
	BOOLEAN result;
			
	PAGED_CODE(  );
	
	ASSERT( IS_MY_DEV_OBJ( DeviceObject ) );

	NextDevInChain = ((PDEVICE_EXTENSION)DeviceObject->DeviceExtension)->NextDevInChain;

	ASSERT( NextDevInChain );

	FastIoDispatch = NextDevInChain->DriverObject->FastIoDispatch;
	
	if( VALID_FAST_IO_DISPATCH_HANDLER( FastIoDispatch,  FastIoQueryOpen ) )
	{
		PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation( Irp );
		
		IoStack->DeviceObject = NextDevInChain;

		result = ( FastIoDispatch->FastIoQueryOpen )( 
			Irp,
			NetworkInformation,
			NextDevInChain );

		IoStack->DeviceObject = DeviceObject;

		if( IoStack->FileObject && 
			IoStack->FileObject->FileName.Length &&
			IoStack->FileObject->FileName.Buffer &&
			result &&
			NT_SUCCESS( Irp->IoStatus.Status ) )
		{
			DrmDispatchOpenOrCreateFile( DeviceObject, Irp );
		}
		
		if( result &&
			NT_SUCCESS( Irp->IoStatus.Status ) )
		{
			AvxCheckFile( ( PDEVICE_EXTENSION )DeviceObject->DeviceExtension,
				Irp, TRUE );
		}

		return result;
	}
	
	return FALSE;
}

VOID 
DrmDispatchOpenOrCreateFile(
	 PDEVICE_OBJECT DeviceObject,
	 PIRP Irp
	 )
{
	PWSTR pwszFullPath = NULL;
	UNICODE_STRING unFullPath = { 0 };
	ANSI_STRING anFullPath = { 0 };
	NTSTATUS status = STATUS_SUCCESS;
	ULONG ChkSum = 0;
	ULONG Disposition = 0;
	PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation( Irp );
	PDEVICE_EXTENSION pdx = ( PDEVICE_EXTENSION )DeviceObject->DeviceExtension;

	ASSERT( DeviceObject );
	ASSERT( Irp );
	PAGED_CODE(  );
	
	if( !IoStack->FileObject || 
		!IoStack->FileObject->FileName.Buffer ||
		!IoStack->FileObject->FileName.Length )
			return;

	status = FsFltrCreateFullPath( IoStack->FileObject, 
		&pwszFullPath, pdx->VolLetter, pdx );

	if( !NT_SUCCESS( status ) )
		return;

	RtlInitUnicodeString( &unFullPath, pwszFullPath );

	status = RtlUnicodeStringToAnsiString( 
		&anFullPath, &unFullPath, TRUE ); 

	if( !NT_SUCCESS( status ) )
	{
		FsFltrFreeFullPath( pwszFullPath );
		return;
	}
	
	UpcaseAnsiString( &anFullPath );
	ChkSum = CreateChkSumForStr( &anFullPath );
	
	if( LookupHideFileInListOfHideFilesByChkSum( ChkSum ) )
	{//hide this file
		Disposition = IoStack->Parameters.Create.Options >> 24;

		switch( Disposition )
		{
			case FILE_OVERWRITE_IF:
			case FILE_OPEN_IF:
			case FILE_SUPERSEDE:
			case FILE_CREATE:
				Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
				Irp->IoStatus.Information = 0;
			break;
			case FILE_OVERWRITE:
			case FILE_OPEN:
				Irp->IoStatus.Status = STATUS_OBJECT_NAME_NOT_FOUND;
				Irp->IoStatus.Information = 0;
			default:
			break;
		}
	}

	RtlFreeAnsiString( &anFullPath );
	FsFltrFreeFullPath( pwszFullPath );

	return;
}

/****************************************************************************/
/*  Function Name: FsFltrPreFsFltrPassThrough                               */
/*  Section: RESIDENT                                                       */
/*  Description: for compatibility only                                     */
/*  Return: STATUS_SUCCESS                                                  */
/****************************************************************************/

NTSTATUS
FsFltrPreFsFltrPassThrough (
    IN PFS_FILTER_CALLBACK_DATA Data,
    OUT PVOID *CompletionContext
    )
{
	UNREFERENCED_PARAMETER( Data );
	UNREFERENCED_PARAMETER( CompletionContext );

	ASSERT( IS_MY_DEV_OBJ( Data->DeviceObject ) );

	return STATUS_SUCCESS;
}

/****************************************************************************/
/*  Function Name: FsFltrPreFsFltrPassThrough                               */
/*  Section: RESIDENT                                                       */
/*  Description: for compatibility only                                     */
/*  Return: VOID                                                            */
/****************************************************************************/

VOID
FsFltrPostFsFltrPassThrough (
    IN PFS_FILTER_CALLBACK_DATA Data,
    IN NTSTATUS OperationStatus,
    IN PVOID CompletionContext
    )
{
	UNREFERENCED_PARAMETER( Data );
	UNREFERENCED_PARAMETER( OperationStatus );
	UNREFERENCED_PARAMETER( CompletionContext );

	ASSERT( IS_MY_DEV_OBJ( Data->DeviceObject ) );
}

/****************************************************************************/
/*  Function Name: FsFltrFastIoQueryOpen                                    */
/*  Section: INIT                                                           */
/*  Description: set global drive masks: maxDrivesToHookMask - all existing */
/*               drives, curDrivesToHookMask - drives, that support filter  */
/*               driver                                                     */
/*  Return: NT status                                                       */
/****************************************************************************/

NTSTATUS GetDrivesToHook(  )
{
	PROCESS_DEVICEMAP_INFORMATION ProcDevMapInfo;
	NTSTATUS status;

	status = ZwQueryInformationProcess(
		(HANDLE)0xFFFFFFFF,
		ProcessDeviceMap,
		&ProcDevMapInfo,
		sizeof( ProcDevMapInfo ),
		NULL );

	if( !NT_SUCCESS( status ) )
		return status;

	maxDrivesToHookMask = ProcDevMapInfo.Query.DriveMap;
	curDrivesToHookMask = maxDrivesToHookMask;

	for( register ULONG drive = 0; drive < 32; drive++ )
	{
		if( FlagOn( maxDrivesToHookMask, 1 << drive ) )
		{
			switch( ProcDevMapInfo.Query.DriveType[drive] )
			{
				case DRIVE_UNKNOWN:
				case DRIVE_NO_ROOT_DIR:
				//case DRIVE_REMOVABLE:
				case DRIVE_REMOTE:
				//case DRIVE_CDROM:
				case DRIVE_RAMDISK:
					ClearFlag( curDrivesToHookMask, 1 << drive );
				default:
				break;
			}
		}
	}

	return STATUS_SUCCESS;
}

/****************************************************************************/
/*  Function Name: FsFltrAttachDeviceToDeviceStackByDevIndex                */
/*  Section: INIT                                                           */
/*  Description: function is called on initialization step, by DeviceIndex  */
/*               function forms symbolic link and receives ptr to device,   */
/*               if device is mounted, creates new device and attaches it to*/
/*               target device, else returns STATUS_UNSUCCESSFUL            */
/*  Return: NT status                                                       */
/****************************************************************************/

NTSTATUS FsFltrAttachDeviceToDeviceStackByDevIndex( UCHAR DeviceIndex )
{
	WCHAR wszDrivePath[] = L"\\??\\A:";
	UNICODE_STRING unDriveName = { 0 };
	NTSTATUS status = STATUS_SUCCESS;
	IO_STATUS_BLOCK iosb = { 0 };
	PFILE_OBJECT FileObj = NULL;
	PDEVICE_OBJECT TargetFsDev = NULL;
	PDEVICE_OBJECT SourceDevice = NULL;
	PDEVICE_EXTENSION pdx = NULL;
	PDEVICE_OBJECT TargetDevice;
	//PDEVOBJ_EXTENSION_UNDOC DevObjExt = NULL;
	//PDEVICE_OBJECT QueryDev = NULL;

	ASSERT( FsFltrDriverObject );

	wszDrivePath[4] += DeviceIndex;

	RtlInitUnicodeString( &unDriveName, wszDrivePath );
	
	status = 
		IoGetDeviceObjectPointer( &unDriveName, FILE_READ_ATTRIBUTES, &FileObj, &TargetDevice );

	ASSERT( NT_SUCCESS( status ) );

	/*//walk by chain 
		
	for( DevObjExt = (PDEVOBJ_EXTENSION_UNDOC)
		 TargetDevice->DeviceObjectExtension,
		 QueryDev = TargetDevice; 
	
		 DevObjExt->AttachedTo;

		 DevObjExt = (PDEVOBJ_EXTENSION_UNDOC)
		 QueryDev->DeviceObjectExtension	) 
		 {
			 QueryDev = DevObjExt->AttachedTo;
		 }

	 TargetDevice = QueryDev;*/

	//check on mount
	if( FileObj->DeviceObject->Vpb &&
		FileObj->DeviceObject->Vpb->DeviceObject )
	{//was mounted
		TargetFsDev = FileObj->DeviceObject->Vpb->DeviceObject;
	}
	else
	{
		ObDereferenceObject( FileObj );
		return STATUS_UNSUCCESSFUL; 
	}
	
	status = IoCreateDevice(
		FsFltrDriverObject,
		sizeof( DEVICE_EXTENSION ),
		NULL,
		TargetFsDev->DeviceType,
		TargetFsDev->Characteristics,
		FALSE,
		&SourceDevice );

	if( !NT_SUCCESS( status ) )
	{
		ObDereferenceObject( FileObj );
		KdPrint( ( "FsFltr!FsFltrAttachDeviceToDeviceStackByDevIndex: Failed create device for attach to stack, status = %08x\n",
			status ) );
		return STATUS_UNSUCCESSFUL;
	}

	SourceDevice->Flags |= TargetFsDev->Flags & ( DO_BUFFERED_IO | DO_DIRECT_IO );
	ClearFlag( SourceDevice->Flags, DO_DEVICE_INITIALIZING ); 
	
	pdx = ( PDEVICE_EXTENSION )SourceDevice->DeviceExtension;
	pdx->VolLetter = 'A' + DeviceIndex;

	TargetFsDev = IoAttachDeviceToDeviceStack( SourceDevice, TargetFsDev );
	pdx->NextDevInChain = TargetFsDev;

	ASSERT( DriveHookDevicesTable[DeviceIndex] == NULL );
	DriveHookDevicesTable[DeviceIndex] = SourceDevice;

	ObDereferenceObject( FileObj );

	KdPrint( ( "FsFltr!FsFltrAttachDeviceToDeviceStackByDevIndex: Successfully attach to volume %c:\n",
		'A' + DeviceIndex ) );

	return STATUS_SUCCESS;
}

/****************************************************************************/
/*  Function Name: FsFltrUnhookDrive                                        */
/*  Section: PAGED                                                          */
/*  Description: not implemented                                            */
/*  Return: VOID                                                            */
/****************************************************************************/

VOID 
FsFltrUnhookDrive( 
	UCHAR DeviceIndex 
	)
{
	DriveHookDevicesTable[DeviceIndex] = NULL;
}

/****************************************************************************/
/*  Function Name: FsFltrHookOrUnhookDrives                                 */
/*  Section: PAGED                                                          */
/*  Description: by checking mask curDrivesToHookMask, attach to fs stack   */
/*  Return: VOID                                                            */
/****************************************************************************/

ULONG 
FsFltrHookOrUnhookDrives( 
	ULONG IsHook 
	)
{
	ULONG DriveBit;
	ULONG HookDrivesCount = 0;

	for( register ULONG drive = 0; drive < MAX_DRIVES_FOR_HOOK; drive++ )
	{
		DriveBit = 1 << drive;

		if( ( FlagOn( curDrivesToHookMask, DriveBit ) && IsHook ) )
		{
			if( FsFltrAttachDeviceToDeviceStackByDevIndex( (UCHAR)drive ) 
				!= STATUS_SUCCESS )
				ClearFlag( curDrivesToHookMask, DriveBit );
			else
				HookDrivesCount++;
		}
		else if ( ( FlagOn( curDrivesToHookMask, DriveBit ) && !IsHook ) )
		{
			FsFltrUnhookDrive( (UCHAR)drive );		
		}
	}

	return HookDrivesCount;
}

/****************************************************************************/
/*  Function Name: FsFltrDispatchDirectoryControlRequest                    */
/*  Section: PAGED                                                          */
/*  Description: sets completion routine for additional dispatch            */
/*  Return: VOID                                                            */
/****************************************************************************/

NTSTATUS 
FsFltrDispatchDirectoryControlRequest( 
	IN PDEVICE_OBJECT DeviceObject, 
	IN PIRP Irp 
	) 
{
	PDEVICE_EXTENSION pdx;
	NTSTATUS status;
	PIO_STACK_LOCATION IoStack;
	ULONG Status;
	
	PAGED_CODE(  );
	ASSERT( IS_MY_DEV_OBJ( DeviceObject ) );
	
	pdx = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

	IoStack = IoGetCurrentIrpStackLocation( Irp );

	IoCopyCurrentIrpStackLocationToNext( Irp );

	IoSetCompletionRoutine( Irp, 
		FsFltrCompletionForDirControl,
		&Status,
		TRUE,
		TRUE,
		FALSE );
	
	status = IoCallDriver( pdx->NextDevInChain, Irp );

	if( status == STATUS_PENDING )
		return status;

	if( NT_SUCCESS( status ) && status != Status )
	{
		return Status;
	}
	else 
		return status;
	
	ASSERT( 0 );
}

/****************************************************************************/
/*  Function Name: FsFltrCompletionForDirControl                            */
/*  Section: RESIDENT                                                       */
/*  Description: checks Irp->UserBuffer on hide files                       */
/*  Return: NT status                                                       */
/****************************************************************************/

NTSTATUS
FsFltrCompletionForDirControl(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp,
	PVOID Context
	)
{
	PIO_STACK_LOCATION IoStack = NULL;
	PFILE_BOTH_DIR_INFORMATION volatile QueryBuffer = NULL;
	PFILE_BOTH_DIR_INFORMATION volatile PrevBuffer = NULL;
	PDEVICE_EXTENSION pdx = NULL;
	ULONG delta = 0;
	ULONG block_length = 0;
	ULONG cbNewBlock = 0;
	PFILE_BOTH_DIR_INFORMATION source_block = NULL;
	PFILE_BOTH_DIR_INFORMATION new_block = NULL;

	ASSERT( IS_MY_DEV_OBJ( DeviceObject ) );
	UNREFERENCED_PARAMETER( Context );

	IoStack = IoGetCurrentIrpStackLocation( Irp );
	ASSERT( IoStack->MajorFunction == IRP_MJ_DIRECTORY_CONTROL );
	
	pdx = ( PDEVICE_EXTENSION )DeviceObject->DeviceExtension;

	if( Irp->PendingReturned )
		IoMarkIrpPending( Irp );

	if( IoStack->MinorFunction == IRP_MN_QUERY_DIRECTORY &&
		IoStack->Parameters.QueryDirectory.FileInformationClass == FileBothDirectoryInformation &&
		KeGetCurrentIrql(  ) < DISPATCH_LEVEL &&
		Irp->IoStatus.Information != 0 &&
		NT_SUCCESS( Irp->IoStatus.Status ) &&
		CheckPidForTrusted( PsGetCurrentProcessId(  ) ) == FALSE )
	{
		PrevBuffer = (PFILE_BOTH_DIR_INFORMATION) Irp->UserBuffer;

		for( PrevBuffer = (PFILE_BOTH_DIR_INFORMATION) Irp->UserBuffer,
			 QueryBuffer = (PFILE_BOTH_DIR_INFORMATION)Irp->UserBuffer
			 ; ; )
		{
#ifdef DBG
			BOOLEAN b = MmIsAddressValid( QueryBuffer );
			if( !b ) DbgBreakPoint(  );
#endif
			if( ( IoStack->Flags & SL_RETURN_SINGLE_ENTRY ) ||
				( QueryBuffer->NextEntryOffset == 0 ) )
			{//no next entry after this
				if( CheckFileOnHide( IoStack->FileObject, QueryBuffer, pdx->VolLetter ) )
				{
					KdPrint(( "fsfltr!FsFltrCompletionForDirControl: hide for last!\n" ));
					if( IoStack->Flags & SL_RETURN_SINGLE_ENTRY )
					{//requested one entry
						if( IoStack->Parameters.QueryDirectory.FileName &&
							IoStack->Parameters.QueryDirectory.FileName->Buffer )
						{
							if( QueryBuffer->FileName[0] == 
								IoStack->Parameters.QueryDirectory.FileName->Buffer[0] )
							{
								Irp->IoStatus.Status = STATUS_NO_SUCH_FILE;
							}
							else
							{
								Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
							}
						}
						else
						{
							Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
						}
					
						RtlZeroMemory( QueryBuffer, Irp->IoStatus.Information );
						Irp->IoStatus.Information = 0;
					}
					else 
					{//hide elem last in buffer
						delta = (PUCHAR)QueryBuffer - (PUCHAR)Irp->UserBuffer,
						block_length = Irp->IoStatus.Information - delta;
						
						RtlZeroMemory( QueryBuffer, block_length ); 
						Irp->IoStatus.Information -= block_length;

						PrevBuffer->NextEntryOffset = 0;
					}
				}
				break;
			}
			else
			{//more one entry in buffer
				if( CheckFileOnHide( IoStack->FileObject, QueryBuffer, pdx->VolLetter ) )
				{
					KdPrint(( "fsfltr!FsFltrCompletionForDirControl: hide!\n" ));
					cbNewBlock = 
							Irp->IoStatus.Information - QueryBuffer->NextEntryOffset;
					
					new_block = (PFILE_BOTH_DIR_INFORMATION)
							ExAllocatePoolWithTag( NonPagedPool, 
							cbNewBlock,
							FS_FLTR_STD_TAG );

					if( !new_block )
					{
						PrevBuffer = QueryBuffer;
						QueryBuffer = ( PFILE_BOTH_DIR_INFORMATION )
							( ( PUCHAR )QueryBuffer + QueryBuffer->NextEntryOffset );
						continue;
					}
					RtlZeroMemory( new_block, cbNewBlock );

					if( QueryBuffer == (PFILE_BOTH_DIR_INFORMATION)Irp->UserBuffer ) 
					{//hide elem first in buffer
						source_block = 
							( PFILE_BOTH_DIR_INFORMATION )( (PUCHAR)QueryBuffer + QueryBuffer->NextEntryOffset );
						
						RtlCopyMemory( new_block, source_block, cbNewBlock );
					}
					else 
					{//hide elem middle in buffer
						ULONG cbOnePart = 0;
						PFILE_BOTH_DIR_INFORMATION new_middle_buffer = NULL;

						cbOnePart = (PUCHAR)QueryBuffer - (PUCHAR)Irp->UserBuffer;

						RtlCopyMemory( new_block, Irp->UserBuffer, cbOnePart );
						new_middle_buffer = (PFILE_BOTH_DIR_INFORMATION)( (PUCHAR)new_block + cbOnePart );

						cbOnePart = cbNewBlock - cbOnePart;
						
						source_block = 
							( PFILE_BOTH_DIR_INFORMATION )( (PUCHAR)QueryBuffer + QueryBuffer->NextEntryOffset );

						RtlCopyMemory( new_middle_buffer, source_block, cbOnePart );
					}

					RtlZeroMemory( Irp->UserBuffer, Irp->IoStatus.Information );
					RtlCopyMemory( Irp->UserBuffer, new_block, cbNewBlock );

					ExFreePoolWithTag( new_block, FS_FLTR_STD_TAG );
					Irp->IoStatus.Information = cbNewBlock;

					QueryBuffer = PrevBuffer;
					continue;
				}
			}
			PrevBuffer = QueryBuffer;
			QueryBuffer = ( PFILE_BOTH_DIR_INFORMATION )
							( ( PUCHAR )QueryBuffer + QueryBuffer->NextEntryOffset );
		}
		if( Irp->IoStatus.Information == 0 && !( IoStack->Flags & SL_RETURN_SINGLE_ENTRY ) )
		{
			Irp->IoStatus.Status = STATUS_NO_MORE_FILES;
		}
	}

	if( !Irp->PendingReturned )
		*((NTSTATUS*)Context) = Irp->IoStatus.Status;
	
	return Irp->IoStatus.Status;
}

BOOLEAN
CheckPidForTrusted(
	HANDLE Pid
   )
{
	PDEVICE_EXTENSION_CDO pdx_cdo = ( PDEVICE_EXTENSION_CDO )
		FsFltrCDO->DeviceExtension;
	BOOLEAN IsTrusted = FALSE;
	PLIST_ENTRY QueryEntry;

	PAGED_CODE(  );
	ASSERT( Pid );

	ExAcquireFastMutex( &pdx_cdo->MutexGuardListOfTrustedProc );

	for( QueryEntry = pdx_cdo->ListOfTrustedProcesses.Flink;
		 QueryEntry != &pdx_cdo->ListOfTrustedProcesses; 
		 QueryEntry = QueryEntry->Flink ) 
	{ 
		PTRUSTED_PROCESS TrustedProc = CONTAINING_RECORD( QueryEntry, TRUSTED_PROCESS, Next );
		if( Pid == TrustedProc->Pid )
		{
			IsTrusted = TRUE;
			break;
		}
	}

	ExReleaseFastMutex( &pdx_cdo->MutexGuardListOfTrustedProc );

	return IsTrusted;
}

/****************************************************************************/
/*  Function Name: CheckFileOnHide                                          */
/*  Section: PAGED                                                          */
/*  Description: creates full path to file/dir and check it on hide         */
/*  Return: TRUE - file needs to be hidden, FALSE - otherwise               */
/****************************************************************************/

BOOLEAN 
CheckFileOnHide(  
	PFILE_OBJECT FileObject,
	PFILE_BOTH_DIR_INFORMATION BothDirInfo,
	UCHAR DriveLetter
	)
{
	UNICODE_STRING unFullFilePath = { 0 };
	PWSTR wszFullFilePath = NULL;
	ULONG cbBlock = 0;
	ANSI_STRING anFileName;
	NTSTATUS status = STATUS_SUCCESS;
	ULONG ChkSum = 0;
	PFILE_FOR_HIDE FileHide = NULL;
	
	ASSERT( FileObject );
	ASSERT( BothDirInfo );
	
	if( FileObject->FileName.Buffer == NULL || 
		FileObject->FileName.Length == 0 )
		return 0;
	
	if( BothDirInfo->FileName[0] == L'.' &&
		BothDirInfo->FileNameLength == 2 )
		return 0;

	if( BothDirInfo->FileNameLength == 4 && 
		BothDirInfo->FileName[0] == L'.' &&
		BothDirInfo->FileName[1] == L'.' )
		return 0;

	cbBlock = FileObject->FileName.Length + sizeof( WCHAR ) * 4 + BothDirInfo->FileNameLength;
	
	wszFullFilePath = ( PWSTR )ExAllocatePoolWithTag( 
		NonPagedPool, cbBlock, FS_FLTR_STD_TAG );
	if( !wszFullFilePath )
		return FALSE;

	RtlZeroMemory( wszFullFilePath, cbBlock ); 

	wszFullFilePath[0] = (WCHAR)DriveLetter;
	wszFullFilePath[1] = L':';
	
	RtlCopyMemory( &wszFullFilePath[2], FileObject->FileName.Buffer,
		FileObject->FileName.Length );

	if( FileObject->FileName.Buffer[0] == L'\\' && FileObject->FileName.Length == 2 )
	{
		RtlCopyMemory( &wszFullFilePath[(cbBlock - BothDirInfo->FileNameLength - 3) / sizeof(WCHAR)],
			BothDirInfo->FileName, BothDirInfo->FileNameLength );
	}
	else
	{
		if( FileObject->FileName.Buffer[FileObject->FileName.Length / sizeof( WCHAR ) - 1] != L'\\' )
		{
			wszFullFilePath[(cbBlock - BothDirInfo->FileNameLength - 3) / sizeof(WCHAR)] = L'\\';
		
			RtlCopyMemory( &wszFullFilePath[(cbBlock - BothDirInfo->FileNameLength - 2) / sizeof(WCHAR)],
				BothDirInfo->FileName, BothDirInfo->FileNameLength );
		}
		else
		{
			RtlCopyMemory( &wszFullFilePath[(cbBlock - BothDirInfo->FileNameLength - 3) / sizeof(WCHAR)],
				BothDirInfo->FileName, BothDirInfo->FileNameLength );
		}
	}

	RtlInitUnicodeString( &unFullFilePath, wszFullFilePath );
	status = RtlUnicodeStringToAnsiString( &anFileName, &unFullFilePath, TRUE );

	if( !NT_SUCCESS( status ) )
	{
		unFullFilePath.Buffer = 0;
		ExFreePoolWithTag( wszFullFilePath, 0 );
		return FALSE;
	}

	UpcaseAnsiString( &anFileName );

	ChkSum = CreateChkSumForStr( &anFileName );

	RtlFreeAnsiString( &anFileName );
	unFullFilePath.Buffer = 0;

	ExFreePoolWithTag( wszFullFilePath, 0 );
	
	if( LookupHideFileInListOfHideFilesByChkSum( ChkSum ) )
		return TRUE;
	else
		return FALSE;
}

/****************************************************************************/
/*  Function Name: CreateChkSumForStr                                       */
/*  Section: PAGED                                                          */
/*  Description: creates checksum by CRC32                                  */
/*  Return: Checksum                                                        */
/****************************************************************************/

ULONG 
CreateChkSumForStr( 
	PANSI_STRING StrForCalcChkSum 
	)
{
	ULONG crc;
	ULONG len;
	PCHAR buf = StrForCalcChkSum->Buffer;
		
	static ULONG crc_table[256];
	static ULONG is_table_init = 0;

	ASSERT( StrForCalcChkSum );
	PAGED_CODE(  );

	len = StrForCalcChkSum->Length;

	if( !is_table_init )
	{ //generate table
		is_table_init = 1;
		
		for( register int i = 0; i < 256; i++ )
		{
			crc = i;
			for( register int j = 0; j < 8; j++ )
				crc = crc & 1 ? ( crc >> 1 ) ^ 0xEDB88320UL : crc >> 1;
	 
			crc_table[i] = crc;
		}
    }

	crc = 0xFFFFFFFFUL;

	//generate crc
	while ( len-- ) 
        crc = crc_table[( crc ^ *buf++ ) & 0xFF] ^ ( crc >> 8 );
 
    return crc ^ 0xFFFFFFFFUL;
}

/****************************************************************************/
/*  Function Name: FsFltrAllocateForHideFileStruct                          */
/*  Section: PAGED                                                          */
/*  Description: allocate memory for FILE_FOR_HIDE struct                   */
/*  Return: ptr to alocate FILE_FOR_HIDE struct                             */
/****************************************************************************/

PFILE_FOR_HIDE
FsFltrAllocateForHideFileStruct(  
	)
{
	PAGED_CODE(  );
	
	PFILE_FOR_HIDE p = (PFILE_FOR_HIDE) ExAllocatePoolWithTag( NonPagedPool, 
		sizeof( FILE_FOR_HIDE ), FS_FLTR_STD_TAG );
	RtlZeroMemory( p, sizeof( FILE_FOR_HIDE ) );
	return p;
}

/****************************************************************************/
/*  Function Name: FsFltrFreeForHideFileStruct                              */
/*  Section: PAGED                                                          */
/*  Description: frees memory that allocated FsFltrAllocateForHideFileStruct*/
/*  Return: VOID                                                            */
/****************************************************************************/

VOID
FsFltrFreeForHideFileStruct(
	PFILE_FOR_HIDE p
	)
{
	PAGED_CODE(  );
	ExFreePoolWithTag( p, FS_FLTR_STD_TAG );
}

/****************************************************************************/
/*  Function Name: str_len                                                  */
/*  Section: RESIDENT                                                       */
/*  Description: calculates string length                                   */
/*  Return: count characters in string                                      */
/****************************************************************************/

ULONG str_len( PWSTR str )
{
	ULONG len = 0;

	while( *str++ ) len++;

	return len;
}

/****************************************************************************/
/*  Function Name: InsertOrDeleteEntryInListOfHideFiles                     */
/*  Section: PAGED                                                          */
/*  Description: by file name, deletes item from list of hide files, if     */
/*               IsInsert equals false, otherwise insert new item in list   */
/*  Return: FileName length in bytes, including NULL                        */
/****************************************************************************/

ULONG
InsertOrDeleteEntryInListOfHideFiles( 
	PWCHAR FileName,
	BOOLEAN IsInsert
	)
{
	ULONG QueryStrLen = 0;
	ULONG cbStr = 0;
	PWCHAR pwszFileName = NULL;
	ULONG ChkSum = 0;
	ANSI_STRING anFileName = { 0 };
	NTSTATUS status;
	PDEVICE_EXTENSION_CDO pdx = NULL;
	PFILE_FOR_HIDE file_hide = NULL;

	ASSERT( FileName );
	ASSERT( FsFltrCDO );
	ASSERT( FsFltrCDO->DeviceExtension );
	PAGED_CODE(  );

	pdx = ( PDEVICE_EXTENSION_CDO )FsFltrCDO->DeviceExtension;

	QueryStrLen = str_len( FileName );
	if( !QueryStrLen ) return 0;

	if( FileName[QueryStrLen - 1] == L'\\' )
		QueryStrLen--;

	cbStr = ( QueryStrLen + 1 ) * sizeof( WCHAR );
			
	pwszFileName = (PWCHAR)
		ExAllocatePoolWithTag( PagedPool, cbStr, FS_FLTR_STD_TAG );
	
	if( !pwszFileName )
		return cbStr;
		
	RtlZeroMemory( pwszFileName, cbStr );

	RtlCopyMemory( pwszFileName, FileName, cbStr - 2 );

	if( !IsInsert )
	{ //delete item
		UNICODE_STRING unDelFileName = { 0 };
		ANSI_STRING anDelFileName = { 0 };

		RtlInitUnicodeString( &unDelFileName, pwszFileName );
		status = RtlUnicodeStringToAnsiString( &anDelFileName, &unDelFileName, TRUE );

		if( !NT_SUCCESS( status ) )
		{
			ExFreePoolWithTag( pwszFileName, FS_FLTR_STD_TAG );
			return cbStr;
		}

		UpcaseAnsiString( &anDelFileName );
		DeleteEntryFromListOfHideFiles( &anDelFileName );

		ExFreePoolWithTag( pwszFileName, FS_FLTR_STD_TAG );
		RtlFreeAnsiString( &anDelFileName );
		return cbStr;
	}

	file_hide = FsFltrAllocateForHideFileStruct(  );
	
	if( !file_hide ) 
		return cbStr;
	
	RtlInitUnicodeString( &file_hide->FileName, pwszFileName );

	status = RtlUnicodeStringToAnsiString( &anFileName, 
		&file_hide->FileName, TRUE );

	if( !NT_SUCCESS( status ) )
	{
		ExFreePoolWithTag( pwszFileName, FS_FLTR_STD_TAG );
		FsFltrFreeForHideFileStruct( file_hide );

		return cbStr;
	}

	UpcaseAnsiString( &anFileName );
	file_hide->ChkSumOfName = CreateChkSumForStr( &anFileName );

	ExAcquireFastMutex( &pdx->MutexForGuardList );
	
	InsertHeadList( 
		&pdx->ListOfHideFiles,
		(PLIST_ENTRY)file_hide
		);

	ExReleaseFastMutex( &pdx->MutexForGuardList );

	if( FileName[QueryStrLen] == L'\\' )
		return cbStr + 1 * sizeof( WCHAR );
	else
		return cbStr;
}

/****************************************************************************/
/*  Function Name: DeleteEntryFromListOfHideFiles                           */
/*  Section: PAGED                                                          */
/*  Description: by file name, deletes item from list of hide files;        */
/*               string must be upcase                                      */
/*  Return: TRUE - if deletion success, FALSE - otherwise                   */
/****************************************************************************/

BOOLEAN
DeleteEntryFromListOfHideFiles( 
	PANSI_STRING FileName 
	)
{
	ULONG ChkSum = 0;	
	PFILE_FOR_HIDE del_elem = NULL;
	PDEVICE_EXTENSION_CDO pdx = NULL;

	ASSERT( FileName );
	ASSERT( FsFltrCDO );
	ASSERT( FsFltrCDO->DeviceExtension );
	PAGED_CODE(  );

	pdx = ( PDEVICE_EXTENSION_CDO )FsFltrCDO->DeviceExtension;
	
	ChkSum = CreateChkSumForStr( FileName );

	del_elem = LookupHideFileInListOfHideFilesByChkSum( ChkSum );

	if( !del_elem ) return FALSE;

	ExAcquireFastMutex( &pdx->MutexForGuardList );

	RemoveEntryList( (PLIST_ENTRY)del_elem );

	ExReleaseFastMutex( &pdx->MutexForGuardList );

	ExFreePoolWithTag( del_elem->FileName.Buffer, FS_FLTR_STD_TAG );
	FsFltrFreeForHideFileStruct( del_elem );

	return TRUE;
}

/****************************************************************************/
/*  Function Name: LookupHideFileInListOfHideFilesByChkSum                  */
/*  Section: PAGED                                                          */
/*  Description: by checksum, lookup item in list of hide files;            */
/*  Return: if success, ptr to FILE_FOR_HIDE struct, otherwise NULL         */
/****************************************************************************/

PFILE_FOR_HIDE
LookupHideFileInListOfHideFilesByChkSum(
   ULONG ChkSum
   )
{
	PDEVICE_EXTENSION_CDO pdx;

	PAGED_CODE(  );

	pdx = ( PDEVICE_EXTENSION_CDO )FsFltrCDO->DeviceExtension;

	if( IsListEmpty( &pdx->ListOfHideFiles ) ) return NULL;

	ExAcquireFastMutex( &pdx->MutexForGuardList );

	for( PLIST_ENTRY QueryStruct = pdx->ListOfHideFiles.Flink;
		 QueryStruct != &pdx->ListOfHideFiles;
		 QueryStruct = QueryStruct->Flink )
	{
		if( ( ( PFILE_FOR_HIDE ) QueryStruct )->ChkSumOfName == ChkSum )
		{
			ExReleaseFastMutex( &pdx->MutexForGuardList );
			return (PFILE_FOR_HIDE)QueryStruct;
		}
	}

	ExReleaseFastMutex( &pdx->MutexForGuardList );

	return NULL;
}

/****************************************************************************/
/*  Function Name: UpcaseAnsiString                                         */
/*  Section: RESIDENT                                                       */
/*  Description: upcase StrForUpper                                         */
/*  Return: VOID                                                            */
/****************************************************************************/

VOID
UpcaseAnsiString(
	PANSI_STRING StrForUpper
	)
{
	for( ULONG curIndex = 0; curIndex < StrForUpper->Length; curIndex++ )
		if( StrForUpper->Buffer[curIndex] >= 'a' && StrForUpper->Buffer[curIndex] <= 'z' )
			StrForUpper->Buffer[curIndex] &= 0xDF;

}		

/****************************************************************************/
/*  Function Name: FsFltrDispatchCreateOrCloseOrCleanupRequest              */
/*  Section: PAGED                                                          */
/*  Description: dispatch three requests:                                   */
/*               IRP_MJ_CREATE                                              */
/*               IRP_MJ_CLOSE                                               */
/*               IRP_MJ_CLEANUP                                             */
/*               set completion routine, check opened file on hide          */
/*  Return: NT status                                                       */
/****************************************************************************/

NTSTATUS
FsFltrDispatchCreateOrCloseOrCleanupRequest(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp
	)
{
	PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation( Irp );
	PDEVICE_EXTENSION pdx;
	KEVENT NotifEvent;
	NTSTATUS status;

	PAGED_CODE(  );

	if( IS_MY_CTRL_DEV_OBJ( DeviceObject ) )
	{//dispatch for CDO
		//KdPrint( ( "fsfltr!FsFltrDispatchCreateOrCloseOrCleanupRequest: Successfully dispatch open/close/cleanup request\n" ) );

		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;

		IoCompleteRequest( Irp, IO_NO_INCREMENT );
		return STATUS_SUCCESS;
	}
	
	ASSERT( IS_MY_DEV_OBJ( DeviceObject ) );

	pdx = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

	if( IoStack->MajorFunction == IRP_MJ_CLOSE ||
		IoStack->MajorFunction == IRP_MJ_CLEANUP )
	{
		IoSkipCurrentIrpStackLocation( Irp );
		return IoCallDriver( pdx->NextDevInChain, Irp );
	}

	KeInitializeEvent( &NotifEvent, NotificationEvent, FALSE );

	IoCopyCurrentIrpStackLocationToNext( Irp );

	IoSetCompletionRoutine( Irp, FsFltrCreateCompletion, &NotifEvent, TRUE, TRUE, FALSE );
	
	status = IoCallDriver( pdx->NextDevInChain, Irp );

	if( status == STATUS_PENDING ) 
	{
		KeWaitForSingleObject( &NotifEvent, 
			Executive, KernelMode, FALSE, NULL ); 
	}

	if( !NT_SUCCESS( Irp->IoStatus.Status ) )
	{
		status = Irp->IoStatus.Status;
		IoCompleteRequest( Irp, IO_NO_INCREMENT );
		return status;
	}

	DrmDispatchOpenOrCreateFile( DeviceObject, Irp );
	
	status = Irp->IoStatus.Status;

	if( !NT_SUCCESS( status ) )
	{
		IoCompleteRequest( Irp, IO_NO_INCREMENT );
		return status;
	}

	AvxCheckFile( pdx, Irp, FALSE );

	return status;
}

//function must complete IRP
VOID AvxCheckFile(
	PDEVICE_EXTENSION pdx,
	PIRP Irp,
	BOOLEAN IsFastIoRequestor
	)
{
	PWCHAR FullPath = NULL;
	PWCHAR NtPath;
	ULONG cbNtPath;
	UNICODE_STRING unFullPath = { 0 };
	UNICODE_STRING unNtFullPath;
	OBJECT_ATTRIBUTES ObjAttr = { 0 };
	FILE_BASIC_INFORMATION FileBasicInfo = { 0 };
	HANDLE hQueryFile = NULL;
	IO_STATUS_BLOCK iosb = { 0 };
	NTSTATUS Status = STATUS_SUCCESS;
	PFILE_PENDING_CREATE FilePendingCreate = NULL;
	FILE_PENDING_FINAL_STATUS FinalStatusOfRequest = Enabled;
	PDEVICE_EXTENSION_CDO pdx_cdo = ( PDEVICE_EXTENSION_CDO ) FsFltrCDO->DeviceExtension;
	KEVENT Event = { 0 };
	PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation( Irp );

	if( !IsAvxActive ) return;

	//check file on directory
	Status = FsFltrCreateFullPath( IoStack->FileObject, &FullPath, pdx->VolLetter, pdx );

	if( !NT_SUCCESS( Status ) )
		goto complete;
				
	RtlInitUnicodeString( &unFullPath, FullPath );

	cbNtPath = str_len( FullPath ) * sizeof( WCHAR ) + 
		sizeof( WCHAR ) + 4 * sizeof( WCHAR );// \0 + \??\

	NtPath = (PWCHAR) ExAllocatePoolWithTag( PagedPool, cbNtPath, FS_FLTR_STD_TAG );

	if( !NtPath )
	{
		FsFltrFreeFullPath( FullPath );
		goto complete;
	}

	RtlZeroMemory( NtPath, cbNtPath );

	NtPath[0] = L'\\';
	NtPath[1] = L'?';
	NtPath[2] = L'?';
	NtPath[3] = L'\\';

	RtlCopyMemory( &NtPath[4], FullPath, cbNtPath - 5 * sizeof( WCHAR ) );

	RtlInitUnicodeString( &unNtFullPath, NtPath );
				
	InitializeObjectAttributes( &ObjAttr, &unNtFullPath, 
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL );

	Status = IoCreateFileSpecifyDeviceObjectHint( 
		&hQueryFile,
		FILE_READ_ATTRIBUTES | SYNCHRONIZE,
		&ObjAttr,
		&iosb,
		NULL, //AllocationSize
		0, //Attributes
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, //ea buffer
		0, //ea length
		CreateFileTypeNone,
		NULL, //must be zero
		IO_IGNORE_SHARE_ACCESS_CHECK, //options
		pdx->NextDevInChain );

	ASSERT( NT_SUCCESS( Status ) );

	Status = ZwQueryInformationFile( hQueryFile, &iosb, &FileBasicInfo, 
			sizeof( FILE_BASIC_INFORMATION ), FileBasicInformation );

	ASSERT( NT_SUCCESS( Status ) );

	if( FileBasicInfo.FileAttributes & FILE_ATTRIBUTE_DIRECTORY )
	{// is directory ?
		if( FullPath ) FsFltrFreeFullPath( FullPath );
		if( NtPath ) ExFreePoolWithTag( NtPath, FS_FLTR_STD_TAG );

		goto complete;
	}

	//work with file
	FilePendingCreate = ( PFILE_PENDING_CREATE )
		ExAllocatePoolWithTag( NonPagedPool, sizeof( FILE_PENDING_CREATE ), FS_FLTR_STD_TAG );

	if( !FilePendingCreate ) 
	{
		if( FullPath ) FsFltrFreeFullPath( FullPath );
		if( NtPath ) ExFreePoolWithTag( NtPath, FS_FLTR_STD_TAG );
		
		goto complete; 
	}

	RtlZeroMemory( FilePendingCreate, sizeof( FILE_PENDING_CREATE ) );

	//create and init FileName member
	FilePendingCreate->FileName.Buffer = ( PWCHAR )
		ExAllocatePoolWithTag( PagedPool, unFullPath.MaximumLength, FS_FLTR_STD_TAG );

	if( FilePendingCreate->FileName.Buffer == NULL ) 
	{
		if( FullPath ) FsFltrFreeFullPath( FullPath );
		if( NtPath ) ExFreePoolWithTag( NtPath, FS_FLTR_STD_TAG );
		if( FilePendingCreate ) ExFreePoolWithTag( FilePendingCreate, FS_FLTR_STD_TAG );

		goto complete;
	}

	RtlZeroMemory( FilePendingCreate->FileName.Buffer, unFullPath.MaximumLength );

	FilePendingCreate->FileName.Length = unFullPath.Length;
	FilePendingCreate->FileName.MaximumLength = unFullPath.MaximumLength;
	RtlCopyMemory( FilePendingCreate->FileName.Buffer, unFullPath.Buffer, unFullPath.Length );

	FilePendingCreate->FinalStatus = &FinalStatusOfRequest;
				
	KeInitializeEvent( &Event, SynchronizationEvent, FALSE );
	FilePendingCreate->SynchEvent = &Event;

	if( IsFastIoRequestor )
		FilePendingCreate->Requestor = _PENDING_FILE_INFORMATION::INTERNAL::FastIoQueryOpen;
	else
		FilePendingCreate->Requestor = _PENDING_FILE_INFORMATION::INTERNAL::IrpMjCreate;

	FilePendingCreate->Cid.UniqueProcess = PsGetCurrentProcessId(  );
	FilePendingCreate->Cid.UniqueThread = PsGetCurrentThreadId(  );
	FilePendingCreate->CreateDisposition = 
		( PENDING_FILE_INFORMATION::DISPOSITION )( IoStack->Parameters.Create.Options >> 24 );

	ExInterlockedInsertTailList( &pdx_cdo->ListOfPendingCreate, &FilePendingCreate->NextStruct,
		&pdx_cdo->LockGuardPendingCreate );

	KeReleaseSemaphore( &pdx_cdo->SemGuardPendingCreate, IO_NO_INCREMENT, 1, FALSE );

	KeWaitForSingleObject( &Event, Executive, KernelMode, FALSE, NULL );

	//operation completed
	switch( FinalStatusOfRequest )
	{
		case Denied:
		{
			Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
		}
		case Enabled:
		{
			break;
		}
		default:
		{
			ASSERT( 0 );
		}
	}
		
complete:
	if( !IsFastIoRequestor ) IoCompleteRequest( Irp, IO_NO_INCREMENT );

	return;
}


/****************************************************************************/
/*  Function Name: FsFltrCreateCompletion                                   */
/*  Section: PAGED                                                          */
/*  Description: set event to dispatch function                             */
/*  Return: STATUS_MORE_PROCESSING_REQUIRED                                 */
/****************************************************************************/

NTSTATUS
FsFltrCreateCompletion(
   PDEVICE_OBJECT DeviceObject,
   PIRP Irp,
   PVOID Context
   )
{
	PKEVENT pkevent;

	UNREFERENCED_PARAMETER( DeviceObject );
	UNREFERENCED_PARAMETER( Irp );
	PAGED_CODE(  )

	ASSERT( IS_MY_DEV_OBJ( DeviceObject ) );

	pkevent = (PKEVENT)Context;

	KeSetEvent( pkevent, IO_NO_INCREMENT, FALSE );

	return STATUS_MORE_PROCESSING_REQUIRED;
}

/****************************************************************************/
/*  Function Name: FsFltrCreateFullPath                                     */
/*  Section: PAGED                                                          */
/*  Description: creates full path to file by file object                   */
/*  Return: NT status                                                       */
/****************************************************************************/

NTSTATUS
FsFltrCreateFullPath(
	 IN PFILE_OBJECT FileObject,
	 OUT WCHAR** FullPath,
	 CHAR VolLetter,
	 PDEVICE_EXTENSION pdx
	)
{
	PWSTR pwszFullPath = NULL;
	PWSTR pwszQueryPath = NULL;
	ULONG cbFullPath = 0;
	PFILE_OBJECT QueryFileObject = NULL;
	PWSTR RelativePath;
	NTSTATUS status;
	BOOLEAN NeedFullPath = FALSE;

	ASSERT( FileObject );
	ASSERT( FullPath );
	PAGED_CODE(  );

	if( FileObject->FileName.Length == 0 ||
		FileObject->FileName.Buffer == NULL ||
		FlagOn( FileObject->Flags, FO_VOLUME_OPEN )	)
			return STATUS_UNSUCCESSFUL;

	if( FileObject->FileName.Buffer[0] == L'\\' &&
		FileObject->FileName.Length == sizeof( WCHAR ) )
	{//if open root
		*FullPath = (PWCHAR)
			ExAllocatePoolWithTag( PagedPool, 4 * sizeof( WCHAR ), FS_FLTR_STD_TAG );
		if( *FullPath == NULL ) return STATUS_INSUFFICIENT_RESOURCES;
		RtlZeroMemory( *FullPath, 4 * sizeof( WCHAR ) );

		FullPath[0][0] = (WCHAR)VolLetter;
		FullPath[0][1] = L':';
		FullPath[0][2] = L'\\';
		return STATUS_SUCCESS;
	}

	if( FileObject->RelatedFileObject )
	{//if relative path exists
		status = QueryFileSystemForFileName( FileObject->RelatedFileObject, 
			pdx->NextDevInChain, &RelativePath );

		if( NT_SUCCESS( status ) )
		{
			UNICODE_STRING unFirstNameRelative;
			UNICODE_STRING unRemainingNameRelative;
			UNICODE_STRING unFirstName;
			UNICODE_STRING unRemainingName;

			FsRtlDissectName( FileObject->RelatedFileObject->FileName, &unFirstNameRelative, 
				&unRemainingNameRelative );

			if( unFirstNameRelative.Buffer == NULL ||
				unRemainingNameRelative.Buffer == NULL )
			{
				return STATUS_INSUFFICIENT_RESOURCES;
			}

			FsRtlDissectName( FileObject->FileName, &unFirstName, &unRemainingName );

			if( unFirstName.Buffer == NULL ||
				unRemainingName.Buffer == NULL )
			{
				return STATUS_INSUFFICIENT_RESOURCES;
			}

			if( RtlCompareUnicodeString( &unFirstNameRelative, &unFirstName, TRUE ) == 0 )
			{
				NeedFullPath = TRUE;
				ExFreePoolWithTag( RelativePath, FS_FLTR_STD_TAG );
			}

			if( !NeedFullPath )
			{
				ULONG cbRelativePath = str_len( RelativePath ) * sizeof( WCHAR ) + sizeof( WCHAR );
				ULONG strPos = 0;
				ULONG cbFullPath = str_len( RelativePath ) * sizeof( WCHAR ) +
					FileObject->FileName.Length + sizeof( WCHAR ) + 
						2 * sizeof( WCHAR ) + sizeof( WCHAR );
				//0 + C: + \\

				PWCHAR Path = ( PWCHAR )
					ExAllocatePoolWithTag( PagedPool, cbFullPath, FS_FLTR_STD_TAG );

				if( !Path )
				{
					ExFreePoolWithTag( RelativePath, FS_FLTR_STD_TAG );
					return STATUS_INSUFFICIENT_RESOURCES;
				}

				RtlZeroMemory( Path, cbFullPath );

				Path[0] = (WCHAR)VolLetter;
				Path[1] = L':';
				
				strPos = 2;

				RtlCopyMemory( &Path[strPos], RelativePath, cbRelativePath - sizeof( WCHAR ) );

				strPos += ( cbRelativePath / 2 - 1 );

				if( Path[strPos - 1] != '\\' &&
					FileObject->FileName.Buffer[0] != '\\' )
				{
					Path[strPos] = '\\';
					strPos++;
				}
				else if( Path[strPos - 1] == '\\' &&
					FileObject->FileName.Buffer[0] == '\\' )
				{
					Path[strPos-1] = 0;
					strPos--;
				}

				RtlCopyMemory( &Path[strPos], FileObject->FileName.Buffer, 
					FileObject->FileName.Length );

				strPos += ( FileObject->FileName.Length / sizeof( WCHAR ) );

				if( Path[strPos - 1] == '\\' ) Path[strPos - 1] = 0;

				*FullPath = Path;

				ExFreePoolWithTag( RelativePath, FS_FLTR_STD_TAG );

				return STATUS_SUCCESS;
			}
		}
	}

	if( FileObject->RelatedFileObject == NULL || NeedFullPath )
	{
		ULONG cbPath = FileObject->FileName.Length + sizeof( WCHAR ) + 2 * sizeof( WCHAR );
		PWCHAR Path = ( PWCHAR )ExAllocatePoolWithTag( PagedPool, 
			cbPath, FS_FLTR_STD_TAG );

		if( !Path ) return STATUS_INSUFFICIENT_RESOURCES;

		RtlZeroMemory( Path, cbPath );

		Path[0] = ( WCHAR )VolLetter;
		Path[1] = L':';
		
		RtlCopyMemory( &Path[2], FileObject->FileName.Buffer, FileObject->FileName.Length );

		if( FileObject->FileName.Buffer[FileObject->FileName.Length / sizeof( WCHAR ) - 1] == '\\' )
			Path[FileObject->FileName.Length / sizeof( WCHAR ) - 1 + 2] = 0;

		*FullPath = Path;

		return STATUS_SUCCESS;
	}

	ASSERT( 0 );
	return STATUS_SUCCESS;
}

NTSTATUS
QueryFileSystemForFileName(
    PFILE_OBJECT QueryFileObject,
	PDEVICE_OBJECT DeviceObject,
	WCHAR **FileName
	)
{
	PIRP Irp = NULL;
	PIO_STACK_LOCATION IoStack = NULL;
	IO_STATUS_BLOCK iosb = { 0 };
	PFILE_NAME_INFORMATION FileNameInfo = NULL;
	ULONG cbBuf = 1024;
	KEVENT Event;
	NTSTATUS status;

	ASSERT( QueryFileObject );
	ASSERT( DeviceObject );
	ASSERT( FileName );

	PAGED_CODE(  );

	FileNameInfo = ( PFILE_NAME_INFORMATION )
		ExAllocatePoolWithTag( PagedPool, cbBuf, FS_FLTR_STD_TAG );
	
	if( FileNameInfo == NULL )
		return STATUS_INSUFFICIENT_RESOURCES;

	Irp = IoAllocateIrp( DeviceObject->StackSize, TRUE );

	Irp->Tail.Overlay.Thread = PsGetCurrentThread(  );
	Irp->RequestorMode = KernelMode;
	Irp->UserIosb = &iosb;
	Irp->AssociatedIrp.SystemBuffer = FileNameInfo;
	Irp->Flags = IRP_SYNCHRONOUS_API;

	IoStack = IoGetNextIrpStackLocation( Irp );

	IoStack->MajorFunction = IRP_MJ_QUERY_INFORMATION;
	IoStack->Parameters.QueryFile.FileInformationClass = FileNameInformation;
	IoStack->Parameters.QueryFile.Length = cbBuf;
	IoStack->FileObject = QueryFileObject;

	KeInitializeEvent( &Event, NotificationEvent, FALSE );

	IoSetCompletionRoutine( Irp, ( PIO_COMPLETION_ROUTINE )FsFltrQueryFileInfoCompletion, &Event, 
		TRUE, TRUE, FALSE );

	status = IoCallDriver( DeviceObject, Irp );

	KeWaitForSingleObject( &Event, Executive, KernelMode, FALSE, NULL );

	if( NT_SUCCESS( iosb.Status ) )
	{//copy data to client buffer
		ULONG cbClientBuf = FileNameInfo->FileNameLength + sizeof( WCHAR );
		PWCHAR pClientBuf = NULL;

		pClientBuf = ( PWCHAR )ExAllocatePoolWithTag( PagedPool, 
			cbClientBuf, FS_FLTR_STD_TAG );

		if( !pClientBuf )
		{
			ExFreePoolWithTag( FileNameInfo, FS_FLTR_STD_TAG );
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		
		RtlZeroMemory( pClientBuf, cbClientBuf );

		RtlCopyMemory( pClientBuf, &FileNameInfo->FileName, FileNameInfo->FileNameLength );

		*FileName = pClientBuf;
	}
	else
	{
		*FileName = NULL;
	}

	ExFreePoolWithTag( FileNameInfo, FS_FLTR_STD_TAG );

	return iosb.Status;
}

NTSTATUS
FsFltrQueryFileInfoCompletion(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp,
	PKEVENT Event
	)
{
	UNREFERENCED_PARAMETER( DeviceObject );

	ASSERT( Irp->UserIosb );

	Irp->UserIosb->Status = Irp->IoStatus.Status;
	Irp->UserIosb->Information = Irp->IoStatus.Information;

	KeSetEvent( Event, IO_NO_INCREMENT, FALSE );

	IoFreeIrp( Irp );
	return STATUS_MORE_PROCESSING_REQUIRED;
}


/****************************************************************************/
/*  Function Name: FsFltrFreeFullPath                                       */
/*  Section: PAGED                                                          */
/*  Description: free buffer that was allocated by FsFltrCreateFullPath     */
/*  Return: VOID                                                            */
/****************************************************************************/

VOID
FsFltrFreeFullPath(
   PWSTR FullPath
	)
{
	PAGED_CODE(  );

	return ExFreePoolWithTag( FullPath, FS_FLTR_STD_TAG );
}

/****************************************************************************/
/*  Function Name: FsFltrDispatchDeviceControl                              */
/*  Section: PAGED                                                          */
/*  Description: dispatch IRP_MJ_DEVICE_CONTROL request                     */
/*  Return: NT status                                                       */
/****************************************************************************/

NTSTATUS
FsFltrDispatchDeviceControl(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp 
	)
{
	PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation( Irp );
	NTSTATUS status = STATUS_SUCCESS;
	
	PAGED_CODE(  );

	if( IS_MY_CTRL_DEV_OBJ( DeviceObject ) )
	{
		if( IoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_LISTEN_CREATE_REQUEST )
		{
			IoMarkIrpPending( Irp ); 
			IoSetCancelRoutine( Irp, Cancel );
			IoStartPacket( DeviceObject, Irp, NULL, Cancel );

			return STATUS_PENDING;
		}
		else if( IoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_LISTEN_CREATE_REPLY )
		{
			if( IoStack->Parameters.DeviceIoControl.InputBufferLength < 
				sizeof( FILE_PENDING_FINAL_STATUS ) )
			{
				Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
				Irp->IoStatus.Information = 0;
			}
			else
			{
				PDEVICE_EXTENSION_CDO pdx_cdo = 
					( PDEVICE_EXTENSION_CDO ) DeviceObject->DeviceExtension;

				pdx_cdo->ReceivedStatus = 
					*( ( PFILE_PENDING_FINAL_STATUS )Irp->AssociatedIrp.SystemBuffer );
				
				KeSetEvent( &pdx_cdo->SynchEvent, IO_NO_INCREMENT, FALSE );

				Irp->IoStatus.Status = STATUS_SUCCESS;
				Irp->IoStatus.Information = 0;
			}

			status = Irp->IoStatus.Status;
			IoCompleteRequest( Irp, IO_NO_INCREMENT );

			return status;
		}
		else if( IoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_START_AVX )
		{
			if( InterlockedCompareExchange( &IsAvxActive, TRUE, FALSE ) == FALSE )
				status = STATUS_SUCCESS;
			else
				status = STATUS_UNSUCCESSFUL;

			Irp->IoStatus.Status = status;
			Irp->IoStatus.Information = 0;

			IoCompleteRequest( Irp, IO_NO_INCREMENT );

			return status;
		}
		else if( IoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_STOP_AVX )
		{
			if( InterlockedCompareExchange( &IsAvxActive, FALSE, TRUE ) == TRUE )
				status = STATUS_SUCCESS;
			else
				status = STATUS_UNSUCCESSFUL;

			Irp->IoStatus.Status = status;
			Irp->IoStatus.Information = 0;

			IoCompleteRequest( Irp, IO_NO_INCREMENT );

			return status;
		}
		else if( IoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_FSFLTR_ADD_FILES || 
				 IoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_FSFLTR_REMOVE_FILES ||
				 IoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_FSFLTR_QUERY_FILES )
		{
			status = FsFltrpDispatchDeviceControl( IoGetCurrentIrpStackLocation( Irp ),
				&Irp->IoStatus, Irp->MdlAddress );

			IoCompleteRequest( Irp, IO_NO_INCREMENT );
			return status;
		}
		else if( IoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_ADD_TRUSTED_PROCESSES || 
				 IoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_REMOVE_TRUSTED_PROCESSES ||
				 IoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_QUERY_TRUSTED_PROCESSES )
		{
			status = FsFltrDispatchTrustedProcessOp( (PULONG)Irp->AssociatedIrp.SystemBuffer, 
				IoStack->Parameters.DeviceIoControl.InputBufferLength, (PULONG)Irp->AssociatedIrp.SystemBuffer,
					IoStack->Parameters.DeviceIoControl.OutputBufferLength, 
						IoStack->Parameters.DeviceIoControl.IoControlCode, &Irp->IoStatus );

			IoCompleteRequest( Irp, IO_NO_INCREMENT );
			return status;
		}
		
		Irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
		IoCompleteRequest( Irp, IO_NO_INCREMENT );
		KdPrint(( "fsfltr!FsFltrDispatchDeviceControl: was called not implemented function\n" ));

		return STATUS_NOT_IMPLEMENTED;
	}
	else if( IS_MY_DEV_OBJ( DeviceObject ) )
	{
		PDEVICE_EXTENSION pdx = ( PDEVICE_EXTENSION )DeviceObject->DeviceExtension;
		IoSkipCurrentIrpStackLocation( Irp );
		return IoCallDriver( pdx->NextDevInChain, Irp );
	}

	ASSERT( 0 );

	return STATUS_SUCCESS;
}

NTSTATUS
FsFltrDispatchTrustedProcessOp(
   PULONG InputBuffer,
   ULONG InputBufferLength,
   PULONG OutputBuffer,
   ULONG OutputBufferLength,
   ULONG IoControlCode,
   PIO_STATUS_BLOCK iosb
   )
{
	PDEVICE_EXTENSION_CDO pdx_cdo = ( PDEVICE_EXTENSION_CDO )FsFltrCDO->DeviceExtension;

	PAGED_CODE(  );
	ASSERT( iosb );

	if( InputBuffer == NULL )
	{
		iosb->Status = STATUS_INVALID_PARAMETER;
		return STATUS_INVALID_PARAMETER;
	}

	switch( IoControlCode )
	{
		case IOCTL_REMOVE_TRUSTED_PROCESSES:
		{
			PLIST_ENTRY QueryEntry = NULL;
			ULONG cPids = 0;
			ULONG numRemovedPids = 0;

			if( InputBufferLength < sizeof( ULONG ) * 2 )
			{
				iosb->Status = STATUS_INVALID_PARAMETER;
				return STATUS_INVALID_PARAMETER;
			}

			cPids = *InputBuffer++;
			
			if( cPids == 0 )
			{
				iosb->Status = STATUS_INVALID_PARAMETER;
				return STATUS_INVALID_PARAMETER;
			}

			ExAcquireFastMutex( &pdx_cdo->MutexGuardListOfTrustedProc );

			for( ULONG PidIndex = 0; PidIndex < cPids; PidIndex++ )
			{
				for( QueryEntry = pdx_cdo->ListOfTrustedProcesses.Flink;
					 QueryEntry != &pdx_cdo->ListOfTrustedProcesses; 
					 QueryEntry = QueryEntry->Flink ) 
				{
					PTRUSTED_PROCESS TrustedProc = 
						CONTAINING_RECORD( QueryEntry, TRUSTED_PROCESS, Next );

					if( TrustedProc->Pid == (HANDLE)InputBuffer[PidIndex] )
					{
						RemoveEntryList( QueryEntry );
						numRemovedPids++;
					}
				}
			}

			ExReleaseFastMutex( &pdx_cdo->MutexGuardListOfTrustedProc );

			if( !numRemovedPids )
			{
				iosb->Status = STATUS_NO_SUCH_FILE;
				return STATUS_NO_SUCH_FILE;
			}

			iosb->Status = STATUS_SUCCESS;
			return STATUS_SUCCESS;
		}
		case IOCTL_ADD_TRUSTED_PROCESSES:
		{
			ULONG cPids = 0;
			ULONG numAddedPids = 0;
			
			if( InputBufferLength < sizeof( ULONG ) * 2 )
			{
				iosb->Status = STATUS_INVALID_PARAMETER;
				return STATUS_INVALID_PARAMETER;
			}

			cPids = *InputBuffer;
			InputBuffer++;

			if( cPids == 0 )
			{
				iosb->Status = STATUS_INVALID_PARAMETER;
				return STATUS_INVALID_PARAMETER;
			}

			ExAcquireFastMutex( &pdx_cdo->MutexGuardListOfTrustedProc );

			for( ULONG i = 0; i < cPids; i++ )
			{
				if( CheckPidForTrustedUnsafe( (HANDLE)InputBuffer[i] ) == TRUE ) continue;

				PTRUSTED_PROCESS TrustedProcess = ( PTRUSTED_PROCESS )
					ExAllocatePoolWithTag( PagedPool, sizeof( TRUSTED_PROCESS ), 
						FS_FLTR_STD_TAG );

				if( !TrustedProcess )
				{
					iosb->Status = STATUS_INSUFFICIENT_RESOURCES;
					return STATUS_INSUFFICIENT_RESOURCES;
				}

				TrustedProcess->Pid = ( HANDLE )InputBuffer[i];

				InsertTailList( &pdx_cdo->ListOfTrustedProcesses, &TrustedProcess->Next );

				numAddedPids++;
			}

			ExReleaseFastMutex( &pdx_cdo->MutexGuardListOfTrustedProc );

			if( !numAddedPids )
			{
				iosb->Status = STATUS_NO_SUCH_FILE;
				return STATUS_NO_SUCH_FILE;
			}

			iosb->Status = STATUS_SUCCESS;
			return STATUS_SUCCESS;
		}
		case IOCTL_QUERY_TRUSTED_PROCESSES:
		{
			PTRUSTED_PROCESS TrustedProc = NULL;
			PLIST_ENTRY QueryEntry;
			PULONG QueryPid = NULL;

			ULONG cPids = 0;

			if( OutputBuffer == NULL )
			{
				iosb->Status = STATUS_INVALID_PARAMETER;
				return STATUS_INVALID_PARAMETER;
			}

			ExAcquireFastMutex( &pdx_cdo->MutexGuardListOfTrustedProc );

			for( QueryEntry = pdx_cdo->ListOfTrustedProcesses.Flink;
				 QueryEntry != &pdx_cdo->ListOfTrustedProcesses; 
				 QueryEntry = QueryEntry->Flink, cPids++ ) {  }

			if( cPids == 0 )
			{
				iosb->Status = STATUS_NO_MORE_FILES;
				ExReleaseFastMutex( &pdx_cdo->MutexGuardListOfTrustedProc );
				return STATUS_NO_MORE_FILES;
			}

			if( OutputBufferLength < cPids * sizeof( HANDLE ) + 4  )
			{
				ExReleaseFastMutex( &pdx_cdo->MutexGuardListOfTrustedProc );
				iosb->Status = STATUS_INVALID_PARAMETER;
				return STATUS_INVALID_PARAMETER;
			}

			*OutputBuffer = cPids;

			for( QueryEntry = pdx_cdo->ListOfTrustedProcesses.Flink,
				 QueryPid = OutputBuffer + 1;
				 QueryEntry != &pdx_cdo->ListOfTrustedProcesses; 
				 QueryEntry = QueryEntry->Flink,
				 QueryPid++ ) 
			{ 
				PTRUSTED_PROCESS TrustedProc = CONTAINING_RECORD( QueryEntry, TRUSTED_PROCESS, Next );
				*QueryPid = ( ULONG )TrustedProc->Pid; 
			}

			ExReleaseFastMutex( &pdx_cdo->MutexGuardListOfTrustedProc );

			iosb->Information = ( cPids + 1 ) * sizeof( ULONG );
			iosb->Status = STATUS_SUCCESS;

			return STATUS_SUCCESS;
		}
		default:
			ASSERT( 0 );

	}

	return STATUS_SUCCESS;
}

BOOLEAN
CheckPidForTrustedUnsafe(
	HANDLE Pid
   )
{
	PDEVICE_EXTENSION_CDO pdx_cdo = ( PDEVICE_EXTENSION_CDO )
		FsFltrCDO->DeviceExtension;
	BOOLEAN IsTrusted = FALSE;
	PLIST_ENTRY QueryEntry;

	PAGED_CODE(  );
	ASSERT( Pid );
	ASSERT( pdx_cdo );

	for( QueryEntry = pdx_cdo->ListOfTrustedProcesses.Flink;
		 QueryEntry != &pdx_cdo->ListOfTrustedProcesses; 
		 QueryEntry = QueryEntry->Flink ) 
	{ 
		PTRUSTED_PROCESS TrustedProc = CONTAINING_RECORD( QueryEntry, TRUSTED_PROCESS, Next );
		if( Pid == TrustedProc->Pid )
		{
			IsTrusted = TRUE;
			break;
		}
	}

	return IsTrusted;
}

/****************************************************************************/
/*  Function Name: FsFltrpDispatchDeviceControl                             */
/*  Section: PAGED                                                          */
/*  Description: dispatch device control request for specific IOCTLs        */
/*  Return: NT status                                                       */
/****************************************************************************/

NTSTATUS 
FsFltrpDispatchDeviceControl(
	 PIO_STACK_LOCATION IoStack,
	 PIO_STATUS_BLOCK piosb,
	 PMDL Mdl
	)
{
	PVOID OutBuffer = NULL;
	ULONG next_offset = 0;
	ULONG elem_count = 0;
	PLIST_ENTRY query_entry = NULL;
	PFILE_FOR_HIDE FileForHide = NULL;
	ULONG cbTargetBuf = 0;
	PWCHAR QueryStr = NULL;
	PDEVICE_EXTENSION_CDO pdx_cdo = ( PDEVICE_EXTENSION_CDO )FsFltrCDO->DeviceExtension;

	ASSERT( IoStack );
	ASSERT( piosb );
	PAGED_CODE(  );

	switch( IoStack->Parameters.DeviceIoControl.IoControlCode )
	{
		case IOCTL_FSFLTR_ADD_FILES:
		case IOCTL_FSFLTR_REMOVE_FILES:
		{// add or remove files from list of hide files
			KdPrint( ( "fsfltr!FsFltrpDispatchDeviceControl: Call service for add/remove files\n" ) );

			if( IoStack->Parameters.DeviceIoControl.OutputBufferLength < 3 * sizeof( WCHAR ) )
			{
				piosb->Information = 0;
				piosb->Status = STATUS_INFO_LENGTH_MISMATCH;

				return STATUS_INFO_LENGTH_MISMATCH;
			}

			ASSERT( Mdl );
			OutBuffer = MmGetSystemAddressForMdlSafe( Mdl, NormalPagePriority );

			if( !OutBuffer )
			{
				piosb->Information = 0;
				piosb->Status = STATUS_INSUFFICIENT_RESOURCES;

				return STATUS_INSUFFICIENT_RESOURCES;
			}

			for( PWCHAR QueryStr = (PWCHAR)OutBuffer;
				QueryStr[0];
				QueryStr = ( PWCHAR )( (PUCHAR)QueryStr + next_offset )  )
			{
				if( IoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_FSFLTR_REMOVE_FILES )
					next_offset = InsertOrDeleteEntryInListOfHideFiles( QueryStr, 0 );
				else
					next_offset = InsertOrDeleteEntryInListOfHideFiles( QueryStr, 1 );
			}

			MmUnmapLockedPages( OutBuffer, Mdl );

			piosb->Information = 0;
			piosb->Status = STATUS_SUCCESS;

			return STATUS_SUCCESS;
		}
		case IOCTL_FSFLTR_QUERY_FILES:
		{//to copies all hide files to client
			KdPrint( ( "fsfltr!FsFltrpDispatchDeviceControl: Call service for query files\n" ) );

			ASSERT( Mdl );

			elem_count = GetCountElementsInListOfHideFiles(  );

			if( !elem_count )
			{
				piosb->Information = 0;
				piosb->Status = STATUS_NO_MORE_FILES;

				return STATUS_NO_MORE_FILES;
			}

			ExAcquireFastMutex( &pdx_cdo->MutexForGuardList );
			//first circle for calculate total size of data
			for( register ULONG i = 0; i < elem_count; i++ )
			{
				GetElementFromListByIndexUnsafe( i, &query_entry ); //danger
				ASSERT( query_entry );
				FileForHide = CONTAINING_RECORD( query_entry, FILE_FOR_HIDE, NextStruct );
				cbTargetBuf += FileForHide->FileName.Length + sizeof( WCHAR ); //null terminate for sz
			}

			cbTargetBuf += sizeof( WCHAR ); //null terminate for multi sz

			if( IoStack->Parameters.DeviceIoControl.OutputBufferLength < cbTargetBuf )
			{
				ExReleaseFastMutex( &pdx_cdo->MutexForGuardList );

				piosb->Information = 0;
				piosb->Status = STATUS_INFO_LENGTH_MISMATCH;

				return STATUS_INFO_LENGTH_MISMATCH;
			}

			OutBuffer = MmGetSystemAddressForMdlSafe( Mdl, NormalPagePriority );
			if( !OutBuffer )
			{
				ExReleaseFastMutex( &pdx_cdo->MutexForGuardList );

				piosb->Information = 0;
				piosb->Status = STATUS_INSUFFICIENT_RESOURCES;

				return STATUS_INSUFFICIENT_RESOURCES;
			}

			RtlZeroMemory( OutBuffer, cbTargetBuf );

			QueryStr = ( PWCHAR )OutBuffer;
			for( register ULONG i = 0; i < elem_count; i++ )
			{
				GetElementFromListByIndexUnsafe( i, &query_entry ); //danger
				ASSERT( query_entry );
				FileForHide = CONTAINING_RECORD( query_entry, FILE_FOR_HIDE, NextStruct );

				RtlCopyMemory( QueryStr, FileForHide->FileName.Buffer, 
					FileForHide->FileName.Length );

				QueryStr = 
					( PWCHAR )( ( PUCHAR )QueryStr + FileForHide->FileName.Length + sizeof( WCHAR ) );
			}

			ExReleaseFastMutex( &pdx_cdo->MutexForGuardList );

			MmUnmapLockedPages( OutBuffer, Mdl );

			piosb->Information = cbTargetBuf;
			piosb->Status = STATUS_SUCCESS;

			return STATUS_SUCCESS;
		}
	}
	KdPrint( ( "fsfltr!FsFltrpDispatchDeviceControl: Try call unimplemented service %08X\n",
		IoStack->Parameters.DeviceIoControl.IoControlCode ) );

	piosb->Information = 0;
	piosb->Status = STATUS_NOT_IMPLEMENTED;

	return STATUS_NOT_IMPLEMENTED;
}

/****************************************************************************/
/*  Function Name: GetCountElementsInListOfHideFiles                        */
/*  Section: PAGED                                                          */
/*  Description:                                                            */
/*  Return: count entrys in list of hide files                              */
/****************************************************************************/

ULONG
GetCountElementsInListOfHideFiles(
	 )
{
	PAGED_CODE(  );

	PDEVICE_EXTENSION_CDO pdx = ( PDEVICE_EXTENSION_CDO )
		FsFltrCDO->DeviceExtension;
	ULONG cEntryInList = 0;
	PLIST_ENTRY query_entry = NULL;

	ExAcquireFastMutex( &pdx->MutexForGuardList );

	for( query_entry = pdx->ListOfHideFiles.Flink; 
		 query_entry != &pdx->ListOfHideFiles;
		 query_entry = query_entry->Flink )
			cEntryInList++;

	ExReleaseFastMutex( &pdx->MutexForGuardList );

	return cEntryInList;
}

/****************************************************************************/
/*  Function Name: GetElementFromListByIndexUnsafe                                */
/*  Section: PAGED                                                          */
/*  Description: by index of element return ptr to list entry of element    */
/*  Return: TRUE if found, FALSE otherwise                                  */
/****************************************************************************/

BOOLEAN
GetElementFromListByIndexUnsafe(
	ULONG Index,
	LIST_ENTRY **FileForHide
	)
{
	PDEVICE_EXTENSION_CDO pdx = ( PDEVICE_EXTENSION_CDO )
		FsFltrCDO->DeviceExtension;
	ULONG QueryIndex = 0xFFFFFFFF;
	PLIST_ENTRY query_entry = NULL;

	PAGED_CODE(  );
	ASSERT( FileForHide );

	for( query_entry = pdx->ListOfHideFiles.Flink; 
		 query_entry != &pdx->ListOfHideFiles;
		 query_entry = query_entry->Flink )
	{
			if( Index == ++QueryIndex )
			{
				*FileForHide = query_entry;
				return TRUE;
			}
	}

	*FileForHide = NULL;
	return FALSE;
}

/****************************************************************************/
/*  Function Name: FsFltrDispatchFileSystemControl                          */
/*  Section: PAGED                                                          */
/*  Description: dispatch IRP_MJ_FILE_SYSTEM_CONTROL request                */
/*  Return: NT status                                                       */
/****************************************************************************/

NTSTATUS
FsFltrDispatchFileSystemControl(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp
	)
{
	PDEVICE_EXTENSION_FS_CDO fspdx = NULL;
	PIO_STACK_LOCATION IoStack = NULL;
	PDEVICE_OBJECT RealDevice = NULL;
	PDEVICE_OBJECT FsVolumeDev = NULL;
	KEVENT _event;
	PDEVICE_OBJECT SourceDevice = NULL;
	PDEVICE_EXTENSION pdx = NULL;
	CHAR VolLetter;
	NTSTATUS status = STATUS_SUCCESS;
	ULONG DiskIndex;
	
	PAGED_CODE(  );
	ASSERT( IS_MY_DEV_OBJ( DeviceObject ) );

	IoStack = IoGetCurrentIrpStackLocation( Irp );
	fspdx = ( PDEVICE_EXTENSION_FS_CDO ) DeviceObject->DeviceExtension;

	if( IS_MY_CTRL_DEV_OBJ( DeviceObject ) )
	{
		Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		Irp->IoStatus.Information = 0;

		IoCompleteRequest( Irp, IO_NO_INCREMENT );

		return STATUS_INVALID_DEVICE_REQUEST; 
	}

	if( IoStack->MinorFunction == IRP_MN_MOUNT_VOLUME )
	{
		KeInitializeEvent( &_event, NotificationEvent, FALSE );
		RealDevice = IoStack->Parameters.MountVolume.Vpb->RealDevice;
		
		IoCopyCurrentIrpStackLocationToNext( Irp );

		IoSetCompletionRoutine( Irp, 
			IoCompletionMount,
			&_event,
			TRUE,
			TRUE,
			FALSE );

		status = IoCallDriver( fspdx->NextDevInChain, Irp );

		if( status == STATUS_PENDING )
		{
			KeWaitForSingleObject( &_event, Executive, 
				KernelMode, FALSE, NULL );
			status = Irp->IoStatus.Status;
		}

		if( NT_SUCCESS( status ) && 
			KeReadStateEvent( &_event ) != 0 )
		{//mount complete
			FsVolumeDev = RealDevice->Vpb->DeviceObject;

			status = IoCreateDevice( FsFltrDriverObject,
				sizeof( DEVICE_EXTENSION ),
				NULL,
				FsVolumeDev->DeviceType,
				FsVolumeDev->Characteristics,
				FALSE,
				&SourceDevice );

			if( !NT_SUCCESS( status ) )
			{
				status = Irp->IoStatus.Status;
				IoCompleteRequest( Irp, IO_NO_INCREMENT );
				return status;
			}

			SetFlag( SourceDevice->Flags,
				FlagOn( FsVolumeDev->Flags,
				( DO_BUFFERED_IO | DO_DIRECT_IO ) ) );

			status = 
				GetDosDeviceNameByVolumeDeviceObject( RealDevice, &VolLetter );

			if( !NT_SUCCESS( status ) )
			{
				IoDeleteDevice( SourceDevice );

				status = Irp->IoStatus.Status;
				IoCompleteRequest( Irp, IO_NO_INCREMENT );
				return status;
			}

			pdx = ( PDEVICE_EXTENSION )SourceDevice->DeviceExtension;
			pdx->VolLetter = VolLetter;

			pdx->NextDevInChain = 
				IoAttachDeviceToDeviceStack( SourceDevice, FsVolumeDev );

			if( !pdx->NextDevInChain )
			{
				IoDeleteDevice( SourceDevice );

				status = Irp->IoStatus.Status;
				IoCompleteRequest( Irp, IO_NO_INCREMENT );
				return status;
			}

			ClearFlag( SourceDevice->Flags, DO_DEVICE_INITIALIZING );

			DiskIndex = VolLetter - 'A';
			ASSERT( !FlagOn( curDrivesToHookMask, 1 << DiskIndex ) );
			ASSERT( DriveHookDevicesTable[DiskIndex] == NULL );

			//update volume map
			SetFlag( curDrivesToHookMask, 1 << DiskIndex );
			DriveHookDevicesTable[DiskIndex] = SourceDevice;
			KdPrint( ( "FsFltr!FsFltrDispatchFileSystemControl: Successfully attach device to volume %c:\n",
				VolLetter ) );

			status = Irp->IoStatus.Status;
			IoCompleteRequest( Irp, IO_NO_INCREMENT );
			return status;
		}
		else
		{
			IoCompleteRequest( Irp, IO_NO_INCREMENT );
			return status;
		}
	}
	/*else if( IoStack->MinorFunction == IRP_MN_USER_FS_REQUEST &&
			 IoStack->Parameters.FileSystemControl.FsControlCode == FSCTL_DISMOUNT_VOLUME )
	{
		KeInitializeEvent( &_event, SynchronizationEvent, FALSE );

		IoSetCompletionRoutine( Irp, IoCompletionMount, &_event, 
			TRUE, TRUE, FALSE );

		status = IoCallDriver( fspdx->NextDevInChain, Irp );

		if( status == STATUS_PENDING )
		{
			KeWaitForSingleObject( &_event, Executive, KernelMode, FALSE, NULL );
			status = Irp->IoStatus.Status;
		}

		if( NT_SUCCESS( status ) &&
			KeReadStateEvent( &_event) != 0 )
		{ //dismount success
			DriveIndex = CheckDeviceInHookDeviceBuffer( DeviceObject );
			ASSERT( DriveIndex != 0xFFFFFFFF );

			IoDetachDevice(  );
			IoDeleteDevice( SourceDevice );

			ClearFlag( curDrivesToHookMask, 1 << DriveIndex );
			DriveHookDevicesTable[DriveIndex] = NULL;

			//KdPrint( ( "fsfltr!FsFltrFastIoDetachDevice: Successfully detach from %c:\n", 'A' + DriveIndex ) );
			__asm nop
			__asm nop
		}
	}*/
	else
	{
		IoSkipCurrentIrpStackLocation( Irp );
		return IoCallDriver( fspdx->NextDevInChain, Irp );
	}
}

/****************************************************************************/
/*  Function Name: IoCompletionMount                                        */
/*  Section: PAGED                                                          */
/*  Description: IO completion function for IRP_MJ_FILE_SYSTEM_CONTROL,     */
/*               mount request                                              */
/*  Return: NT status                                                       */
/****************************************************************************/

NTSTATUS
IoCompletionMount(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp,
	PVOID Context
	)
{
	PKEVENT pkevent;

	UNREFERENCED_PARAMETER( DeviceObject );
	UNREFERENCED_PARAMETER( Irp );

	ASSERT( Context );

	PAGED_CODE(  );

	pkevent = ( PKEVENT )Context;
	KeSetEvent( pkevent, IO_NO_INCREMENT, FALSE );

	return STATUS_MORE_PROCESSING_REQUIRED;
}

/****************************************************************************/
/*  Function Name: GetDosDeviceNameByVolumeDeviceObject                     */
/*  Section: PAGED                                                          */
/*  Description: by ptr to volume/(partition) device object return it letter*/
/*  Return: NT status                                                       */
/****************************************************************************/

NTSTATUS
GetDosDeviceNameByVolumeDeviceObject(
	PVOID VolumeDeviceObject,
	CHAR* pVolLetter
	)
{
	NTSTATUS status;
	UNICODE_STRING unDosName = { 0 };

	PAGED_CODE(  );
	ASSERT( VolumeDeviceObject );
	ASSERT( pVolLetter );

	if( KeGetCurrentIrql(  ) > PASSIVE_LEVEL )
	{
		return STATUS_UNSUCCESSFUL;
	}

	status = IoVolumeDeviceToDosName( VolumeDeviceObject, &unDosName );

	if( !NT_SUCCESS( status ) )
	{
		return status;
	}

	*pVolLetter = (CHAR)( unDosName.Buffer[0] );

	ExFreePool( unDosName.Buffer );

	return STATUS_SUCCESS;
}

/****************************************************************************/
/*  Function Name: CheckDeviceInHookDeviceBuffer                            */
/*  Section: PAGED                                                          */
/*  Description: by device object return index in DriveHookDevicesTable     */
/*  Return: index in DriveHookDevicesTable                                  */
/****************************************************************************/

ULONG
CheckDeviceInHookDeviceBuffer(
	PDEVICE_OBJECT DeviceObject
	)
{
	PAGED_CODE(  );

	for( register ULONG i = 0; i < MAX_DRIVES_FOR_HOOK; i++ )
	{
		if( DriveHookDevicesTable[i] == DeviceObject ) return i;
	}

	return -1;
}

/*
//is synchronous packet?
	if( Irp->ThreadListEntry.Flink == Irp->ThreadListEntry.Blink &&
		Irp->ThreadListEntry.Flink == &Irp->ThreadListEntry )
	{ //asynch
		return status;
	}
*/

/*NTSTATUS
FsFltrReadMBRSynch(
	)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING unPathToDR = { 0 };
	PWCHAR pwszPathToDR = L"\\Device\\Harddisk0\\DR0";
	PFILE_OBJECT FileObj = NULL;
	PDEVICE_OBJECT DevObj = NULL;
	PIRP Irp = NULL;
	PVOID pMbr = NULL;
	LARGE_INTEGER offset = { 0 };
	KEVENT notif_event = { 0 };
	IO_STATUS_BLOCK iosb = { 0 };

	RtlInitUnicodeString( &unPathToDR, pwszPathToDR );

	status = IoGetDeviceObjectPointer( &unPathToDR, FILE_READ_DATA, 
		&FileObj, &DevObj );

	if( !NT_SUCCESS( status ) ) return status;

	ObReferenceObject( DevObj );
	ObDereferenceObject( FileObj );

	pMbr = ExAllocatePoolWithTag( PagedPool, 512, '    ' );

	offset.QuadPart = 0;
	KeInitializeEvent( &notif_event, NotificationEvent, FALSE );

	Irp = IoBuildSynchronousFsdRequest( IRP_MJ_READ, DevObj,
		pMbr, 512, &offset, &notif_event, &iosb );

	if( !Irp ) 
	{
		ExFreePoolWithTag( pMbr, '    ' );
		ObDereferenceObject( DevObj );
		return STATUS_UNSUCCESSFUL;
	}

	status = IoCallDriver( DevObj, Irp );

	if( status == STATUS_PENDING )
	{
		KeWaitForSingleObject( &notif_event, Executive, 
			KernelMode, FALSE, NULL );
	}

	//some operations

	ExFreePoolWithTag( pMbr, '    ' );
	ObDereferenceObject( DevObj );

	return STATUS_SUCCESS;
}

NTSTATUS FsFltrReadMBRAsynch(
	)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING unPathToDR = { 0 };
	PWCHAR pwszPathToDR = L"\\Device\\Harddisk0\\DR0";
	PFILE_OBJECT FileObj = NULL;
	PDEVICE_OBJECT DevObj = NULL;
	PIRP Irp = NULL;
	PVOID pMbr = NULL;
	PIO_STACK_LOCATION IoStack = NULL;
	IO_STATUS_BLOCK iosb = { 0 };
	PMDL Mdl = NULL;
	LARGE_INTEGER offset = { 0 };
	KEVENT event_;
	struct {
		PKEVENT pkevent;
		PIO_STATUS_BLOCK iosb; } CompletionParameter;

	RtlInitUnicodeString( &unPathToDR, pwszPathToDR );

	status = IoGetDeviceObjectPointer( &unPathToDR, FILE_READ_DATA, 
		&FileObj, &DevObj );

	if( !NT_SUCCESS( status ) ) return status;

	pMbr = ExAllocatePoolWithTag( NonPagedPool, 4096, '    ' );

	Irp = IoAllocateIrp( DevObj->StackSize, FALSE );
	IoStack = IoGetNextIrpStackLocation( Irp );

	if( DevObj->Flags & DO_DIRECT_IO )
	{
		Mdl = IoAllocateMdl( pMbr, 4096, FALSE, FALSE, Irp );
		MmBuildMdlForNonPagedPool( Mdl );
	}

	KeInitializeEvent( &event_, NotificationEvent, FALSE );

	Irp->RequestorMode = KernelMode;
	Irp->Tail.Overlay.Thread = PsGetCurrentThread(  );
	Irp->UserIosb = &iosb;

	offset.QuadPart = 0;
	
	IoStack->DeviceObject = DevObj;
	IoStack->FileObject = FileObj;

	IoStack->MajorFunction = IRP_MJ_READ;
	IoStack->Parameters.Read.ByteOffset.QuadPart = offset.QuadPart;
	IoStack->Parameters.Read.Length = 512;

	CompletionParameter.pkevent = &event_;
	CompletionParameter.iosb = &iosb;

	IoSetCompletionRoutine( Irp, IoCompletionRead, &CompletionParameter, TRUE, TRUE, TRUE );

	status = IoCallDriver( DevObj, Irp );

	KeWaitForSingleObject( &event_, Executive, 
		KernelMode, FALSE, NULL );

	status = iosb.Status;
	ObDereferenceObject( FileObj );

	//manipulate with data

	ExFreePool( pMbr );

	return STATUS_SUCCESS;
}

NTSTATUS
IoCompletionRead(
	 PDEVICE_OBJECT DeviceObject,
	 PIRP Irp,
	 PVOID Context
	)
{
	struct PARAM {
		PKEVENT pkevent;
		PIO_STATUS_BLOCK iosb; 
	};

	UNREFERENCED_PARAMETER( DeviceObject );

	PARAM *pp = (PARAM*)Context;
	
	pp->iosb->Status = Irp->IoStatus.Status;
	pp->iosb->Information = Irp->IoStatus.Information;
	
	IoFreeMdl( Irp->MdlAddress );
	IoFreeIrp( Irp );

	KeSetEvent( pp->pkevent, IO_NO_INCREMENT, FALSE );

	return STATUS_MORE_PROCESSING_REQUIRED;
}*/



