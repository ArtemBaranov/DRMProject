///////////////////////////////////////////////////////////////////////////////
//
//	File System filter driver project file
//
//	fsfltr.h - declare structs, macros for driver
//
//		Author:		Baranov Artem
//		Creation date:	11.03.2008
//		Last modify:	11.03.2008
//
//
///////////////////////////////////////////////////////////////////////////////

#define VALID_FAST_IO_DISPATCH_HANDLER(_FastIoDispatchPtr, _FieldName) \
    (((_FastIoDispatchPtr) != NULL) && \
     (((_FastIoDispatchPtr)->SizeOfFastIoDispatch) >= \
            (FIELD_OFFSET(FAST_IO_DISPATCH, _FieldName) + sizeof(void *))) && \
     ((_FastIoDispatchPtr)->_FieldName != NULL))

//supported device type for attach to CDO of file system
#define IS_SUPPORTED_DEVICE_TYPE(_type) \
    (((_type) == FILE_DEVICE_DISK_FILE_SYSTEM) || \
     ((_type) == FILE_DEVICE_CD_ROM_FILE_SYSTEM))



//device extension of attached device
typedef struct _DEVICE_EXTENSION
{
	PDEVICE_OBJECT NextDevInChain;
	CHAR VolLetter;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

typedef struct _DEVICE_EXTENSION_CDO
{
	LIST_ENTRY ListOfHideFiles;
	FAST_MUTEX MutexForGuardList;
	KSEMAPHORE SemGuardPendingCreate;
	LIST_ENTRY ListOfPendingCreate;
	KSPIN_LOCK LockGuardPendingCreate;
	FILE_PENDING_FINAL_STATUS ReceivedStatus;
	KEVENT SynchEvent;
	KEVENT CancelIrpEvent;
	LIST_ENTRY ListOfTrustedProcesses;
	FAST_MUTEX MutexGuardListOfTrustedProc;
} DEVICE_EXTENSION_CDO, *PDEVICE_EXTENSION_CDO;

typedef struct _DEVICE_EXTENSION_FS_CDO
{
	PDEVICE_OBJECT NextDevInChain;
} DEVICE_EXTENSION_FS_CDO, *PDEVICE_EXTENSION_FS_CDO;

typedef struct _TRUSTED_PROCESS
{
	LIST_ENTRY Next;
	HANDLE Pid;
} TRUSTED_PROCESS, *PTRUSTED_PROCESS;

typedef struct _FILE_FOR_HIDE
{
	LIST_ENTRY NextStruct;
	UNICODE_STRING FileName;
	ULONG ChkSumOfName;
} FILE_FOR_HIDE, *PFILE_FOR_HIDE;

//struct describe request to query this file in user mode
typedef struct _FILE_PENDING_CREATE
{
	LIST_ENTRY NextStruct;
	PKEVENT SynchEvent; //event set in StartIO where request was dispatched
	PFILE_PENDING_FINAL_STATUS FinalStatus; //final status of operation
	UNICODE_STRING FileName; //created file name
	_PENDING_FILE_INFORMATION::INTERNAL::REQUESTOR Requestor;
	CLIENT_ID Cid;
	PENDING_FILE_INFORMATION::DISPOSITION CreateDisposition;
} FILE_PENDING_CREATE, *PFILE_PENDING_CREATE;

typedef struct _DEVOBJ_EXTENSION_UNDOC {

    CSHORT          Type;
    USHORT          Size;

    //
    // Public part of the DeviceObjectExtension structure
    //

    PDEVICE_OBJECT  DeviceObject;               // owning device object

	//
	// Private part (has been copied from XP SP2)
	//

	ULONG PowerFlags;
	PVOID Dope; //PDEVICE_OBJECT_POWER_EXTENSION
	ULONG ExtensionFlags;
	PVOID DeviceNode;
	PDEVICE_OBJECT AttachedTo;
	ULONG StartIoCount;
	ULONG StartIoKey;
	ULONG StartIoFlags;
	PVPB Vpb;

} DEVOBJ_EXTENSION_UNDOC, *PDEVOBJ_EXTENSION_UNDOC;


#define FS_FLTR_STD_TAG 'lfsF' //Fsfl
#define FS_FLTR_FAST_IO_TAG 'afsF' //Fsfa

#define MAX_DRIVES_FOR_HOOK 32

#define DRIVE_UNKNOWN		0
#define DRIVE_NO_ROOT_DIR	1
#define DRIVE_REMOVABLE		2
#define DRIVE_FIXED			3
#define DRIVE_REMOTE		4
#define DRIVE_CDROM			5
#define DRIVE_RAMDISK		6