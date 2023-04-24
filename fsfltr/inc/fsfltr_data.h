#define IOCTL_FSFLTR_ADD_FILES CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x801, METHOD_IN_DIRECT, \
	FILE_WRITE_DATA )

#define IOCTL_FSFLTR_REMOVE_FILES CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x802, METHOD_IN_DIRECT, \
	FILE_WRITE_DATA )

#define IOCTL_FSFLTR_QUERY_FILES CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x803, METHOD_OUT_DIRECT, \
	FILE_READ_DATA )

#define IOCTL_LISTEN_CREATE_REQUEST CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x804 , METHOD_BUFFERED, \
	FILE_READ_DATA )

#define IOCTL_LISTEN_CREATE_REPLY CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x805 , METHOD_BUFFERED, \
	FILE_WRITE_DATA )

#define IOCTL_START_AVX CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x806, METHOD_BUFFERED, \
	FILE_READ_DATA )

#define IOCTL_STOP_AVX CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x807, METHOD_BUFFERED, \
	FILE_READ_DATA )

#define IOCTL_ADD_TRUSTED_PROCESSES CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x808 , METHOD_BUFFERED, \
	FILE_WRITE_DATA )

#define IOCTL_REMOVE_TRUSTED_PROCESSES CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x809 , METHOD_BUFFERED, \
	FILE_WRITE_DATA )

#define IOCTL_QUERY_TRUSTED_PROCESSES CTL_CODE( FILE_DEVICE_DISK_FILE_SYSTEM, 0x80A , METHOD_BUFFERED, \
	FILE_READ_DATA )

//enum describe status for completed _FILE_PENDING_CREATE request
typedef enum _FILE_PENDING_FINAL_STATUS
{
	Enabled, // function that dispatch IRP_MJ_CREATE return success status
	Denied //function that dispatch IRP_MJ_CREATE return access denied 
} FILE_PENDING_FINAL_STATUS, *PFILE_PENDING_FINAL_STATUS;

#ifndef _NTDDK_

	typedef struct _CLIENT_ID {
		HANDLE UniqueProcess;
		HANDLE UniqueThread;
	} CLIENT_ID;

#endif

#pragma pack( push,2 )
typedef struct _PENDING_FILE_INFORMATION
{
	struct INTERNAL {
		enum REQUESTOR { IrpMjCreate, FastIoQueryOpen } RequestorId;
	} Internal;
	CLIENT_ID Cid;
	enum DISPOSITION { 
		FileSupersede, //if exists, replace; if does not exist, create
		FileOpen, //if exists, open; if does not exist, error
		FileCreate, //if exists, error; if does not exist, create
		FileOpenIf,//if exists, open; if does not exist, create
		FileOverwrite,//if exists, open and overwrite; if does not exist, error
		FileOverwriteIf //if exists, open and overwrite; if does not exist, create
	} CreateDisposition;
	ULONG cbFile;
	WCHAR FileName[1];
} PENDING_FILE_INFORMATION, *PPENDING_FILE_INFORMATION;
#pragma pack( pop )