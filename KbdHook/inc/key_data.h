#define KERNEL_EVENT_NAME L"\\BaseNamedObjects\\KEventForKbdHook"
#define USER_EVENT_NAME L"\\BaseNamedObjects\\UEventForKbdHook"

typedef struct _KEY
{
	USHORT ScanCode; //scan code
	USHORT CapsLockOn; //1 if caps lock was on
	USHORT ShiftPressed; //1 if shift was pressed, 0 - otherwise
} KEY, *PKEY;

typedef struct _FOR_INIT_KBD_HOOK
{
	PVOID StartVA;
	ULONG Size;
} FOR_INIT_KBD_HOOK, *PFOR_INIT_KBD_HOOK;

#define IOCTL_KBD_HOOK_INIT CTL_CODE( FILE_DEVICE_UNKNOWN, 0x999, METHOD_BUFFERED, \
	FILE_READ_DATA | FILE_WRITE_DATA )

#define IOCTL_KBD_HOOK_UNINIT CTL_CODE( FILE_DEVICE_UNKNOWN, 0x998, METHOD_BUFFERED, \
	FILE_READ_DATA )

#define IOCTL_KBD_HOOK_START CTL_CODE( FILE_DEVICE_UNKNOWN, 0x997, METHOD_BUFFERED, \
	FILE_READ_DATA )

#define IOCTL_KBD_HOOK_STOP CTL_CODE( FILE_DEVICE_UNKNOWN, 0x996, METHOD_BUFFERED, \
	FILE_READ_DATA )