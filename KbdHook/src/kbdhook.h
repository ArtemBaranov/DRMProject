///////////////////////////////////////////////////////////////////////////////
//
//	Keyboard filter driver project file
//
//	kbdhook.h - declare structs, macros for driver
//
//		Author:		Baranov Artem
//		Creation date:	??.??.????
//		Last modify:	??.??.????
//
//
///////////////////////////////////////////////////////////////////////////////

#pragma once

typedef struct _DEVICE_EXTENSION
{
	LIST_ENTRY ChListHead; //characters list head
	KSEMAPHORE SemForGuardQueue; //semaphore that guard characters list
	KSPIN_LOCK LockForList; //spin lock that guard all operation for list
	PVOID pThread; //ptr to thread, that write data in shared memory
	PKEVENT pEventK; //ptr to event that set driver when driver has copied data
	PKEVENT pEventU; //ptr to event that set DLL when data have been read
	PDEVICE_OBJECT NextDevInChain; //ptr to next lower device
	NPAGED_LOOKASIDE_LIST  LookasideList; //memory for KBD_DATA entry
	KEVENT NeedThreadTerminate; //set driver when log thread must be terminate
	ULONG Caps_Lock; //if caps lock on than set in 1, otherwise 0
	ULONG ShiftPressed; //if shift key pressed
	PMDL MdlOfBufferForLog; //MDL describe shared memory
	PVOID BufferForLog; //ptr to shared mem
	ULONG numCachedEntry; //number entry that stored in list
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

typedef struct _KBD_DATA
{
	LIST_ENTRY NextStruct;
	USHORT MakeCode; //scan code
	USHORT CapsLockOn; //1 if caps lock was on
	USHORT ShiftPressed; //1 if shift was pressed, 0 - otherwise
} KBD_DATA, *PKBD_DATA;

#define DRMPRINT( mes ) DbgPrint( "DRM, 1: %s\n", mes ) //output messages in all builds
#define DRMKDPRINT( mes ) KdPrint(( "DRM, 1: %s\n", mes )) //output messages in checked build

#define KEY_CAPS_LOCK_CODE 0x3A // scan code of caps lock key
#define KEY_SHIFT_CODE 0x2A //scan code of shift key
#define KEY_CTRL_CODE 0x1D //scan code of ctrl key
#define KEY_ALT_CODE 0x38 //scan code of alt key

#define MAX_CACHED_ENTRY 0xFF //number entry that may be stored in list