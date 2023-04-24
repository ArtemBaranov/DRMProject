///////////////////////////////////////////////////////////////////////////////
//
//	Client DLL of filter driver project file
//
//	kbdhook.h - contain functions, structs declaration for client program
//
//		Author:		Baranov Artem
//		Creation date:	??.??.????
//		Last modify:	??.??.????
//
//
///////////////////////////////////////////////////////////////////////////////

#pragma once

#ifndef KBD_HOOK_API

#define KBD_HOOK_API __declspec(dllimport)

#endif

typedef enum _LOG_MODE 
{
	Raw,
	Text 
} LOG_MODE;

/*
Function: InitKbdHook.

Description: client call function after is successfully executed DllMain. 
Function prepares the driver for work and starts monitoring the keyboard
with write in a file, a full way to which it is set. The log file is created,
thus if the file exists, it is rewritten by a new file.

Returned values: 1 if the driver is successfully prepared to work, 0 otherwise.
To get extended error information, call GetLastError.
*/

KBD_HOOK_API BOOL __stdcall InitKbdHook( IN LPCWSTR pwszLogFileName, LOG_MODE LogMode );

/*
Function: StartLog

Description: 
The client call function after successful execute of function InitKbdHook.
Function carries out start of monitoring of the keyboard with the subsequent 
recording ASCII-codes in a log file.

Returned values: 1 if the log start success, 0 otherwise.
To get extended error information, call GetLastError.
*/

KBD_HOOK_API BOOL __stdcall StartLog(  );

/*
Function: StopLog

Description: 
The client call function after successful execute StartLog function.
Function stops writing codes in a file.

Returned values: 1 if the log stop success, 0 otherwise.
To get extended error information, call GetLastError.
*/

KBD_HOOK_API BOOL __stdcall StopLog(  );

/*
Function: StopLog

Description: 
The client call function after successful execute StopLog function.
Function uninitializing driver, closes log file.

Returned values: 1 if the log stop success, 0 otherwise.
To get extended error information, call GetLastError.
*/

KBD_HOOK_API BOOL __stdcall UnInitKbdHook(  );