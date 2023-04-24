#include <stdio.h>
#include <windows.h>
#include <kbdhook.h>

#pragma comment(linker, "/DEFAULTLIB:kbdhookdll.lib")

void main()
{
	InitKbdHook( L"C:\\1.txt", Text );
	StopLog(  );
	StartLog(  );

	StopLog(  );
	UnInitKbdHook(  );
}