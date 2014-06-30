
// Logger.cpp

#include "Globals.h"




cLogger * cLogger::s_Logger = NULL;

#ifdef _WIN32
	#include <io.h>  // Needed for _isatty(), not available on Linux

	HANDLE g_Console = GetStdHandle(STD_OUTPUT_HANDLE);
	WORD g_DefaultConsoleAttrib = 0x07;
#elif defined (__linux) && !defined(ANDROID_NDK)
	#include <unistd.h>  // Needed for isatty() on Linux
#endif





cLogger::cLogger(void)
{
	s_Logger = this;
}





cLogger * cLogger::GetInstance(void)
{
	return s_Logger;
}





void cLogger::Log(const char * a_Format, va_list a_ArgList, eLogLevel a_LogLevel)
{
	AString Message;
	AppendVPrintf(Message, a_Format, a_ArgList);
	SetColor(a_LogLevel);
	printf("%s\n", Message.c_str());
	ResetColor();
}





void cLogger::SetColor(eLogLevel a_LogLevel)
{
	#ifdef _WIN32
		WORD Attrib = 0x07;  // by default, gray on black
		switch (a_LogLevel)
		{
			case llRegular: Attrib = 0x07; break;  // Gray on black
			case llInfo:    Attrib = 0x0e; break;  // Yellow on black
			case llWarning: Attrib = 0x0c; break;  // Read on black
			case llError:   Attrib = 0xc0; break;  // Black on red
			default: ASSERT(!"Unhandled color scheme");
		}
		SetConsoleTextAttribute(g_Console, Attrib);
	#elif defined(__linux)
		switch (a_LogLevel)
		{
			case llRegular: printf("\x1b[0m");         break;  // Whatever the console default is
			case llInfo:    printf("\x1b[33;1m");      break;  // Yellow on black
			case llWarning: printf("\x1b[31;1m");      break;  // Red on black
			case llError:   printf("\x1b[1;33;41;1m"); break;  // Yellow on red
			default: ASSERT(!"Unhandled color scheme");
		}
	#endif
}





void cLogger::ResetColor(void)
{
	#ifdef _WIN32
		SetConsoleTextAttribute(g_Console, g_DefaultConsoleAttrib);
	#elif defined(__linux) && !defined(ANDROID_NDK)
		printf("\x1b[0m");
	#endif
}





//////////////////////////////////////////////////////////////////////////
// Global functions

void LOG(const char* a_Format, ...)
{
	va_list argList;
	va_start(argList, a_Format);
	cLogger::GetInstance()->Log(a_Format, argList, cLogger::llRegular);
	va_end(argList);
}

void LOGINFO(const char* a_Format, ...)
{
	va_list argList;
	va_start(argList, a_Format);
	cLogger::GetInstance()->Log(a_Format, argList, cLogger::llInfo);
	va_end(argList);
}

void LOGWARNING(const char* a_Format, ...)
{
	va_list argList;
	va_start(argList, a_Format);
	cLogger::GetInstance()->Log(a_Format, argList, cLogger::llWarning);
	va_end(argList);
}

void LOGERROR(const char* a_Format, ...)
{
	va_list argList;
	va_start(argList, a_Format);
	AString Message;
	cLogger::GetInstance()->Log(a_Format, argList, cLogger::llError);
	va_end(argList);
}
