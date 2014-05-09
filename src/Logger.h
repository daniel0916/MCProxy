
// Logger.h





#pragma once


class cLogger
{
public:

	enum eLogLevel
	{
		llRegular,
		llInfo,
		llWarning,
		llError,
	};

	cLogger(void);

	void Log(const char * a_Format, va_list a_ArgList, eLogLevel a_LogLevel);

	void SetColor(eLogLevel a_LogLevel);
	void ResetColor(void);

	static cLogger * GetInstance();

private:

	static cLogger * s_Logger;

};





extern void LOG(const char* a_Format, ...);
extern void LOGINFO(const char* a_Format, ...);
extern void LOGWARNING(const char* a_Format, ...);
extern void LOGERROR(const char* a_Format, ...);




