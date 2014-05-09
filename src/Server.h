
// Server.h

// Interfaces to the cServer class encapsulating the entire "server"





#pragma once

#include "SocketThreads.h"
#include "ListenThread.h"
#include "PolarSSL++/RsaPrivateKey.h"
#include "inifile\iniFile.h"






class cServer
	: public cListenThread::cCallback
{
	SOCKET m_ListenSocket;
	cRsaPrivateKey m_PrivateKey;
	AString m_PublicKeyDER;
	short m_ConnectPort;
	
public:
	cServer(void);
	~cServer(void);
	
	int Init(void);
	void Start(void);
	
	cRsaPrivateKey & GetPrivateKey(void) { return m_PrivateKey; }
	const AString & GetPublicKeyDER (void) { return m_PublicKeyDER; }
	
	short GetConnectPort(void) const { return m_ConnectPort; }

	cSocketThreads m_SocketThreads;

	cIniFile m_Config;
	AString m_MainServerAddress;
	int m_MainServerPort;

private:

	cThread * m_InputThread;
	bool m_bStop;
	static void InputThread(void* a_Params);
	void ExecuteConsoleCommand(const AString & a_Cmd);

	cListenThread m_ListenThread;

	// cListenThread::cCallback overrides:
	virtual void OnConnectionAccepted(cSocket & a_Socket) override;

} ;




