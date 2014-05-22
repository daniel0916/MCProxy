
// Server.h

// Interfaces to the cServer class encapsulating the entire "server"





#pragma once

#include "SocketThreads.h"
#include "ListenThread.h"
#include "PolarSSL++/RsaPrivateKey.h"
#include "inifile/iniFile.h"
#include "Authenticator.h"
#include "Connection.h"





typedef std::list<cConnection *> cConnectionList;





class cServer
	: public cListenThread::cCallback
{
	SOCKET m_ListenSocket;
	
public:
	cServer(void);
	~cServer(void);
	static cServer * Get() { return s_Server; }
	
	int Init(void);
	void Start(void);
	
	cRsaPrivateKey & GetPrivateKey(void) { return m_PrivateKey; }
	const AString & GetPublicKeyDER (void) { return m_PublicKeyDER; }
	void AuthenticateUser(const AString & a_Name, const AString & a_UUID);
	void KickUser(const AString & a_Name, const AString & a_Reason);

	AString GenerateOfflineUUID(const AString & a_Username);

	cSocketThreads m_SocketThreads;

	cIniFile m_Config;
	AString m_MainServerAddress;
	int m_MainServerPort;
	AString m_MainServerName;
	int m_ListenPort;
	AString m_MOTD;
	int m_MaxPlayers;
	int m_PlayerAmount;
	AString m_FaviconData;
	bool m_ShouldAuthenticate;

	cRsaPrivateKey m_PrivateKey;
	AString m_PublicKeyDER;
	AString m_ServerID;
	cAuthenticator m_Authenticator;

	cConnectionList m_Connections;

private:

	static cServer*	s_Server;

	cThread * m_InputThread;
	bool m_bStop;
	static void InputThread(void* a_Params);
	void ExecuteConsoleCommand(const AString & a_Cmd);

	cListenThread m_ListenThread;

	// cListenThread::cCallback overrides:
	virtual void OnConnectionAccepted(cSocket & a_Socket) override;

} ;




