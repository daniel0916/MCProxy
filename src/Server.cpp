
// Server.cpp

// Interfaces to the cServer class encapsulating the entire "server"

#include "Globals.h"
#include "Server.h"
#include "Connection.h"
#include "ServerConnection.h"





cServer::cServer(void) :
	m_ListenThread(*this, cSocket::IPv4, "Client IPv4")
{
}





cServer::~cServer(void)
{
	cLogger::GetInstance()->ResetColor();
}





int cServer::Init(short a_ListenPort, short a_ConnectPort)
{
	m_ConnectPort = a_ConnectPort;

	#ifdef _WIN32
		WSAData wsa;
		int res = WSAStartup(0x0202, &wsa);
		if (res != 0)
		{
			LOGERROR("Cannot initialize WinSock: %d", res);
			return res;
		}
	#endif  // _WIN32

	LOGINFO("Generating protocol encryption keypair...");
	m_PrivateKey.Generate();
	m_PublicKeyDER = m_PrivateKey.GetPubKeyDER();

	m_ListenThread.SetReuseAddr(true);
	if (!m_ListenThread.Initialize("25564"))
	{
		return 1;
	}
	if (!m_ListenThread.Start())
	{
		return 1;
	}

	return 0;
}





void cServer::OnConnectionAccepted(cSocket & a_Socket)
{
	SOCKET ServerSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (ServerSocket == INVALID_SOCKET)
	{
		return;
	}

	cSocket Socket = cSocket(ServerSocket);
	if (!Socket.ConnectIPv4("localhost", 25565))
	{
		return;
	}

	cConnection * Connection = new cConnection(a_Socket, Socket, *this);
	cServerConnection * Server = new cServerConnection(Connection, *this);
	Connection->m_ServerConnection = Server;

	m_SocketThreads.AddClient(Socket, Server);
	m_SocketThreads.AddClient(a_Socket, Connection);
}




