
// Server.cpp

// Interfaces to the cServer class encapsulating the entire "server"

#include "Globals.h"
#include "Server.h"
#include "Connection.h"
#include "ServerConnection.h"
#include <iostream>
#include <csignal>


bool g_TERMINATE_EVENT_RAISED = false;



void NonCtrlHandler(int a_Signal)
{
	LOGD("Terminate event raised from std::signal");
	g_TERMINATE_EVENT_RAISED = true;

	switch (a_Signal)
	{
		case SIGSEGV:
		{
			std::signal(SIGSEGV, SIG_DFL);
			LOGERROR("  D:    | MCServer has encountered an error and needs to close");
			LOGERROR("Details | SIGSEGV: Segmentation fault");
			exit(EXIT_FAILURE);
		}
		case SIGABRT:
		#ifdef SIGABRT_COMPAT
		case SIGABRT_COMPAT:
		#endif
		{
			std::signal(a_Signal, SIG_DFL);
			LOGERROR("  D:    | MCServer has encountered an error and needs to close");
			LOGERROR("Details | SIGABRT: Server self-terminated due to an internal fault");
			exit(EXIT_FAILURE);
		}
		case SIGINT:
		case SIGTERM:
		{
			std::signal(a_Signal, SIG_IGN); // Server is shutting down, wait for it...
			break;
		}
		default: break;
	}
}





cServer::cServer(void) :
	m_ListenThread(*this, cSocket::IPv4, "Client IPv4"),
	m_bStop(false)
{
}





cServer::~cServer(void)
{
	cLogger::GetInstance()->ResetColor();
}





void cServer::InputThread(void * a_Params)
{
	cServer & self = *(cServer*)a_Params;

	while (!self.m_bStop && !g_TERMINATE_EVENT_RAISED && std::cin.good())
	{
		AString Command;
		std::getline(std::cin, Command);
		if (!Command.empty())
		{
			self.ExecuteConsoleCommand(TrimString(Command));
		}
	}

	if (g_TERMINATE_EVENT_RAISED || !std::cin.good())
	{
		// We have come here because the std::cin has received an EOF / a terminate signal has been sent, and the server is still running; stop the server:
		self.m_bStop = true;
	}
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





void cServer::Start(void)
{
	m_InputThread = new cThread(InputThread, this, "cServer::InputThread");
	m_InputThread->Start(false);

	while (!m_bStop)
	{
		if (g_TERMINATE_EVENT_RAISED)
		{
			m_bStop = true;
		}
	}
}





void cServer::ExecuteConsoleCommand(const AString & a_Cmd)
{
	AStringVector split = StringSplit(a_Cmd, " ");
	if (split.empty())
	{
		return;
	}

	if (split[0].compare("stop") == 0)
	{
		m_bStop = true;
		return;
	}
	
	LOGWARN("Unknown command");
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




