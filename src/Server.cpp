
// Server.cpp

// Interfaces to the cServer class encapsulating the entire "server"

#include "Globals.h"
#include "Server.h"
#include "Connection.h"
#include "ServerConnection.h"
#include "File.h"
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
			LOGERROR("  D:    | MCProxy has encountered an error and needs to close");
			LOGERROR("Details | SIGSEGV: Segmentation fault");
			exit(EXIT_FAILURE);
		}
		case SIGABRT:
		#ifdef SIGABRT_COMPAT
		case SIGABRT_COMPAT:
		#endif
		{
			std::signal(a_Signal, SIG_DFL);
			LOGERROR("  D:    | MCProxy has encountered an error and needs to close");
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
	m_bStop(false),
	m_MainServerAddress("localhost"),
	m_MainServerPort(25565),
	m_MOTD("MCProxy - A Minecraft Proxy Server"),
	m_MaxPlayers(100),
	m_PlayerAmount(0)
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





int cServer::Init(void)
{
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

	LOGINFO("Loading config...");
	if (!m_Config.ReadFile("config.ini"))
	{
		m_Config.SetValueI("Proxy", "ListenPort", 25565);
		m_Config.SetValue("Proxy", "MainServer", "Lobby");
		m_Config.SetValueI("Proxy", "MaxPlayers", 100);
		m_Config.SetValue("Proxy", "MOTD", "MCProxy - A Minecraft Proxy Server");
		m_Config.SetValue("Servers", "Lobby", "localhost:25566");
		m_Config.WriteFile("config.ini");
	}

	int ListenPort = m_Config.GetValueI("Proxy", "ListenPort");
	if (ListenPort == NULL)
	{
		LOGWARN("ListenPort is wrong");
		return 1;
	}

	AString ServerName = m_Config.GetValue("Proxy", "MainServer");
	AString ServerConfig = m_Config.GetValue("Servers", ServerName);
	if (ServerConfig.empty())
	{
		LOGWARN("Can't load MainServer from config");
		return 1;
	}
	AStringVector ServerData = StringSplit(ServerConfig, ":");
	m_MainServerAddress = ServerData[0];
	m_MainServerPort = atoi(ServerData[1].c_str());

	m_MOTD = m_Config.GetValue("Proxy", "MOTD");
	m_MaxPlayers = m_Config.GetValueI("Proxy", "MaxPlayers");

	LOGINFO("Loading favicon...");
	m_FaviconData = Base64Encode(cFile::ReadWholeFile(FILE_IO_PREFIX + AString("favicon.png")));
	LOGINFO(m_FaviconData.c_str());

	m_ListenThread.SetReuseAddr(true);
	if (!m_ListenThread.Initialize(Printf("%i", ListenPort)))
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
	if (!Socket.ConnectIPv4(m_MainServerAddress, m_MainServerPort))
	{
		return;
	}

	cConnection * Connection = new cConnection(a_Socket, Socket, *this);
	cServerConnection * Server = new cServerConnection(Connection, *this);
	Connection->m_ServerConnection = Server;

	m_SocketThreads.AddClient(Socket, Server);
	m_SocketThreads.AddClient(a_Socket, Connection);
}




