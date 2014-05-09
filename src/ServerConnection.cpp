
// Server.cpp

// Interfaces to the cServer class encapsulating the entire "server"

#include "Globals.h"
#include "ServerConnection.h"





cServerConnection::cServerConnection(cConnection * a_ClientConnection, cServer & a_Server) :
	m_ClientConnection(a_ClientConnection),
	m_Server(a_Server),
	m_ShouldSend(true)
{
}





void cServerConnection::DataReceived(const char * a_Data, size_t a_Size)
{
	if (m_ShouldSend)
	{
		m_ClientConnection->SendToClient(a_Data, a_Size);
	}
}





void cServerConnection::GetOutgoingData(AString & a_Data)
{
}





void cServerConnection::SocketClosed(void)
{
	m_Server.m_SocketThreads.RemoveClient(this);
	m_Server.m_SocketThreads.RemoveClient(m_ClientConnection);
}

