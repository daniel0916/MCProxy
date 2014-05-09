
// Server.h

// Interfaces to the cServer class encapsulating the entire "server"





#pragma once

#include "SocketThreads.h"
#include "Connection.h"
#include "Server.h"






class cServerConnection
	: public cSocketThreads::cCallback
{
public :

	cServerConnection(cConnection * a_ClientConnection, cServer & a_Server);

	cConnection * m_ClientConnection;
	cServer & m_Server;
	bool m_ShouldSend;

	// cSocketThreads::cCallback overrides:
	virtual void DataReceived(const char * a_Data, size_t a_Size) override;  // Data is received from the client
	virtual void GetOutgoingData(AString & a_Data) override;  // Data can be sent to client
	virtual void SocketClosed(void) override;  // The socket has been closed for any reason
};