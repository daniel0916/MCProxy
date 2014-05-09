
// ProtoProxy.cpp

// Implements the main app entrypoint

#include "Globals.h"
#include "Server.h"





int main(int argc, char ** argv)
{
	cServer Server;
	int res = Server.Init();
	if (res != 0)
	{
		LOGERROR("Server initialization failed: %d", res);
		return res;
	}

	Server.Start();
	
	return 0;
}




