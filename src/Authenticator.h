
// cAuthenticator.h

// Interfaces to the cAuthenticator class representing the thread that authenticates users against the official MC server
// Authentication prevents "hackers" from joining with an arbitrary username (possibly impersonating the server admins)
// For more info, see http://wiki.vg/Session#Server_operation
// In MCS, authentication is implemented as a single thread that receives queued auth requests and dispatches them one by one.





#pragma once
#ifndef CAUTHENTICATOR_H_INCLUDED
#define CAUTHENTICATOR_H_INCLUDED

#include "IsThread.h"





// fwd: "cRoot.h"
class cRoot;





class cAuthenticator :
	public cIsThread
{
	typedef cIsThread super;

public:
	cAuthenticator(void);
	~cAuthenticator();

	/** Queues a request for authenticating a user. If the auth fails, the user will be kicked */
	void Authenticate(const AString & a_UserName, const AString & a_ServerHash);

	/** Starts the authenticator thread. The thread may be started and stopped repeatedly */
	void Start();

	/** Stops the authenticator thread. The thread may be started and stopped repeatedly */
	void Stop(void);

private:

	class cUser
	{
	public:
		AString m_Name;
		AString m_ServerID;

		cUser(const AString & a_Name, const AString & a_ServerID) :
			m_Name(a_Name),
			m_ServerID(a_ServerID)
		{
		}
	};

	typedef std::deque<cUser> cUserList;

	cCriticalSection m_CS;
	cUserList        m_Queue;
	cEvent           m_QueueNonempty;

	AString m_Server;
	AString m_Address;
	bool    m_ShouldAuthenticate;

	/** cIsThread override: */
	virtual void Execute(void) override;

	/** Returns true if the user authenticated okay, false on error; iLevel is the recursion deptht (bails out if too deep) */
	bool AuthWithYggdrasil(AString & a_UserName, const AString & a_ServerId, AString & a_UUID);
};





#endif  // CAUTHENTICATOR_H_INCLUDED




