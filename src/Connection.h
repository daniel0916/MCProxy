
// Connection.h

// Interfaces to the cConnection class representing a single pair of connected sockets





#pragma once

#include "ByteBuffer.h"
#include "Timer.h"
#include "SocketThreads.h"
#include "PolarSSL++/AesCfb128Decryptor.h"
#include "PolarSSL++/AesCfb128Encryptor.h"





class cProtocol172;
class cServer;
class cServerConnection;





class cConnection :
	public cSocketThreads::cCallback
{
public:
	cConnection(cSocket a_ClientSocket, cSocket a_ServerSocket, cServer & a_Server);
	~cConnection();

	bool SendToClient(const char * a_Data, size_t a_Size);

	void Kick(AString a_Reason);
	void Authenticate(AString a_Name, AString a_UUID);

	cServerConnection * m_ServerConnection;
	cServerConnection * m_OldServerConnection;

	AString m_UserName;
	AString m_UUID;

	cServer & m_Server;

	cSocket m_ClientSocket;
	cSocket m_ServerSocket;

	cByteBuffer m_ClientBuffer;
	cByteBuffer m_ServerBuffer;

	cAesCfb128Decryptor m_ServerDecryptor;
	cAesCfb128Encryptor m_ServerEncryptor;

	cAesCfb128Decryptor m_ClientDecryptor;
	cAesCfb128Encryptor m_ClientEncryptor;

	AString m_ServerEncryptionBuffer;  // Buffer for the data to be sent to the server once encryption is established
	AString m_ClientEncryptionBuffer;  // Buffer for the data to be sent to the client once encryption is established

	/// True if the server connection has provided encryption keys
	bool m_IsServerEncrypted;

	/// True if the client connection has provided encryption keys
	bool m_IsClientEncrypted;

	/// Sends data to the specified socket. If sending fails, prints a fail message using a_Peer and returns false.
	bool SendData(cSocket a_Socket, const char * a_Data, size_t a_Size, const char * a_Peer);

	/// Sends data to the specified socket. If sending fails, prints a fail message using a_Peer and returns false.
	bool SendData(cSocket a_Socket, cByteBuffer & a_Data, const char * a_Peer);

	/// Sends data to the specfied socket, after encrypting it using a_Encryptor. If sending fails, prints a fail message using a_Peer and returns false
	bool SendEncryptedData(cSocket a_Socket, cAesCfb128Encryptor & a_Encryptor, const char * a_Data, size_t a_Size, const char * a_Peer);

	/// Sends data to the specfied socket, after encrypting it using a_Encryptor. If sending fails, prints a fail message using a_Peer and returns false
	bool SendEncryptedData(cSocket a_Socket, cAesCfb128Encryptor & a_Encryptor, cByteBuffer & a_Data, const char * a_Peer);

	enum eConnectionState
	{
		csUnencrypted,           // The connection is not encrypted. Packets must be decoded in order to be able to start decryption.
		csEncryptedUnderstood,   // The communication is encrypted and so far all packets have been understood, so they can be still decoded
		csEncryptedUnknown,      // The communication is encrypted, but an unknown packet has been received, so packets cannot be decoded anymore
		csWaitingForEncryption,  // The communication is waiting for the other line to establish encryption
	};

	eConnectionState m_ClientState;
	eConnectionState m_ServerState;

	void StartEncryption(const Byte * a_Key);
	AString m_AuthServerID;

	bool m_SwitchServer;
	void SwitchServer(AString a_ServerAddress, short a_ServerPort);
	AString m_NewServerName;
        
        bool m_AlreadyCountPlayer;
	bool m_AlreadyRemovedPlayer;
        
        bool m_SendedHandshake;
	
protected:

	/// Decodes packets coming from the client, sends appropriate counterparts to the server; returns false if the connection is to be dropped
	bool DecodeClientsPackets(const char * a_Data, int a_Size);

	/// Decodes packets coming from the server, sends appropriate counterparts to the client; returns false if the connection is to be dropped
	bool DecodeServersPackets(const char * a_Data, int a_Size);
	
	// Packet handling, client-side, initial:
	bool HandleClientHandshake(void);

	cProtocol172 * m_Protocol;

	// cSocketThreads::cCallback overrides:
	virtual void DataReceived(const char * a_Data, size_t a_Size) override;  // Data is received from the client
	virtual void GetOutgoingData(AString & a_Data) override;  // Data can be sent to client
	virtual void SocketClosed(void) override;  // The socket has been closed for any reason
} ;




