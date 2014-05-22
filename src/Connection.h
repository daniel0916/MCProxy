
// Connection.h

// Interfaces to the cConnection class representing a single pair of connected sockets





#pragma once

#include "ByteBuffer.h"
#include "Timer.h"
#include "SocketThreads.h"
#include "PolarSSL++/AesCfb128Decryptor.h"
#include "PolarSSL++/AesCfb128Encryptor.h"





class cServer;
class cServerConnection;





class cConnection :
	public cSocketThreads::cCallback
{
	int m_ItemIdx;  ///< Index for the next file into which item metadata should be written (ParseSlot() function)
	
	cCriticalSection m_CSLog;
	
	cServer & m_Server;
	cSocket m_ClientSocket;
	cSocket m_ServerSocket;

	cServerConnection * m_OldServerConnection;
	
	enum eConnectionState
	{
		csUnencrypted,           // The connection is not encrypted. Packets must be decoded in order to be able to start decryption.
		csEncryptedUnderstood,   // The communication is encrypted and so far all packets have been understood, so they can be still decoded
		csEncryptedUnknown,      // The communication is encrypted, but an unknown packet has been received, so packets cannot be decoded anymore
		csWaitingForEncryption,  // The communication is waiting for the other line to establish encryption
	};
	
	eConnectionState m_ClientState;
	eConnectionState m_ServerState;

	int m_ClientEntityID;
	int m_ServerEntityID;

	struct cScoreboard
	{
		AString m_ObjectiveName;
		AString m_ObjectiveValue;
	};
	typedef std::vector<cScoreboard> cScoreboards;
	cScoreboards m_Scoreboards;

	typedef std::vector<AString> cTeams;
	cTeams m_Teams;

	typedef std::vector<AString> cTabPlayers;
	cTabPlayers m_TabPlayers;
	
public:
	cConnection(cSocket a_ClientSocket, cSocket a_ServerSocket, cServer & a_Server);
	~cConnection();

	bool SendToClient(const char * a_Data, size_t a_Size);

	void Kick(AString a_Reason);

	void Authenticate(AString a_Name, AString a_UUID);

	cServerConnection * m_ServerConnection;

	bool m_SwitchServer;
	bool m_AlreadyCountPlayer;
	bool m_AlreadyRemovedPlayer;

	AString m_UserName;
	AString m_UUID;
	
protected:

	cByteBuffer m_ClientBuffer;
	cByteBuffer m_ServerBuffer;
	
	cAesCfb128Decryptor m_ServerDecryptor;
	cAesCfb128Encryptor m_ServerEncryptor;

	cAesCfb128Decryptor m_ClientDecryptor;
	cAesCfb128Encryptor m_ClientEncryptor;

	AString m_ServerEncryptionBuffer;  // Buffer for the data to be sent to the server once encryption is established
	AString m_ClientEncryptionBuffer;  // Buffer for the data to be sent to the client once encryption is established
	
	/*
	The protocol states can be one of:
	-1: no initial handshake received yet
	1: status
	2: login
	3: game
	*/
	/// State the to-server protocol is in (as defined by the initial handshake / login), -1 if no initial handshake received yet
	int m_ServerProtocolState;
	
	/// State the to-client protocol is in (as defined by the initial handshake / login), -1 if no initial handshake received yet
	int m_ClientProtocolState;
	
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
	
	/// Decodes packets coming from the client, sends appropriate counterparts to the server; returns false if the connection is to be dropped
	bool DecodeClientsPackets(const char * a_Data, int a_Size);

	/// Decodes packets coming from the server, sends appropriate counterparts to the client; returns false if the connection is to be dropped
	bool DecodeServersPackets(const char * a_Data, int a_Size);
	
	// Packet handling, client-side, initial:
	bool HandleClientHandshake(void);
	
	// Packet handling, client-side, status:
	bool HandleClientStatusPing(void);
	bool HandleClientStatusRequest(void);
	
	// Packet handling, client-side, login:
	bool HandleClientLoginEncryptionKeyResponse(void);
	bool HandleClientLoginStart(void);

	// Packet handling, client-side, game:
	bool HandleClientAnimation(void);
	bool HandleClientChatMessage(void);
	bool HandleClientEntityAction(void);
	bool HandleClientPlayerOnGround(void);
	
	bool HandleClientUnknownPacket(UInt32 a_PacketType, UInt32 a_PacketLen, UInt32 a_PacketReadSoFar);

	// Packet handling, server-side, login:
	bool HandleServerLoginDisconnect(void);
	bool HandleServerLoginEncryptionKeyRequest(void);
	bool HandleServerLoginSuccess(void);

	// Packet handling, server-side, game:
	bool HandleServerAttachEntity(void);
	bool HandleServerCollectPickup(void);
	bool HandleServerEntity(void);
	bool HandleServerEntityHeadLook(void);
	bool HandleServerEntityLook(void);
	bool HandleServerEntityMetadata(void);
	bool HandleServerEntityProperties(void);
	bool HandleServerEntityRelativeMove(void);
	bool HandleServerEntityRelativeMoveLook(void);
	bool HandleServerEntityStatus(void);
	bool HandleServerEntityTeleport(void);
	bool HandleServerEntityVelocity(void);
	bool HandleServerJoinGame(void);
	bool HandleServerPlayerAnimation(void);
	bool HandleServerUseBed(void);
	bool HandleServerScoreboardObjective(void);
	bool HandleServerTeams(void);
	bool HandleServerPlayerListItem(void);
	bool HandleServerPluginMessage(void);
	
	bool HandleServerUnknownPacket(UInt32 a_PacketType, UInt32 a_PacketLen, UInt32 a_PacketReadSoFar);

	/// Parses the slot data in a_Buffer and write it to a_Packet; returns true if successful, false if not enough data
	bool ParseSlot(cByteBuffer & a_Buffer, cByteBuffer & a_Packet);
	
	/// Parses the metadata in a_Buffer and write it to a_Packet; returns true if successful, false if not enough data
	bool ParseMetadata(cByteBuffer & a_Buffer, cByteBuffer & a_Packet);

	void SendChatMessage(AString a_Message, AString a_Color);

	void SwitchServer(AString a_ServerAddress, short a_ServerPort);

	void StartEncryption(const Byte * a_Key);
	AString m_AuthServerID;

	AString m_NewServerName;

	// cSocketThreads::cCallback overrides:
	virtual void DataReceived(const char * a_Data, size_t a_Size) override;  // Data is received from the client
	virtual void GetOutgoingData(AString & a_Data) override;  // Data can be sent to client
	virtual void SocketClosed(void) override;  // The socket has been closed for any reason
} ;




