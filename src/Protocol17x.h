
// Protocol17x.h


#pragma once


#include "ByteBuffer.h"

class cConnection;



struct cScoreboard
{
	AString m_ObjectiveName;
	AString m_ObjectiveValue;
};
typedef std::vector<cScoreboard> cScoreboards;
typedef std::vector<AString> cTeams;
typedef std::vector<AString> cTabPlayers;



class cProtocol172
{

public:

	cProtocol172(cConnection * a_Connection);

	virtual bool HandleClientPackets(UInt32 a_PacketType, UInt32 a_PacketLen, UInt32 a_PacketReadSoFar);
	virtual bool HandleServerPackets(UInt32 a_PacketType, UInt32 a_PacketLen, UInt32 a_PacketReadSoFar);

	/// State the to-client protocol is in (as defined by the initial handshake / login), -1 if no initial handshake received yet
	int m_ClientProtocolState;

	/*
	The protocol states can be one of:
	-1: no initial handshake received yet
	1: status
	2: login
	3: game
	*/
	/// State the to-server protocol is in (as defined by the initial handshake / login), -1 if no initial handshake received yet
	int m_ServerProtocolState;

	cScoreboards m_Scoreboards;
	cTeams m_Teams;
	cTabPlayers m_TabPlayers;

	void SendChatMessage(AString a_Message, AString a_Color);

protected:

	cConnection * m_Connection;
	
	// Packet handling, client-side, status:
	virtual bool HandleClientStatusPing(void);
	virtual bool HandleClientStatusRequest(void);

	// Packet handling, client-side, login:
	virtual bool HandleClientLoginEncryptionKeyResponse(void);
	virtual bool HandleClientLoginStart(void);

	// Packet handling, client-side, game:
	virtual bool HandleClientAnimation(void);
	virtual bool HandleClientChatMessage(void);
	virtual bool HandleClientEntityAction(void);
	virtual bool HandleClientPlayerOnGround(void);

	virtual bool HandleClientUnknownPacket(UInt32 a_PacketType, UInt32 a_PacketLen, UInt32 a_PacketReadSoFar);

	// Packet handling, server-side, login:
	virtual bool HandleServerLoginDisconnect(void);
	virtual bool HandleServerLoginEncryptionKeyRequest(void);
	virtual bool HandleServerLoginSuccess(void);

	// Packet handling, server-side, game:
	virtual bool HandleServerAttachEntity(void);
	virtual bool HandleServerCollectPickup(void);
	virtual bool HandleServerEntity(void);
	virtual bool HandleServerEntityHeadLook(void);
	virtual bool HandleServerEntityLook(void);
	virtual bool HandleServerEntityMetadata(void);
	virtual bool HandleServerEntityProperties(void);
	virtual bool HandleServerEntityRelativeMove(void);
	virtual bool HandleServerEntityRelativeMoveLook(void);
	virtual bool HandleServerEntityStatus(void);
	virtual bool HandleServerEntityTeleport(void);
	virtual bool HandleServerEntityVelocity(void);
	virtual bool HandleServerJoinGame(void);
	virtual bool HandleServerPlayerAnimation(void);
	virtual bool HandleServerUseBed(void);
	virtual bool HandleServerScoreboardObjective(void);
	virtual bool HandleServerTeams(void);
	virtual bool HandleServerPlayerListItem(void);
	virtual bool HandleServerPluginMessage(void);
	virtual bool HandleServerSpawnPlayer(void);

	virtual bool HandleServerUnknownPacket(UInt32 a_PacketType, UInt32 a_PacketLen, UInt32 a_PacketReadSoFar);

	/// Parses the slot data in a_Buffer and write it to a_Packet; returns true if successful, false if not enough data
	bool ParseSlot(cByteBuffer & a_Buffer, cByteBuffer & a_Packet);

	/// Parses the metadata in a_Buffer and write it to a_Packet; returns true if successful, false if not enough data
	bool ParseMetadata(cByteBuffer & a_Buffer, cByteBuffer & a_Packet);

	int m_ClientEntityID;
	int m_ServerEntityID;

	enum eConnectionState
	{
		csUnencrypted,           // The connection is not encrypted. Packets must be decoded in order to be able to start decryption.
		csEncryptedUnderstood,   // The communication is encrypted and so far all packets have been understood, so they can be still decoded
		csEncryptedUnknown,      // The communication is encrypted, but an unknown packet has been received, so packets cannot be decoded anymore
		csWaitingForEncryption,  // The communication is waiting for the other line to establish encryption
	};
};





class cProtocol176 :
	public cProtocol172
{
	typedef cProtocol172 super;

public:
	cProtocol176(cConnection * a_Connection);

	// cProtocol172 overrides:
	virtual bool HandleServerSpawnPlayer(void) override;
	virtual bool HandleClientStatusRequest(void) override;

};