
// Protocol17x.cpp

#include "Globals.h"
#include "Protocol17x.h"
#include "Server.h"
#include "PolarSSL++/PublicKey.h"
#include "PolarSSL++/Sha1Checksum.h"
#include "ServerConnection.h"




const int MAX_ENC_LEN = 512;  // Maximum size of the encrypted message; should be 128, but who knows...





#define HANDLE_CLIENT_PACKET_READ(Proc, Type, Var) \
	Type Var; \
	{ \
		if (!m_Connection->m_ClientBuffer.Proc(Var)) \
		{ \
			return false; \
		} \
	}

#define HANDLE_SERVER_PACKET_READ(Proc, Type, Var) \
	Type Var; \
	{ \
		if (!m_Connection->m_ServerBuffer.Proc(Var)) \
		{ \
			return false; \
		} \
	}

#define CLIENTSEND(...) \
	{ \
		if (m_Connection->m_IsClientEncrypted) \
		{ \
			m_Connection->SendEncryptedData(m_Connection->m_ClientSocket, m_Connection->m_ClientEncryptor, __VA_ARGS__, "Client"); \
		} \
		else \
		{ \
			m_Connection->SendData(m_Connection->m_ClientSocket, __VA_ARGS__, "Client"); \
		} \
	}
#define SERVERSEND(...) m_Connection->SendData(m_Connection->m_ServerSocket, __VA_ARGS__, "Server")
#define CLIENTENCRYPTSEND(...) m_Connection->SendEncryptedData(m_Connection->m_ClientSocket, m_Connection->m_ClientEncryptor, __VA_ARGS__, "Client")
#define SERVERENCRYPTSEND(...) m_Connection->SendEncryptedData(m_Connection->m_ServerSocket, m_Connection->m_ServerEncryptor, __VA_ARGS__, "Server")

#define COPY_TO_SERVER() \
	{ \
		AString ToServer; \
		m_Connection->m_ClientBuffer.ReadAgain(ToServer); \
		switch (m_Connection->m_ServerState) \
		{ \
			case csUnencrypted: \
			{ \
				SERVERSEND(ToServer.data(), ToServer.size()); \
				break; \
			} \
			case csEncryptedUnderstood: \
			case csEncryptedUnknown: \
			{ \
				SERVERENCRYPTSEND(ToServer.data(), ToServer.size()); \
				break; \
			} \
			case csWaitingForEncryption: \
			{ \
				m_Connection->m_ServerEncryptionBuffer.append(ToServer.data(), ToServer.size()); \
				break; \
			} \
		} \
	}

#define COPY_TO_CLIENT() \
	{ \
		AString ToClient; \
		m_Connection->m_ServerBuffer.ReadAgain(ToClient); \
		switch (m_Connection->m_ClientState) \
		{ \
			case csUnencrypted: \
			{ \
				CLIENTSEND(ToClient.data(), ToClient.size()); \
				break; \
			} \
			case csEncryptedUnderstood: \
			case csEncryptedUnknown: \
			{ \
				CLIENTENCRYPTSEND(ToClient.data(), ToClient.size()); \
				break; \
			} \
			case csWaitingForEncryption: \
			{ \
				m_Connection->m_ClientEncryptionBuffer.append(ToClient.data(), ToClient.size()); \
				break; \
			} \
		} \
	}

#define HANDLE_CLIENT_READ(Proc) \
	{ \
		if (!Proc) \
		{ \
			AString Leftover; \
			m_Connection->m_ClientBuffer.ReadAgain(Leftover); \
			m_Connection->m_ClientBuffer.ResetRead(); \
			return true; \
		} \
	}
	
#define HANDLE_SERVER_READ(Proc) \
	{ \
		if (!Proc) \
		{ \
			m_Connection->m_ServerBuffer.ResetRead(); \
			return true; \
		} \
	}



///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// cProtocol172:

cProtocol172::cProtocol172(cConnection * a_Connection) :
	m_Connection(a_Connection),
	m_ServerProtocolState(-1),
	m_ClientProtocolState(-1)
{
}





bool cProtocol172::HandleClientPackets(UInt32 a_PacketType, UInt32 a_PacketLen, UInt32 a_PacketReadSoFar)
{
	switch (m_ClientProtocolState)
	{
		case -1:
		{
			// No initial handshake received yet
			HANDLE_CLIENT_READ(HandleClientUnknownPacket(a_PacketType, a_PacketLen, a_PacketReadSoFar));
			break;
		}  // case -1

		case 1:
		{
			// Status query
			switch (a_PacketType)
			{
				case 0x00: HANDLE_CLIENT_READ(HandleClientStatusRequest()); break;
				case 0x01: HANDLE_CLIENT_READ(HandleClientStatusPing()); break;
				default:   HANDLE_CLIENT_READ(HandleClientUnknownPacket(a_PacketType, a_PacketLen, a_PacketReadSoFar)); break;
			}
			break;
		}

		case 2:
		{
			// Login
			switch (a_PacketType)
			{
				case 0x00: HANDLE_CLIENT_READ(HandleClientLoginStart()); break;
				case 0x01: HANDLE_CLIENT_READ(HandleClientLoginEncryptionKeyResponse()); break;
				default:   HANDLE_CLIENT_READ(HandleClientUnknownPacket(a_PacketType, a_PacketLen, a_PacketReadSoFar)); break;
			}
			break;
		}

		case 3:
		{
			// Game:
			switch (a_PacketType)
			{
				case 0x01: HANDLE_CLIENT_READ(HandleClientChatMessage()); break;
				case 0x03: HANDLE_CLIENT_READ(HandleClientPlayerOnGround()); break;
				case 0x0a: HANDLE_CLIENT_READ(HandleClientAnimation()); break;
				case 0x0b: HANDLE_CLIENT_READ(HandleClientEntityAction()); break;
				default:   HANDLE_CLIENT_READ(HandleClientUnknownPacket(a_PacketType, a_PacketLen, a_PacketReadSoFar)); break;
			}
			break;
		}  // case 3 - Game

		default:
		{
			HANDLE_CLIENT_READ(HandleClientUnknownPacket(a_PacketType, a_PacketLen, a_PacketReadSoFar));
			break;
		}
	}  // switch (m_ProtocolState)

	return true;
}





bool cProtocol172::HandleServerPackets(UInt32 a_PacketType, UInt32 a_PacketLen, UInt32 a_PacketReadSoFar)
{
	switch (m_ServerProtocolState)
		{
			case -1:
			{
				HANDLE_SERVER_READ(HandleServerUnknownPacket(a_PacketType, a_PacketLen, a_PacketReadSoFar));
				break;
			}
			
			case 1:
			{
				// Status query:
				HANDLE_SERVER_READ(HandleServerUnknownPacket(a_PacketType, a_PacketLen, a_PacketReadSoFar));
				break;
			}
			
			case 2:
			{
				// Login:
				switch (a_PacketType)
				{
					case 0x00: HANDLE_SERVER_READ(HandleServerLoginDisconnect()); break;
					case 0x01: HANDLE_SERVER_READ(HandleServerLoginEncryptionKeyRequest()); break;
					case 0x02: HANDLE_SERVER_READ(HandleServerLoginSuccess()); break;
					default:   HANDLE_SERVER_READ(HandleServerUnknownPacket(a_PacketType, a_PacketLen, a_PacketReadSoFar)); break;
				}
				break;
			}
			
			case 3:
			{
				// Game:
				switch (a_PacketType)
				{
					case 0x01: HANDLE_SERVER_READ(HandleServerJoinGame()); break;
					case 0x0a: HANDLE_SERVER_READ(HandleServerUseBed()); break;
					case 0x0b: HANDLE_SERVER_READ(HandleServerPlayerAnimation()); break;
					case 0x0d: HANDLE_SERVER_READ(HandleServerCollectPickup()); break;
					case 0x12: HANDLE_SERVER_READ(HandleServerEntityVelocity()); break;
					case 0x14: HANDLE_SERVER_READ(HandleServerEntity()); break;
					case 0x15: HANDLE_SERVER_READ(HandleServerEntityRelativeMove()); break;
					case 0x16: HANDLE_SERVER_READ(HandleServerEntityLook()); break;
					case 0x17: HANDLE_SERVER_READ(HandleServerEntityRelativeMoveLook()); break;
					case 0x18: HANDLE_SERVER_READ(HandleServerEntityTeleport()); break;
					case 0x19: HANDLE_SERVER_READ(HandleServerEntityHeadLook()); break;
					case 0x1a: HANDLE_SERVER_READ(HandleServerEntityStatus()); break;
					case 0x1b: HANDLE_SERVER_READ(HandleServerAttachEntity()); break;
					case 0x1c: HANDLE_SERVER_READ(HandleServerEntityMetadata()); break;
					case 0x20: HANDLE_SERVER_READ(HandleServerEntityProperties()); break;
					case 0x3b: HANDLE_SERVER_READ(HandleServerScoreboardObjective()); break;
					case 0x3e: HANDLE_SERVER_READ(HandleServerTeams()); break;
					case 0x38: HANDLE_SERVER_READ(HandleServerPlayerListItem()); break;
					case 0x3f: HANDLE_SERVER_READ(HandleServerPluginMessage()); break;
					case 0x0c: HANDLE_SERVER_READ(HandleServerSpawnPlayer()); break;
					default:   HANDLE_SERVER_READ(HandleServerUnknownPacket(a_PacketType, a_PacketLen, a_PacketReadSoFar)); break;
				}  // switch (PacketType)
				break;
			}  // case 3 - Game
			
			default:
			{
				HANDLE_SERVER_READ(HandleServerUnknownPacket(a_PacketType, a_PacketLen, a_PacketReadSoFar));
				break;
			}
		}  // switch (m_ProtocolState)*/

	return true;
}





///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// packet handling, client-side, login:

bool cProtocol172::HandleClientLoginEncryptionKeyResponse(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadBEShort, short, EncKeyLength);
	AString EncKey;
	if (!m_Connection->m_ClientBuffer.ReadString(EncKey, EncKeyLength))
	{
		return false;
	}

	HANDLE_CLIENT_PACKET_READ(ReadBEShort, short, EncNonceLength);
	AString EncNonce;
	if (!m_Connection->m_ClientBuffer.ReadString(EncNonce, EncNonceLength))
	{
		return false;
	}

	m_Connection->m_ClientBuffer.CommitRead();

	if ((EncKeyLength > MAX_ENC_LEN) || (EncNonceLength > MAX_ENC_LEN))
	{
		LOGD("Too long encryption");
		m_Connection->Kick("Hacked client");
		return false;
	}

	// Decrypt EncNonce using privkey
	cRsaPrivateKey & rsaDecryptor = cServer::Get()->m_PrivateKey;
	Int32 DecryptedNonce[MAX_ENC_LEN / sizeof(Int32)];
	int res = rsaDecryptor.Decrypt((const Byte *)EncNonce.data(), EncNonce.size(), (Byte *)DecryptedNonce, sizeof(DecryptedNonce));
	if (res != 4)
	{
		LOGD("Bad nonce length: got %d, exp %d", res, 4);
		m_Connection->Kick("Hacked client");
		return false;
	}
	if (ntohl(DecryptedNonce[0]) != (unsigned)(uintptr_t)this)
	{
		LOGD("Bad nonce value");
		m_Connection->Kick("Hacked client");
		return false;
	}

	// Decrypt the symmetric encryption key using privkey:
	Byte DecryptedKey[MAX_ENC_LEN];
	res = rsaDecryptor.Decrypt((const Byte *)EncKey.data(), EncKey.size(), DecryptedKey, sizeof(DecryptedKey));
	if (res != 16)
	{
		LOGD("Bad key length");
		m_Connection->Kick("Hacked client");
		return false;
	}

	m_Connection->StartEncryption(DecryptedKey);

	cServer::Get()->m_Authenticator.Authenticate(m_Connection->m_UserName, m_Connection->m_AuthServerID);

	return true;
}





bool cProtocol172::HandleClientLoginStart(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadVarUTF8String, AString, UserName);

	m_Connection->m_UserName = UserName;

	if (cServer::Get()->m_ShouldAuthenticate)
	{
		m_Connection->m_ClientBuffer.CommitRead();

		// Send Encryption Request
		cByteBuffer Packet(512);
		Packet.WriteByte(0x01);
		Packet.WriteVarUTF8String(cServer::Get()->m_ServerID);
		AString PubKeyDer = cServer::Get()->m_PublicKeyDER;
		Packet.WriteBEShort((short)PubKeyDer.size());
		Packet.WriteBuf(PubKeyDer.data(), PubKeyDer.size());
		Packet.WriteBEShort(4);
		Packet.WriteBEInt((int)(intptr_t)this);
		AString Pkt;
		Packet.ReadAll(Pkt);
		cByteBuffer ToClient(512);
		ToClient.WriteVarUTF8String(Pkt);
		CLIENTSEND(ToClient);

		return true;
	}

	m_Connection->m_UUID = cServer::Get()->GenerateOfflineUUID(UserName);

	COPY_TO_SERVER();
	return true;
}





///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// packet handling, client-side, game:

bool cProtocol172::HandleClientAnimation(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadBEInt, int, EntityID);
	HANDLE_CLIENT_PACKET_READ(ReadChar, char, Animation);

	if (EntityID == m_ClientEntityID)
	{
		m_Connection->m_ClientBuffer.CommitRead();

		// Send the same packet, but with modified Entity ID:
		cByteBuffer Packet(512);
		Packet.WriteByte(0x0A);
		Packet.WriteBEInt(m_ServerEntityID);
		Packet.WriteChar(Animation);
		AString Pkt;
		Packet.ReadAll(Pkt);
		cByteBuffer ToServer(512);
		ToServer.WriteVarUTF8String(Pkt);
		SERVERSEND(ToServer);

		return true;
	}

	COPY_TO_SERVER();
	return true;
}





bool cProtocol172::HandleClientChatMessage(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadVarUTF8String, AString, Message);

	AStringVector ChatMessage = StringSplit(Message, " ");
	if (ChatMessage[0] == "/server")
	{
		if (ChatMessage.size() < 2)
		{
			return true;
		}
		m_Connection->m_NewServerName = ChatMessage[1];
		AString ServerConfig = cServer::Get()->m_Config.GetValue("Servers", ChatMessage[1]);
		if (ServerConfig.empty())
		{
			SendChatMessage("Can't load server data from config!", "c");
			return true;
		}

		AStringVector ServerData = StringSplit(ServerConfig, ":");
		AString ServerAddress = ServerData[0];
		short ServerPort = (short)atoi(ServerData[1].c_str());

		m_Connection->SwitchServer(ServerAddress, ServerPort);

		return true;
	}

	COPY_TO_SERVER();
	return true;
}





bool cProtocol172::HandleClientEntityAction(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadBEInt, int, PlayerID);
	HANDLE_CLIENT_PACKET_READ(ReadByte, Byte, ActionType);
	HANDLE_CLIENT_PACKET_READ(ReadBEInt, int, HorseJumpBoost);

	if (PlayerID == m_ClientEntityID)
	{
		m_Connection->m_ClientBuffer.CommitRead();

		// Send the same packet, but with modified Entity ID:
		cByteBuffer Packet(512);
		Packet.WriteByte(0x0B);
		Packet.WriteBEInt(m_ServerEntityID);
		Packet.WriteByte(ActionType);
		Packet.WriteBEInt(HorseJumpBoost);
		AString Pkt;
		Packet.ReadAll(Pkt);
		cByteBuffer ToServer(512);
		ToServer.WriteVarUTF8String(Pkt);
		SERVERSEND(ToServer);

		return true;
	}

	COPY_TO_SERVER();
	return true;
}





bool cProtocol172::HandleClientPlayerOnGround(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadChar, char, OnGround);

	if (m_Connection->m_SwitchServer)
	{
		m_Connection->m_ClientBuffer.CommitRead();
		return true;
	}

	COPY_TO_SERVER();
	return true;
}





bool cProtocol172::HandleClientStatusPing(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadBEInt64, Int64, Time);

	m_Connection->m_ClientBuffer.CommitRead();

	cByteBuffer Packet(512);
	Packet.WriteByte(0x01);
	Packet.WriteBEInt64(Time);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToClient(512);
	ToClient.WriteVarUTF8String(Pkt);
	CLIENTSEND(ToClient);

	return true;
}





bool cProtocol172::HandleClientStatusRequest(void)
{
	// Send the response:
	AString Response = "{\"version\":{\"name\":\"1.7.2\",\"protocol\":4},\"players\":{";
	AppendPrintf(Response, "\"max\":%u,\"online\":%u,\"sample\":[]},",
		cServer::Get()->m_MaxPlayers,
		cServer::Get()->m_PlayerAmount
		);
	AppendPrintf(Response, "\"description\":{\"text\":\"%s\"},",
		cServer::Get()->m_MOTD.c_str()
		);
	AppendPrintf(Response, "\"favicon\":\"data:image/png;base64,%s\"",
		cServer::Get()->m_FaviconData.c_str()
		);
	Response.append("}");

	cByteBuffer Packet(512);
	Packet.WriteByte(0x00);
	Packet.WriteVarUTF8String(Response);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToClient(512);
	ToClient.WriteVarUTF8String(Pkt);
	CLIENTSEND(ToClient);

	return true;
}





bool cProtocol172::HandleClientUnknownPacket(UInt32 a_PacketType, UInt32 a_PacketLen, UInt32 a_PacketReadSoFar)
{
	AString Data;
	if (!m_Connection->m_ClientBuffer.ReadString(Data, a_PacketLen - a_PacketReadSoFar))
	{
		return false;
	}

	COPY_TO_SERVER();

	return true;
}





///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// packet handling, server-side, login:

bool cProtocol172::HandleServerLoginDisconnect(void)
{
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, Reason);

	COPY_TO_CLIENT();
	return true;
}





bool cProtocol172::HandleServerLoginEncryptionKeyRequest(void)
{
	// Read the packet from the server:
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, ServerID);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, PublicKeyLength);
	AString PublicKey;
	if (!m_Connection->m_ServerBuffer.ReadString(PublicKey, PublicKeyLength))
	{
		return false;
	}
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, NonceLength);
	AString Nonce;
	if (!m_Connection->m_ServerBuffer.ReadString(Nonce, NonceLength))
	{
		return false;
	}

	// The proxy don't support authentication from the server. So don't send it to the client.

	return true;
}





bool cProtocol172::HandleServerLoginSuccess(void)
{
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, UUID);
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, Username);

	if (m_Connection->m_SwitchServer)
	{
		m_Connection->m_ServerBuffer.CommitRead();
		m_ServerProtocolState = 3;

		LOGINFO("%s switched to %s", m_Connection->m_UserName.c_str(), m_Connection->m_NewServerName.c_str());

		return true;
	}

	m_ServerProtocolState = 3;

	if (m_Connection->m_IsClientEncrypted)
	{
		m_Connection->m_ClientState = m_Connection->csEncryptedUnderstood;
		CLIENTENCRYPTSEND(m_Connection->m_ClientEncryptionBuffer.data(), m_Connection->m_ClientEncryptionBuffer.size());
		m_Connection->m_ClientEncryptionBuffer.clear();
	}

	COPY_TO_CLIENT();
	m_ClientProtocolState = 3;

	LOGINFO("%s connected to %s", m_Connection->m_UserName.c_str(), cServer::Get()->m_MainServerName.c_str());

	return true;
}





///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// packet handling, server-side, game:

bool cProtocol172::HandleServerAttachEntity(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, EntityID);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, VehicleID);
	HANDLE_SERVER_PACKET_READ(ReadBool, bool, Leash);

	if (EntityID == m_ServerEntityID)
	{
		m_Connection->m_ServerBuffer.CommitRead();

		// Send the same packet, but with modified Entity ID:
		cByteBuffer Packet(512);
		Packet.WriteByte(0x1B);
		Packet.WriteBEInt(m_ClientEntityID);
		Packet.WriteBEInt(VehicleID);
		Packet.WriteBool(Leash);
		AString Pkt;
		Packet.ReadAll(Pkt);
		cByteBuffer ToClient(512);
		ToClient.WriteVarUTF8String(Pkt);
		CLIENTSEND(ToClient);

		return true;
	}

	COPY_TO_CLIENT();
	return true;
}





bool cProtocol172::HandleServerCollectPickup(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, CollectedID);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, CollectorID);

	if (CollectorID == m_ServerEntityID)
	{
		m_Connection->m_ServerBuffer.CommitRead();

		// Send the same packet, but with modified Entity ID:
		cByteBuffer Packet(512);
		Packet.WriteByte(0x0D);
		Packet.WriteBEInt(CollectedID);
		Packet.WriteBEInt(m_ClientEntityID);
		AString Pkt;
		Packet.ReadAll(Pkt);
		cByteBuffer ToClient(512);
		ToClient.WriteVarUTF8String(Pkt);
		CLIENTSEND(ToClient);

		return true;
	}

	COPY_TO_CLIENT();
	return true;
}





bool cProtocol172::HandleServerEntity(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, EntityID);

	if (EntityID == m_ServerEntityID)
	{
		m_Connection->m_ServerBuffer.CommitRead();

		// Send the same packet, but with modified Entity ID:
		cByteBuffer Packet(512);
		Packet.WriteByte(0x14);
		Packet.WriteBEInt(m_ClientEntityID);
		AString Pkt;
		Packet.ReadAll(Pkt);
		cByteBuffer ToClient(512);
		ToClient.WriteVarUTF8String(Pkt);
		CLIENTSEND(ToClient);

		return true;
	}

	COPY_TO_CLIENT();
	return true;
}





bool cProtocol172::HandleServerEntityHeadLook(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, EntityID);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, HeadYaw);

	if (EntityID == m_ServerEntityID)
	{
		m_Connection->m_ServerBuffer.CommitRead();

		// Send the same packet, but with modified Entity ID:
		cByteBuffer Packet(512);
		Packet.WriteByte(0x19);
		Packet.WriteBEInt(m_ClientEntityID);
		Packet.WriteByte(HeadYaw);
		AString Pkt;
		Packet.ReadAll(Pkt);
		cByteBuffer ToClient(512);
		ToClient.WriteVarUTF8String(Pkt);
		CLIENTSEND(ToClient);

		return true;
	}

	COPY_TO_CLIENT();
	return true;
}





bool cProtocol172::HandleServerEntityLook(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, EntityID);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, Yaw);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, Pitch);

	if (EntityID == m_ServerEntityID)
	{
		m_Connection->m_ServerBuffer.CommitRead();

		// Send the same packet, but with modified Entity ID:
		cByteBuffer Packet(512);
		Packet.WriteByte(0x16);
		Packet.WriteBEInt(m_ClientEntityID);
		Packet.WriteByte(Yaw);
		Packet.WriteByte(Pitch);
		AString Pkt;
		Packet.ReadAll(Pkt);
		cByteBuffer ToClient(512);
		ToClient.WriteVarUTF8String(Pkt);
		CLIENTSEND(ToClient);

		return true;
	}

	COPY_TO_CLIENT();
	return true;
}





bool cProtocol172::HandleServerEntityMetadata(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, EntityID);

	cByteBuffer Packet(512);

	if (EntityID == m_ServerEntityID)
	{
		Packet.WriteByte(0x1C);
		Packet.WriteBEInt(m_ClientEntityID);

		if (!ParseMetadata(m_Connection->m_ServerBuffer, Packet))
		{
			return false;
		}

		m_Connection->m_ServerBuffer.CommitRead();

		AString Pkt;
		Packet.ReadAll(Pkt);
		cByteBuffer ToClient(512);
		ToClient.WriteVarUTF8String(Pkt);
		CLIENTSEND(ToClient);

		return true;
	}

	AString Metadata;
	if (!ParseMetadata(m_Connection->m_ServerBuffer, Packet))
	{
		return false;
	}

	COPY_TO_CLIENT();
	return true;
}





bool cProtocol172::HandleServerEntityProperties(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, EntityID);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, Count);

	if (EntityID == m_ServerEntityID)
	{
		cByteBuffer Packet(512);
		Packet.WriteByte(0x20);
		Packet.WriteBEInt(m_ClientEntityID);
		Packet.WriteBEInt(Count);

		for (int i = 0; i < Count; i++)
		{
			HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, Key);
			HANDLE_SERVER_PACKET_READ(ReadBEDouble, double, Value);
			HANDLE_SERVER_PACKET_READ(ReadBEShort, short, ListLength);

			Packet.WriteVarUTF8String(Key);
			Packet.WriteBEDouble(Value);
			Packet.WriteBEShort(ListLength);

			for (short j = 0; j < ListLength; j++)
			{
				HANDLE_SERVER_PACKET_READ(ReadBEInt64, Int64, UUIDHi);
				HANDLE_SERVER_PACKET_READ(ReadBEInt64, Int64, UUIDLo);
				HANDLE_SERVER_PACKET_READ(ReadBEDouble, double, DblVal);
				HANDLE_SERVER_PACKET_READ(ReadByte, Byte, ByteVal);

				Packet.WriteBEInt64(UUIDHi);
				Packet.WriteBEInt64(UUIDLo);
				Packet.WriteBEDouble(DblVal);
				Packet.WriteByte(ByteVal);
			}
		}  // for i

		m_Connection->m_ServerBuffer.CommitRead();

		AString Pkt;
		Packet.ReadAll(Pkt);
		cByteBuffer ToClient(512);
		ToClient.WriteVarUTF8String(Pkt);
		CLIENTSEND(ToClient);

		return true;
	}

	for (int i = 0; i < Count; i++)
	{
		HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, Key);
		HANDLE_SERVER_PACKET_READ(ReadBEDouble, double, Value);
		HANDLE_SERVER_PACKET_READ(ReadBEShort, short, ListLength);

		for (short j = 0; j < ListLength; j++)
		{
			HANDLE_SERVER_PACKET_READ(ReadBEInt64, Int64, UUIDHi);
			HANDLE_SERVER_PACKET_READ(ReadBEInt64, Int64, UUIDLo);
			HANDLE_SERVER_PACKET_READ(ReadBEDouble, double, DblVal);
			HANDLE_SERVER_PACKET_READ(ReadByte, Byte, ByteVal);
		}
	}  // for i

	COPY_TO_CLIENT();
	return true;
}





bool cProtocol172::HandleServerEntityRelativeMove(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, EntityID);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, dx);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, dy);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, dz);

	if (EntityID == m_ServerEntityID)
	{
		m_Connection->m_ServerBuffer.CommitRead();

		// Send the same packet, but with modified Entity ID:
		cByteBuffer Packet(512);
		Packet.WriteByte(0x15);
		Packet.WriteBEInt(m_ClientEntityID);
		Packet.WriteByte(dx);
		Packet.WriteByte(dy);
		Packet.WriteByte(dz);
		AString Pkt;
		Packet.ReadAll(Pkt);
		cByteBuffer ToClient(512);
		ToClient.WriteVarUTF8String(Pkt);
		CLIENTSEND(ToClient);

		return true;
	}

	COPY_TO_CLIENT();
	return true;
}





bool cProtocol172::HandleServerEntityRelativeMoveLook(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, EntityID);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, dx);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, dy);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, dz);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, Yaw);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, Pitch);

	if (EntityID == m_ServerEntityID)
	{
		m_Connection->m_ServerBuffer.CommitRead();

		// Send the same packet, but with modified Entity ID:
		cByteBuffer Packet(512);
		Packet.WriteByte(0x17);
		Packet.WriteBEInt(m_ClientEntityID);
		Packet.WriteByte(dx);
		Packet.WriteByte(dy);
		Packet.WriteByte(dz);
		Packet.WriteByte(Yaw);
		Packet.WriteByte(Pitch);
		AString Pkt;
		Packet.ReadAll(Pkt);
		cByteBuffer ToClient(512);
		ToClient.WriteVarUTF8String(Pkt);
		CLIENTSEND(ToClient);

		return true;
	}

	COPY_TO_CLIENT();
	return true;
}





bool cProtocol172::HandleServerEntityStatus(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, EntityID);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, Status);

	if (EntityID == m_ServerEntityID)
	{
		m_Connection->m_ServerBuffer.CommitRead();

		// Send the same packet, but with modified Entity ID:
		cByteBuffer Packet(512);
		Packet.WriteByte(0x1A);
		Packet.WriteBEInt(m_ClientEntityID);
		Packet.WriteByte(Status);
		AString Pkt;
		Packet.ReadAll(Pkt);
		cByteBuffer ToClient(512);
		ToClient.WriteVarUTF8String(Pkt);
		CLIENTSEND(ToClient);

		return true;
	}

	COPY_TO_CLIENT();
	return true;
}





bool cProtocol172::HandleServerEntityTeleport(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, EntityID);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, AbsX);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, AbsY);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, AbsZ);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, Yaw);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, Pitch);

	if (EntityID == m_ServerEntityID)
	{
		m_Connection->m_ServerBuffer.CommitRead();

		// Send the same packet, but with modified Entity ID:
		cByteBuffer Packet(512);
		Packet.WriteByte(0x18);
		Packet.WriteBEInt(m_ClientEntityID);
		Packet.WriteBEInt(AbsX);
		Packet.WriteBEInt(AbsY);
		Packet.WriteBEInt(AbsZ);
		Packet.WriteByte(Yaw);
		Packet.WriteByte(Pitch);
		AString Pkt;
		Packet.ReadAll(Pkt);
		cByteBuffer ToClient(512);
		ToClient.WriteVarUTF8String(Pkt);
		CLIENTSEND(ToClient);

		return true;
	}

	COPY_TO_CLIENT();
	return true;
}





bool cProtocol172::HandleServerEntityVelocity(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, EntityID);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, VelocityX);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, VelocityY);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, VelocityZ);

	if (EntityID == m_ServerEntityID)
	{
		m_Connection->m_ServerBuffer.CommitRead();

		// Send the same packet, but with modified Entity ID:
		cByteBuffer Packet(512);
		Packet.WriteByte(0x12);
		Packet.WriteBEInt(m_ClientEntityID);
		Packet.WriteBEShort(VelocityX);
		Packet.WriteBEShort(VelocityY);
		Packet.WriteBEShort(VelocityZ);
		AString Pkt;
		Packet.ReadAll(Pkt);
		cByteBuffer ToClient(512);
		ToClient.WriteVarUTF8String(Pkt);
		CLIENTSEND(ToClient);

		return true;
	}

	COPY_TO_CLIENT();
	return true;
}





bool cProtocol172::HandleServerJoinGame(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, EntityID);
	HANDLE_SERVER_PACKET_READ(ReadChar, char, GameMode);
	HANDLE_SERVER_PACKET_READ(ReadChar, char, Dimension);
	HANDLE_SERVER_PACKET_READ(ReadChar, char, Difficulty);
	HANDLE_SERVER_PACKET_READ(ReadChar, char, MaxPlayers);
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, LevelType);

	if (m_Connection->m_SwitchServer)
	{
		m_Connection->m_ServerBuffer.CommitRead();

		m_Connection->m_SwitchServer = false;
		m_ServerEntityID = EntityID;

		cByteBuffer RespawnPacket2(512);
		RespawnPacket2.WriteByte(0x07);
		RespawnPacket2.WriteBEInt(-1);
		RespawnPacket2.WriteByte(0);
		RespawnPacket2.WriteByte(0);
		RespawnPacket2.WriteVarUTF8String("default");
		AString Respawn2Pkt;
		RespawnPacket2.ReadAll(Respawn2Pkt);
		cByteBuffer Respawn2ToServer(512);
		Respawn2ToServer.WriteVarUTF8String(Respawn2Pkt);
		CLIENTSEND(Respawn2ToServer);

		cByteBuffer RespawnPacket3(512);
		RespawnPacket3.WriteByte(0x07);
		RespawnPacket3.WriteBEInt(Dimension);
		RespawnPacket3.WriteByte(Difficulty);
		RespawnPacket3.WriteByte(GameMode);
		RespawnPacket3.WriteVarUTF8String(LevelType);
		AString Respawn3Pkt;
		RespawnPacket3.ReadAll(Respawn3Pkt);
		cByteBuffer Respawn3ToServer(512);
		Respawn3ToServer.WriteVarUTF8String(Respawn3Pkt);
		CLIENTSEND(Respawn3ToServer);

		cServer::Get()->m_SocketThreads.RemoveClient(m_Connection->m_OldServerConnection);
		//m_Connection->m_Server.m_SocketThreads.RemoveClient(m_Connection->m_OldServerConnection);

		return true;
	}

	m_ClientEntityID = EntityID;
	m_ServerEntityID = EntityID;

	cServer::Get()->m_PlayerAmount += 1;
	m_Connection->m_AlreadyCountPlayer = true;

	COPY_TO_CLIENT();
	return true;
}





bool cProtocol172::HandleServerPlayerAnimation(void)
{
	HANDLE_SERVER_PACKET_READ(ReadVarInt, UInt32, PlayerID);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, AnimationID);

	if (PlayerID == m_ServerEntityID)
	{
		m_Connection->m_ServerBuffer.CommitRead();

		// Send the same packet, but with modified Entity ID:
		cByteBuffer Packet(512);
		Packet.WriteByte(0x0B);
		Packet.WriteVarInt(m_ClientEntityID);
		Packet.WriteByte(AnimationID);
		AString Pkt;
		Packet.ReadAll(Pkt);
		cByteBuffer ToClient(512);
		ToClient.WriteVarUTF8String(Pkt);
		CLIENTSEND(ToClient);

		return true;
	}

	COPY_TO_CLIENT();
	return true;
}





bool cProtocol172::HandleServerUseBed(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, EntityID);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, BedX);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, BedY);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, BedZ);

	if (EntityID == m_ServerEntityID)
	{
		m_Connection->m_ServerBuffer.CommitRead();

		// Send the same packet, but with modified Entity ID:
		cByteBuffer Packet(512);
		Packet.WriteByte(0x0A);
		Packet.WriteBEInt(m_ClientEntityID);
		Packet.WriteBEInt(BedX);
		Packet.WriteByte(BedY);
		Packet.WriteBEInt(BedZ);
		AString Pkt;
		Packet.ReadAll(Pkt);
		cByteBuffer ToClient(512);
		ToClient.WriteVarUTF8String(Pkt);
		CLIENTSEND(ToClient);

		return true;
	}

	COPY_TO_CLIENT();
	return true;
}





bool cProtocol172::HandleServerScoreboardObjective(void)
{
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, ObjectiveName);
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, ObjectiveValue);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, Value);

	if (Value == 0)
	{
		cScoreboard Scoreboard;
		Scoreboard.m_ObjectiveName = ObjectiveName;
		Scoreboard.m_ObjectiveValue = ObjectiveValue;
		m_Scoreboards.push_back(Scoreboard);
	}
	else if (Value == 1)
	{
		for (cScoreboards::iterator it = m_Scoreboards.begin(); it != m_Scoreboards.end(); ++it)
		{
			if ((*it).m_ObjectiveName == ObjectiveName)
			{
				m_Scoreboards.erase(it);
				break;
			}
		}
	}

	COPY_TO_CLIENT();
	return true;
}





bool cProtocol172::HandleServerTeams(void)
{
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, TeamName);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, Mode);

	if ((Mode == 0) || (Mode == 2))
	{
		HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, TeamDisplayName);
		HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, TeamPrefix);
		HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, TeamSuffix);
		HANDLE_SERVER_PACKET_READ(ReadByte, Byte, FriendlyFire);
	}
	if ((Mode == 0) || (Mode == 3) || (Mode == 4))
	{
		HANDLE_SERVER_PACKET_READ(ReadBEShort, short, PlayerCount);

		for (short i = 0; i < PlayerCount; i++)
		{
			HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, Player);
		}
	}


	if (Mode == 0)
	{
		m_Teams.push_back(TeamName);
	}
	else if (Mode == 1)
	{
		for (cTeams::iterator it = m_Teams.begin(); it != m_Teams.end(); ++it)
		{
			if ((*it) == TeamName)
			{
				m_Teams.erase(it);
				break;
			}
		}
	}

	COPY_TO_CLIENT();
	return true;
}





bool cProtocol172::HandleServerPlayerListItem(void)
{
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, PlayerName);
	HANDLE_SERVER_PACKET_READ(ReadBool, bool, Online);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, Ping);

	if (Online == true)
	{
		m_TabPlayers.push_back(PlayerName);
	}
	else
	{
		for (cTabPlayers::iterator it = m_TabPlayers.begin(); it != m_TabPlayers.end(); ++it)
		{
			if (*it == PlayerName)
			{
				m_TabPlayers.erase(it);
				break;
			}
		}
	}

	COPY_TO_CLIENT();
	return true;
}





bool cProtocol172::HandleServerPluginMessage(void)
{
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, Channel);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, Length);

	AString data;
	if (!m_Connection->m_ServerBuffer.ReadString(data, Length))
	{
		return false;
	}

	if (Channel == "MCProxy")
	{
		AStringVector Message = StringSplit(data, " ");
		if (Message.size() == 0)
		{
			return true;
		}

		AString LowerMessage = StrToLower(Message[0]);
		if (LowerMessage == "connect")
		{
			if (Message.size() > 2)
			{
				return true;
			}

			AString ServerConfig = cServer::Get()->m_Config.GetValue("Servers", Message[1]);
			if (ServerConfig.empty())
			{
				return true;
			}

			AStringVector ServerData = StringSplit(ServerConfig, ":");
			AString ServerAddress = ServerData[0];
			short ServerPort = (short)atoi(ServerData[1].c_str());

			m_Connection->SwitchServer(ServerAddress, ServerPort);
		}

		else if (LowerMessage == "get")
		{
			if (Message.size() > 2)
			{
				return true;
			}

			AString LowerMessage2 = StrToLower(Message[1]);
			if (LowerMessage2 == "uuid")
			{
				AString UUID = Printf("UUID %s", m_Connection->m_UUID.c_str());

				cByteBuffer Packet(512);
				Packet.WriteByte(0x17);
				Packet.WriteVarUTF8String("MCProxy");
				Packet.WriteBEShort((short)UUID.size());
				Packet.WriteBuf(UUID.data(), UUID.size());
				AString Pkt;
				Packet.ReadAll(Pkt);
				cByteBuffer ToServer(512);
				ToServer.WriteVarUTF8String(Pkt);
				SERVERSEND(ToServer);
			}
		}

		return true;
	}

	COPY_TO_CLIENT();
	return true;
}





bool cProtocol172::HandleServerSpawnPlayer(void)
{
	HANDLE_SERVER_PACKET_READ(ReadVarInt, UInt32, EntityID);
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, EntityUUID);
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, EntityName);
	HANDLE_SERVER_PACKET_READ(ReadVarInt, UInt32, DataCount);

	for (UInt32 i = 0; i < DataCount; i++)
	{
		HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, Name)
		HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, Value)
		HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, Signature)
	}

	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, PosX);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, PosY);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, PosZ);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, Yaw);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, Pitch);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, Item);

	cByteBuffer Packet(512);
	Packet.WriteByte(0x0C);
	Packet.WriteVarInt(EntityID);
	Packet.WriteVarUTF8String(EntityUUID);
	Packet.WriteVarUTF8String(EntityName);
	Packet.WriteBEInt(PosX);
	Packet.WriteBEInt(PosY);
	Packet.WriteBEInt(PosZ);
	Packet.WriteByte(Yaw);
	Packet.WriteByte(Pitch);
	Packet.WriteBEShort(Item);

	if (!ParseMetadata(m_Connection->m_ServerBuffer, Packet))
	{
		return false;
	}
	
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToClient(512);
	ToClient.WriteVarUTF8String(Pkt);
	CLIENTSEND(ToClient);

	return true;
}





bool cProtocol172::HandleServerUnknownPacket(UInt32 a_PacketType, UInt32 a_PacketLen, UInt32 a_PacketReadSoFar)
{
	AString Data;
	ASSERT(a_PacketLen >= a_PacketReadSoFar);
	if (!m_Connection->m_ServerBuffer.ReadString(Data, a_PacketLen - a_PacketReadSoFar))
	{
		return false;
	}

	COPY_TO_CLIENT();
	return true;
}





bool cProtocol172::ParseSlot(cByteBuffer & a_Buffer, cByteBuffer & a_Packet)
{
	short ItemType;
	if (!a_Buffer.ReadBEShort(ItemType))
	{
		return false;
	}
	a_Packet.WriteBEShort(ItemType);

	if (ItemType <= 0)
	{
		return true;
	}
	if (!a_Buffer.CanReadBytes(5))
	{
		return false;
	}
	char ItemCount;
	short ItemDamage;
	short MetadataLength;
	a_Buffer.ReadChar(ItemCount);
	a_Buffer.ReadBEShort(ItemDamage);
	a_Buffer.ReadBEShort(MetadataLength);

	a_Packet.WriteChar(ItemCount);
	a_Packet.WriteBEShort(ItemDamage);
	a_Packet.WriteBEShort(MetadataLength);

	if (MetadataLength <= 0)
	{
		return true;
	}
	AString Metadata;
	Metadata.resize(MetadataLength);
	if (!a_Buffer.ReadBuf((void *)Metadata.data(), MetadataLength))
	{
		return false;
	}

	a_Packet.WriteBuf((void *)Metadata.data(), MetadataLength);

	return true;
}





bool cProtocol172::ParseMetadata(cByteBuffer & a_Buffer, cByteBuffer & a_Packet)
{
	char x;
	if (!a_Buffer.ReadChar(x))
	{
		return false;
	}
	a_Packet.WriteChar(x);

	while (x != 0x7f)
	{
		// int Index = ((unsigned)((unsigned char)x)) & 0x1f;  // Lower 5 bits = index
		int Type = ((unsigned)((unsigned char)x)) >> 5;    // Upper 3 bits = type
		int Length = 0;
		switch (Type)
		{
		case 0: Length = 1; break;  // Byte
		case 1: Length = 2; break;  // short
		case 2: Length = 4; break;  // int
		case 3: Length = 4; break;  // float
		case 4:  // UTF-8 string with VarInt length
		{
					 UInt32 Len;
					 int rs = a_Buffer.GetReadableSpace();
					 if (!a_Buffer.ReadVarInt(Len))
					 {
						 return false;
					 }
					 rs = rs - a_Buffer.GetReadableSpace();
					 cByteBuffer LenBuf(8);
					 LenBuf.WriteVarInt(Len);
					 AString VarLen;
					 LenBuf.ReadAll(VarLen);
					 Length = Len;
					 break;
		}
		case 5:
		{
				  int Before = a_Buffer.GetReadableSpace();
				  if (!ParseSlot(a_Buffer, a_Packet))
				  {
					  return false;
				  }
				  int After = a_Buffer.GetReadableSpace();
				  a_Buffer.ResetRead();
				  a_Buffer.SkipRead(a_Buffer.GetReadableSpace() - Before);
				  Length = Before - After;
				  break;
		}
		case 6: Length = 12; break;  // 3 * int
		case 7: Length = 9; break;
		default:
		{
				   ASSERT(!"Unknown metadata type");
				   break;
		}
		}  // switch (Type)
		AString data;
		if (!a_Buffer.ReadString(data, Length))
		{
			return false;
		}
		a_Packet.Write(data.c_str(), Length);

		if (!a_Buffer.ReadChar(x))
		{
			return false;
		}
		a_Packet.WriteChar(x);

	}  // while (x != 0x7f)
	return true;
}





void cProtocol172::SendChatMessage(AString a_Message, AString a_Color)
{
	AString Message = "\xc2\xa7" + a_Color + a_Message;

	cByteBuffer Packet(512);
	Packet.WriteByte(0x02);
	Packet.WriteVarUTF8String(Printf("{\"text\":\"%s\"}", EscapeString(Message).c_str()));
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToClient(512);
	ToClient.WriteVarUTF8String(Pkt);
	CLIENTSEND(ToClient);
}





///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// cProtocol176:

cProtocol176::cProtocol176(cConnection * a_Connection) :
	super(a_Connection)
{
}





bool cProtocol176::HandleServerSpawnPlayer(void)
{
	HANDLE_SERVER_PACKET_READ(ReadVarInt, UInt32, EntityID);
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, EntityUUID);
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, EntityName);
	HANDLE_SERVER_PACKET_READ(ReadVarInt, UInt32, DataCount);

	cByteBuffer Packet(512);
	Packet.WriteByte(0x0C);
	Packet.WriteVarInt(EntityID);
	Packet.WriteVarUTF8String(EntityUUID);
	Packet.WriteVarUTF8String(EntityName);
	Packet.WriteVarInt(DataCount);

	for (UInt32 i = 0; i < DataCount; i++)
	{
		HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, Name)
		HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, Value)
		HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, Signature)

		Packet.WriteVarUTF8String(Name);
		Packet.WriteVarUTF8String(Value);
		Packet.WriteVarUTF8String(Signature);
	}

	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, PosX);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, PosY);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, PosZ);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, Yaw);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, Pitch);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, CurrentItem);

	Packet.WriteBEInt(PosX);
	Packet.WriteBEInt(PosY);
	Packet.WriteBEInt(PosZ);
	Packet.WriteByte(Yaw);
	Packet.WriteByte(Pitch);
	Packet.WriteBEShort(CurrentItem);

	if (!ParseMetadata(m_Connection->m_ServerBuffer, Packet))
	{
		return false;
	}

	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToClient(512);
	ToClient.WriteVarUTF8String(Pkt);
	CLIENTSEND(ToClient);

	return true;
}





bool cProtocol176::HandleClientStatusRequest(void)
{
	// Send the response:
	AString Response = "{\"version\":{\"name\":\"1.7.6\",\"protocol\":5},\"players\":{";
	AppendPrintf(Response, "\"max\":%u,\"online\":%u,\"sample\":[]},",
		cServer::Get()->m_MaxPlayers,
		cServer::Get()->m_PlayerAmount
		);
	AppendPrintf(Response, "\"description\":{\"text\":\"%s\"},",
		cServer::Get()->m_MOTD.c_str()
		);
	AppendPrintf(Response, "\"favicon\":\"data:image/png;base64,%s\"",
		cServer::Get()->m_FaviconData.c_str()
		);
	Response.append("}");

	cByteBuffer Packet(512);
	Packet.WriteByte(0x00);
	Packet.WriteVarUTF8String(Response);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToClient(512);
	ToClient.WriteVarUTF8String(Pkt);
	CLIENTSEND(ToClient);

	return true;
}






