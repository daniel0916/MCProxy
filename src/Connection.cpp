
// Connection.cpp

// Interfaces to the cConnection class representing a single pair of connected sockets

#include "Globals.h"
#include "Connection.h"
#include "Server.h"
#include "ServerConnection.h"
#include "PolarSSL++/PublicKey.h"
#include <iostream>

#ifdef _WIN32
	#include <direct.h>  // For _mkdir()
#endif




/// When defined, the following macro causes a sleep after each parsed packet (DEBUG-mode only)
// #define SLEEP_AFTER_PACKET





#if defined(_DEBUG) && defined(SLEEP_AFTER_PACKET)
	#define DebugSleep Sleep
#else
	#define DebugSleep(X)
#endif  // else _DEBUG





#define HANDLE_CLIENT_PACKET_READ(Proc, Type, Var) \
	Type Var; \
	{ \
		if (!m_ClientBuffer.Proc(Var)) \
		{ \
			return false; \
		} \
	}

#define HANDLE_SERVER_PACKET_READ(Proc, Type, Var) \
	Type Var; \
	{ \
		if (!m_ServerBuffer.Proc(Var)) \
		{ \
			return false; \
		} \
	}

#define CLIENTSEND(...) SendData(m_ClientSocket, __VA_ARGS__, "Client")
#define SERVERSEND(...) SendData(m_ServerSocket, __VA_ARGS__, "Server")
#define CLIENTENCRYPTSEND(...) SendData(m_ClientSocket, __VA_ARGS__, "Client")  // The client conn is always unencrypted
#define SERVERENCRYPTSEND(...) SendEncryptedData(m_ServerSocket, m_ServerEncryptor, __VA_ARGS__, "Server")

#define COPY_TO_SERVER() \
	{ \
		AString ToServer; \
		m_ClientBuffer.ReadAgain(ToServer); \
		switch (m_ServerState) \
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
				m_ServerEncryptionBuffer.append(ToServer.data(), ToServer.size()); \
				break; \
			} \
		} \
		DebugSleep(50); \
	}

#define COPY_TO_CLIENT() \
	{ \
	AString ToClient; \
	m_ServerBuffer.ReadAgain(ToClient); \
	switch (m_ClientState) \
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
			/* case csWaitingForEncryption: \
			{ \
				Log("Waiting for client encryption, queued %u bytes", ToClient.size()); \
				m_ClientEncryptionBuffer.append(ToClient.data(), ToClient.size()); \
				break; \
			} \
			*/ \
		} \
		DebugSleep(50); \
	}

#define HANDLE_CLIENT_READ(Proc) \
	{ \
		if (!Proc) \
		{ \
			AString Leftover; \
			m_ClientBuffer.ReadAgain(Leftover); \
			m_ClientBuffer.ResetRead(); \
			return true; \
		} \
	}
	
#define HANDLE_SERVER_READ(Proc) \
	{ \
		if (!Proc) \
		{ \
			m_ServerBuffer.ResetRead(); \
			return true; \
		} \
	}
	




typedef unsigned char Byte;





///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// cConnection:

cConnection::cConnection(cSocket a_ClientSocket, cSocket a_ServerSocket, cServer & a_Server) :
	m_ItemIdx(0),
	m_Server(a_Server),
	m_ClientSocket(a_ClientSocket),
	m_ServerSocket(a_ServerSocket),
	m_ClientState(csUnencrypted),
	m_ServerState(csUnencrypted),
	m_ClientBuffer(1024 KiB),
	m_ServerBuffer(1024 KiB),
	m_HasClientPinged(false),
	m_ServerProtocolState(-1),
	m_ClientProtocolState(-1),
	m_IsServerEncrypted(false),
	m_SwitchServer(false)
{
}





cConnection::~cConnection()
{
}





bool cConnection::SendData(cSocket a_Socket, const char * a_Data, size_t a_Size, const char * a_Peer)
{
	int res = a_Socket.Send(a_Data, a_Size);
	if (res <= 0)
	{
		return false;
	}

	return true;
}





bool cConnection::SendData(cSocket a_Socket, cByteBuffer & a_Data, const char * a_Peer)
{
	AString All;
	a_Data.ReadAll(All);
	a_Data.CommitRead();
	return SendData(a_Socket, All.data(), All.size(), a_Peer);
}





bool cConnection::SendEncryptedData(cSocket a_Socket, cAesCfb128Encryptor & a_Encryptor, const char * a_Data, size_t a_Size, const char * a_Peer)
{
	const Byte * Data = (const Byte *)a_Data;
	while (a_Size > 0)
	{
		Byte Buffer[64 KiB];
		size_t NumBytes = (a_Size > sizeof(Buffer)) ? sizeof(Buffer) : a_Size;
		a_Encryptor.ProcessData(Buffer, Data, NumBytes);
		bool res = SendData(a_Socket, (const char *)Buffer, NumBytes, a_Peer);
		if (!res)
		{
			return false;
		}
		Data += NumBytes;
		a_Size -= NumBytes;
	}
	return true;
}





bool cConnection::SendEncryptedData(cSocket a_Socket, cAesCfb128Encryptor & a_Encryptor, cByteBuffer & a_Data, const char * a_Peer)
{
	AString All;
	a_Data.ReadAll(All);
	a_Data.CommitRead();
	return SendEncryptedData(a_Socket, a_Encryptor, All.data(), All.size(), a_Peer);
}





bool cConnection::DecodeClientsPackets(const char * a_Data, int a_Size)
{
	if (!m_ClientBuffer.Write(a_Data, a_Size))
	{
		return false;
	}
	
	while (m_ClientBuffer.CanReadBytes(1))
	{
		UInt32 PacketLen;
		if (
			!m_ClientBuffer.ReadVarInt(PacketLen) ||
			!m_ClientBuffer.CanReadBytes(PacketLen)
		)
		{
			// Not a complete packet yet
			break;
		}
		UInt32 PacketType, PacketReadSoFar;
		PacketReadSoFar = m_ClientBuffer.GetReadableSpace();
		VERIFY(m_ClientBuffer.ReadVarInt(PacketType));
		PacketReadSoFar -= m_ClientBuffer.GetReadableSpace();
		switch (m_ClientProtocolState)
		{
			case -1:
			{
				// No initial handshake received yet
				switch (PacketType)
				{
					case 0x00: HANDLE_CLIENT_READ(HandleClientHandshake()); break;
					default:   HANDLE_CLIENT_READ(HandleClientUnknownPacket(PacketType, PacketLen, PacketReadSoFar)); break;
				}
				break;
			}  // case -1
			
			case 1:
			{
				// Status query
				switch (PacketType)
				{
					case 0x00: HANDLE_CLIENT_READ(HandleClientStatusRequest()); break;
					case 0x01: HANDLE_CLIENT_READ(HandleClientStatusPing()); break;
					default:   HANDLE_CLIENT_READ(HandleClientUnknownPacket(PacketType, PacketLen, PacketReadSoFar)); break;
				}
				break;
			}
			
			case 2:
			{
				// Login
				switch (PacketType)
				{
					case 0x00: HANDLE_CLIENT_READ(HandleClientLoginStart()); break;
					case 0x01: HANDLE_CLIENT_READ(HandleClientLoginEncryptionKeyResponse()); break;
					default:   HANDLE_CLIENT_READ(HandleClientUnknownPacket(PacketType, PacketLen, PacketReadSoFar)); break;
				}
				break;
			}
			
			case 3:
			{
				// Game:
				switch (PacketType)
				{
					case 0x00: HANDLE_CLIENT_READ(HandleClientKeepAlive()); break;
					case 0x01: HANDLE_CLIENT_READ(HandleClientChatMessage()); break;
					case 0x02: HANDLE_CLIENT_READ(HandleClientUseEntity()); break;
					case 0x03: HANDLE_CLIENT_READ(HandleClientPlayerOnGround()); break;
					case 0x04: HANDLE_CLIENT_READ(HandleClientPlayerPosition()); break;
					case 0x05: HANDLE_CLIENT_READ(HandleClientPlayerLook()); break;
					case 0x06: HANDLE_CLIENT_READ(HandleClientPlayerPositionLook()); break;
					case 0x07: HANDLE_CLIENT_READ(HandleClientBlockDig()); break;
					case 0x08: HANDLE_CLIENT_READ(HandleClientBlockPlace()); break;
					case 0x09: HANDLE_CLIENT_READ(HandleClientSlotSelect()); break;
					case 0x0a: HANDLE_CLIENT_READ(HandleClientAnimation()); break;
					case 0x0b: HANDLE_CLIENT_READ(HandleClientEntityAction()); break;
					case 0x0d: HANDLE_CLIENT_READ(HandleClientWindowClose()); break;
					case 0x0e: HANDLE_CLIENT_READ(HandleClientWindowClick()); break;
					case 0x10: HANDLE_CLIENT_READ(HandleClientCreativeInventoryAction()); break;
					case 0x12: HANDLE_CLIENT_READ(HandleClientUpdateSign()); break;
					case 0x13: HANDLE_CLIENT_READ(HandleClientPlayerAbilities()); break;
					case 0x14: HANDLE_CLIENT_READ(HandleClientTabCompletion()); break;
					case 0x15: HANDLE_CLIENT_READ(HandleClientLocaleAndView()); break;
					case 0x16: HANDLE_CLIENT_READ(HandleClientClientStatuses()); break;
					case 0x17: HANDLE_CLIENT_READ(HandleClientPluginMessage()); break;
					default:   HANDLE_CLIENT_READ(HandleClientUnknownPacket(PacketType, PacketLen, PacketReadSoFar)); break;
				}
				break;
			}  // case 3 - Game
			
			default:
			{
				HANDLE_CLIENT_READ(HandleClientUnknownPacket(PacketType, PacketLen, PacketReadSoFar));
				break;
			}
		}  // switch (m_ProtocolState)
		m_ClientBuffer.CommitRead();
	}  // while (true)
	return true;
}





bool cConnection::DecodeServersPackets(const char * a_Data, int a_Size)
{
	if (!m_ServerBuffer.Write(a_Data, a_Size))
	{
		return false;
	}
	
	if (
		(m_ServerState == csEncryptedUnderstood) &&
		(m_ClientState == csUnencrypted)
	)
	{
		// Client hasn't finished encryption handshake yet, don't send them any data yet
	}
	
	while (true)
	{
		UInt32 PacketLen;
		if (
			!m_ServerBuffer.ReadVarInt(PacketLen) ||
			!m_ServerBuffer.CanReadBytes(PacketLen)
		)
		{
			// Not a complete packet yet
			m_ServerBuffer.ResetRead();
			break;
		}
		if (PacketLen == 0)
		{
			m_ServerBuffer.ResetRead();
			AString All;
			m_ServerBuffer.ReadAll(All);
			m_ServerBuffer.CommitRead();  // Try to recover by marking everything as read
			break;
		}
		UInt32 PacketType, PacketReadSoFar;
		PacketReadSoFar = m_ServerBuffer.GetReadableSpace();
		VERIFY(m_ServerBuffer.ReadVarInt(PacketType));
		PacketReadSoFar -= m_ServerBuffer.GetReadableSpace();

		switch (m_ServerProtocolState)
		{
			case -1:
			{
				HANDLE_SERVER_READ(HandleServerUnknownPacket(PacketType, PacketLen, PacketReadSoFar));
				break;
			}
			
			case 1:
			{
				// Status query:
				switch (PacketType)
				{
					case 0x00: HANDLE_SERVER_READ(HandleServerStatusResponse()); break;
					case 0x01: HANDLE_SERVER_READ(HandleServerStatusPing());     break;
					default:   HANDLE_SERVER_READ(HandleServerUnknownPacket(PacketType, PacketLen, PacketReadSoFar)); break;
				}
				break;
			}
			
			case 2:
			{
				// Login:
				switch (PacketType)
				{
					case 0x00: HANDLE_SERVER_READ(HandleServerLoginDisconnect()); break;
					case 0x01: HANDLE_SERVER_READ(HandleServerLoginEncryptionKeyRequest()); break;
					case 0x02: HANDLE_SERVER_READ(HandleServerLoginSuccess()); break;
					default:   HANDLE_SERVER_READ(HandleServerUnknownPacket(PacketType, PacketLen, PacketReadSoFar)); break;
				}
				break;
			}
			
			case 3:
			{
				// Game:
				switch (PacketType)
				{
					case 0x00: HANDLE_SERVER_READ(HandleServerKeepAlive()); break;
					case 0x01: HANDLE_SERVER_READ(HandleServerJoinGame()); break;
					case 0x02: HANDLE_SERVER_READ(HandleServerChatMessage()); break;
					case 0x03: HANDLE_SERVER_READ(HandleServerTimeUpdate()); break;
					case 0x04: HANDLE_SERVER_READ(HandleServerEntityEquipment()); break;
					case 0x05: HANDLE_SERVER_READ(HandleServerCompass()); break;
					case 0x06: HANDLE_SERVER_READ(HandleServerUpdateHealth()); break;
					case 0x07: HANDLE_SERVER_READ(HandleServerRespawn()); break;
					case 0x08: HANDLE_SERVER_READ(HandleServerPlayerPositionLook()); break;
					case 0x09: HANDLE_SERVER_READ(HandleServerSlotSelect()); break;
					case 0x0a: HANDLE_SERVER_READ(HandleServerUseBed()); break;
					case 0x0b: HANDLE_SERVER_READ(HandleServerPlayerAnimation()); break;
					case 0x0c: HANDLE_SERVER_READ(HandleServerSpawnNamedEntity()); break;
					case 0x0d: HANDLE_SERVER_READ(HandleServerCollectPickup()); break;
					case 0x0e: HANDLE_SERVER_READ(HandleServerSpawnObjectVehicle()); break;
					case 0x0f: HANDLE_SERVER_READ(HandleServerSpawnMob()); break;
					case 0x10: HANDLE_SERVER_READ(HandleServerSpawnPainting()); break;
					case 0x11: HANDLE_SERVER_READ(HandleServerSpawnExperienceOrbs()); break;
					case 0x12: HANDLE_SERVER_READ(HandleServerEntityVelocity()); break;
					case 0x13: HANDLE_SERVER_READ(HandleServerDestroyEntities()); break;
					case 0x14: HANDLE_SERVER_READ(HandleServerEntity()); break;
					case 0x15: HANDLE_SERVER_READ(HandleServerEntityRelativeMove()); break;
					case 0x16: HANDLE_SERVER_READ(HandleServerEntityLook()); break;
					case 0x17: HANDLE_SERVER_READ(HandleServerEntityRelativeMoveLook()); break;
					case 0x18: HANDLE_SERVER_READ(HandleServerEntityTeleport()); break;
					case 0x19: HANDLE_SERVER_READ(HandleServerEntityHeadLook()); break;
					case 0x1a: HANDLE_SERVER_READ(HandleServerEntityStatus()); break;
					case 0x1b: HANDLE_SERVER_READ(HandleServerAttachEntity()); break;
					case 0x1c: HANDLE_SERVER_READ(HandleServerEntityMetadata()); break;
					case 0x1f: HANDLE_SERVER_READ(HandleServerSetExperience()); break;
					case 0x20: HANDLE_SERVER_READ(HandleServerEntityProperties()); break;
					case 0x21: HANDLE_SERVER_READ(HandleServerMapChunk()); break;
					case 0x22: HANDLE_SERVER_READ(HandleServerMultiBlockChange()); break;
					case 0x23: HANDLE_SERVER_READ(HandleServerBlockChange()); break;
					case 0x24: HANDLE_SERVER_READ(HandleServerBlockAction()); break;
					case 0x26: HANDLE_SERVER_READ(HandleServerMapChunkBulk()); break;
					case 0x27: HANDLE_SERVER_READ(HandleServerExplosion()); break;
					case 0x28: HANDLE_SERVER_READ(HandleServerSoundEffect()); break;
					case 0x29: HANDLE_SERVER_READ(HandleServerNamedSoundEffect()); break;
					case 0x2b: HANDLE_SERVER_READ(HandleServerChangeGameState()); break;
					case 0x2d: HANDLE_SERVER_READ(HandleServerWindowOpen()); break;
					case 0x2e: HANDLE_SERVER_READ(HandleServerWindowClose()); break;
					case 0x2f: HANDLE_SERVER_READ(HandleServerSetSlot()); break;
					case 0x30: HANDLE_SERVER_READ(HandleServerWindowContents()); break;
					case 0x33: HANDLE_SERVER_READ(HandleServerUpdateSign()); break;
					case 0x35: HANDLE_SERVER_READ(HandleServerUpdateTileEntity()); break;
					case 0x37: HANDLE_SERVER_READ(HandleServerStatistics()); break;
					case 0x38: HANDLE_SERVER_READ(HandleServerPlayerListItem()); break;
					case 0x39: HANDLE_SERVER_READ(HandleServerPlayerAbilities()); break;
					case 0x3a: HANDLE_SERVER_READ(HandleServerTabCompletion()); break;
					case 0x3b: HANDLE_SERVER_READ(HandleServerScoreboardObjective()); break;
					case 0x3e: HANDLE_SERVER_READ(HandleServerTeams()); break;
					case 0x3f: HANDLE_SERVER_READ(HandleServerPluginMessage()); break;
					case 0x40: HANDLE_SERVER_READ(HandleServerKick()); break;
					default:   HANDLE_SERVER_READ(HandleServerUnknownPacket(PacketType, PacketLen, PacketReadSoFar)); break;
				}  // switch (PacketType)
				break;
			}  // case 3 - Game
			
			// TODO: Move this elsewhere
			default:
			{
				HANDLE_SERVER_READ(HandleServerUnknownPacket(PacketType, PacketLen, PacketReadSoFar));
				break;
			}
		}  // switch (m_ProtocolState)
		
		m_ServerBuffer.CommitRead();
	}  // while (CanReadBytes(1))
	return true;
}





///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// packet handling, client-side, initial handshake:

bool cConnection::HandleClientHandshake(void)
{
	// Read the packet from the client:
	HANDLE_CLIENT_PACKET_READ(ReadVarInt,        UInt32,  ProtocolVersion);
	HANDLE_CLIENT_PACKET_READ(ReadVarUTF8String, AString, ServerHost);
	HANDLE_CLIENT_PACKET_READ(ReadBEShort,       short,   ServerPort);
	HANDLE_CLIENT_PACKET_READ(ReadVarInt,        UInt32,  NextState);
	m_ClientBuffer.CommitRead();

	// Send the same packet to the server, but with our port:
	cByteBuffer Packet(512);
	Packet.WriteVarInt(0);  // Packet type - initial handshake
	Packet.WriteVarInt(ProtocolVersion);
	Packet.WriteVarUTF8String(ServerHost);
	Packet.WriteBEShort(m_Server.GetConnectPort());
	Packet.WriteVarInt(NextState);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToServer(512);
	ToServer.WriteVarUTF8String(Pkt);
	SERVERSEND(ToServer);
	
	m_ClientProtocolState = (int)NextState;
	m_ServerProtocolState = (int)NextState;
	
	return true;
}





///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// packet handling, client-side, login:

bool cConnection::HandleClientLoginEncryptionKeyResponse(void)
{
	return true;
}





bool cConnection::HandleClientLoginStart(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadVarUTF8String, AString, UserName);

	COPY_TO_SERVER();
	return true;
}





///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// packet handling, client-side, game:

bool cConnection::HandleClientAnimation(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadBEInt, int,  EntityID);
	HANDLE_CLIENT_PACKET_READ(ReadChar,  char, Animation);

	if (EntityID == m_ClientEntityID)
	{
		m_ClientBuffer.CommitRead();

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
	}
	else
	{
		COPY_TO_SERVER();
	}

	return true;
}





bool cConnection::HandleClientBlockDig(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadByte,  Byte, Status);
	HANDLE_CLIENT_PACKET_READ(ReadBEInt, int,  BlockX);
	HANDLE_CLIENT_PACKET_READ(ReadByte,  Byte, BlockY);
	HANDLE_CLIENT_PACKET_READ(ReadBEInt, int,  BlockZ);
	HANDLE_CLIENT_PACKET_READ(ReadByte,  Byte, BlockFace);

	COPY_TO_SERVER();
	return true;
}





bool cConnection::HandleClientBlockPlace(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadBEInt, int,  BlockX);
	HANDLE_CLIENT_PACKET_READ(ReadByte,  Byte, BlockY);
	HANDLE_CLIENT_PACKET_READ(ReadBEInt, int,  BlockZ);
	HANDLE_CLIENT_PACKET_READ(ReadChar,  char, Face);
	AString Desc;
	if (!ParseSlot(m_ClientBuffer, Desc))
	{
		return false;
	}
	HANDLE_CLIENT_PACKET_READ(ReadChar,  char, CursorX);
	HANDLE_CLIENT_PACKET_READ(ReadChar,  char, CursorY);
	HANDLE_CLIENT_PACKET_READ(ReadChar,  char, CursorZ);

	COPY_TO_SERVER();
	return true;
}





bool cConnection::HandleClientChatMessage(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadVarUTF8String, AString, Message);

	AStringVector ChatMessage = StringSplit(Message, " ");
	if (ChatMessage[0] == "/server")
	{
		if (ChatMessage.size() < 2)
		{
			return true;
		}
		AString ServerConfig = m_Server.m_Config.GetValue("Servers", ChatMessage[1]);
		if (ServerConfig.empty())
		{
			// Server not available (TODO: Send a message to the client)
			return true;
		}

		AStringVector ServerData = StringSplit(ServerConfig, ":");
		AString ServerAddress = ServerData[0];
		int ServerPort = atoi(ServerData[1].c_str());

		SOCKET ServerSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (ServerSocket == INVALID_SOCKET)
		{
			return true;
		}

		cSocket Socket = cSocket(ServerSocket);
		if (!Socket.ConnectIPv4(ServerAddress, ServerPort))
		{
			return true;
		}
		
		m_SwitchServer = true;
		m_ServerConnection->m_ShouldSend = false;

		// Clear Buffers
		AString data;
		m_ServerBuffer.ReadAll(data);
		m_ServerBuffer.CommitRead();
		m_ServerEncryptionBuffer.clear();

		// Remove Scoreboards
		for (cScoreboards::iterator it = m_Scoreboards.begin(); it != m_Scoreboards.end(); ++it)
		{
			cByteBuffer ScoreboardPacket(512);
			ScoreboardPacket.WriteByte(0x3B);
			ScoreboardPacket.WriteVarUTF8String((*it).m_ObjectiveName);
			ScoreboardPacket.WriteVarUTF8String((*it).m_ObjectiveValue);
			ScoreboardPacket.WriteByte(1);
			AString ScoreboardPkt;
			ScoreboardPacket.ReadAll(ScoreboardPkt);
			cByteBuffer ScoreboardToClient(512);
			ScoreboardToClient.WriteVarUTF8String(ScoreboardPkt);
			CLIENTSEND(ScoreboardToClient);
		}
		m_Scoreboards.clear();

		// Remove Teams
		for (cTeams::iterator it = m_Teams.begin(); it != m_Teams.end(); ++it)
		{
			cByteBuffer ScoreboardPacket(512);
			ScoreboardPacket.WriteByte(0x3E);
			ScoreboardPacket.WriteVarUTF8String((*it));
			ScoreboardPacket.WriteByte(1);
			AString ScoreboardPkt;
			ScoreboardPacket.ReadAll(ScoreboardPkt);
			cByteBuffer ScoreboardToClient(512);
			ScoreboardToClient.WriteVarUTF8String(ScoreboardPkt);
			CLIENTSEND(ScoreboardToClient);
		}
		m_Teams.clear();

		cServerConnection * Server = new cServerConnection(this, m_Server);
		m_Server.m_SocketThreads.AddClient(Socket, Server);

		m_OldServerConnection = m_ServerConnection;
		m_ServerConnection = Server;
		m_ServerSocket = Socket;

		cByteBuffer HandshakePacket(512);
		HandshakePacket.WriteByte(0x00);
		HandshakePacket.WriteVarInt(4);
		HandshakePacket.WriteVarUTF8String("localhost");
		HandshakePacket.WriteBEShort(25566);
		HandshakePacket.WriteVarInt(2);
		AString HandshakePkt;
		HandshakePacket.ReadAll(HandshakePkt);
		cByteBuffer HandshakeToServer(512);
		HandshakeToServer.WriteVarUTF8String(HandshakePkt);
		SERVERSEND(HandshakeToServer);

		cByteBuffer LoginStartPacket(512);
		LoginStartPacket.WriteByte(0x00);
		LoginStartPacket.WriteVarUTF8String("CryptoCrafter");
		AString LoginStartPkt;
		LoginStartPacket.ReadAll(LoginStartPkt);
		cByteBuffer LoginStartToServer(512);
		LoginStartToServer.WriteVarUTF8String(LoginStartPkt);
		SERVERSEND(LoginStartToServer);

		m_ServerProtocolState = 2;
	}
	else
	{
		COPY_TO_SERVER();
	}
	
	return true;
}





bool cConnection::HandleClientClientStatuses(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadChar, char, Statuses);

	COPY_TO_SERVER();
	return true;
}





bool cConnection::HandleClientCreativeInventoryAction(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadBEShort, short, SlotNum);
	AString Item;
	if (!ParseSlot(m_ClientBuffer, Item))
	{
		return false;
	}

	COPY_TO_SERVER();
	return true;
}





bool cConnection::HandleClientDisconnect(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadVarUTF8String, AString, Reason);

	COPY_TO_SERVER();
	return true;
}





bool cConnection::HandleClientEntityAction(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadBEInt, int,  PlayerID);
	HANDLE_CLIENT_PACKET_READ(ReadByte,  Byte, ActionType);
	HANDLE_CLIENT_PACKET_READ(ReadBEInt, int,  HorseJumpBoost);

	if (PlayerID == m_ClientEntityID)
	{
		m_ClientBuffer.CommitRead();

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
	}
	else
	{
		COPY_TO_SERVER();
	}

	return true;
}





bool cConnection::HandleClientKeepAlive(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadBEInt, int, ID);

	COPY_TO_SERVER();
	return true;
}





bool cConnection::HandleClientLocaleAndView(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadVarUTF8String, AString, Locale);
	HANDLE_CLIENT_PACKET_READ(ReadChar,          char,    ViewDistance);
	HANDLE_CLIENT_PACKET_READ(ReadChar,          char,    ChatFlags);
	HANDLE_CLIENT_PACKET_READ(ReadChar,          char,    Unused);
	HANDLE_CLIENT_PACKET_READ(ReadChar,          char,    Difficulty);
	HANDLE_CLIENT_PACKET_READ(ReadChar,          char,    ShowCape);

	COPY_TO_SERVER();
	return true;
}





bool cConnection::HandleClientPing(void)
{
	m_HasClientPinged = true;
	m_ClientBuffer.ResetRead();

	SERVERSEND(m_ClientBuffer);
	return true;
}





bool cConnection::HandleClientPlayerAbilities(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadChar,    char, Flags);
	HANDLE_CLIENT_PACKET_READ(ReadBEFloat, float, FlyingSpeed);
	HANDLE_CLIENT_PACKET_READ(ReadBEFloat, float, WalkingSpeed);

	COPY_TO_SERVER();
	return true;
}





bool cConnection::HandleClientPlayerLook(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadBEFloat, float, Yaw);
	HANDLE_CLIENT_PACKET_READ(ReadBEFloat, float, Pitch);
	HANDLE_CLIENT_PACKET_READ(ReadChar,    char,  OnGround);

	COPY_TO_SERVER();
	return true;
}





bool cConnection::HandleClientPlayerOnGround(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadChar, char, OnGround);

	if (!m_SwitchServer)
	{
		COPY_TO_SERVER();
	}
	
	return true;
}





bool cConnection::HandleClientPlayerPosition(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadBEDouble, double, PosX);
	HANDLE_CLIENT_PACKET_READ(ReadBEDouble, double, PosY);
	HANDLE_CLIENT_PACKET_READ(ReadBEDouble, double, Stance);
	HANDLE_CLIENT_PACKET_READ(ReadBEDouble, double, PosZ);
	HANDLE_CLIENT_PACKET_READ(ReadChar,     char,   IsOnGround);
	
	COPY_TO_SERVER();
	return true;
}





bool cConnection::HandleClientPlayerPositionLook(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadBEDouble, double, PosX);
	HANDLE_CLIENT_PACKET_READ(ReadBEDouble, double, PosY);
	HANDLE_CLIENT_PACKET_READ(ReadBEDouble, double, Stance);
	HANDLE_CLIENT_PACKET_READ(ReadBEDouble, double, PosZ);
	HANDLE_CLIENT_PACKET_READ(ReadBEFloat,  float,  Yaw);
	HANDLE_CLIENT_PACKET_READ(ReadBEFloat,  float,  Pitch);
	HANDLE_CLIENT_PACKET_READ(ReadChar,     char,   IsOnGround);
	
	COPY_TO_SERVER();
	return true;
}





bool cConnection::HandleClientPluginMessage(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadVarUTF8String, AString, ChannelName);
	HANDLE_CLIENT_PACKET_READ(ReadBEShort,         short,   Length);
	AString Data;
	if (!m_ClientBuffer.ReadString(Data, Length))
	{
		return false;
	}

	COPY_TO_SERVER();
	return true;
}





bool cConnection::HandleClientSlotSelect(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadBEShort, short, SlotNum);

	COPY_TO_SERVER();
	return true;
}





bool cConnection::HandleClientStatusPing(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadBEInt64, Int64, Time);

	COPY_TO_SERVER();
	return true;
}





bool cConnection::HandleClientStatusRequest(void)
{
	COPY_TO_SERVER();
	return true;
}





bool cConnection::HandleClientTabCompletion(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadVarUTF8String, AString, Query);

	COPY_TO_SERVER();
	return true;
}





bool cConnection::HandleClientUpdateSign(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadBEInt,         int,     BlockX);
	HANDLE_CLIENT_PACKET_READ(ReadBEShort,       short,   BlockY);
	HANDLE_CLIENT_PACKET_READ(ReadBEInt,         int,     BlockZ);
	HANDLE_CLIENT_PACKET_READ(ReadVarUTF8String, AString, Line1);
	HANDLE_CLIENT_PACKET_READ(ReadVarUTF8String, AString, Line2);
	HANDLE_CLIENT_PACKET_READ(ReadVarUTF8String, AString, Line3);
	HANDLE_CLIENT_PACKET_READ(ReadVarUTF8String, AString, Line4);

	COPY_TO_SERVER();
	return true;
}





bool cConnection::HandleClientUseEntity(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadBEInt, int,  EntityID);
	HANDLE_CLIENT_PACKET_READ(ReadChar,  char, MouseButton);

	if (EntityID == m_ClientEntityID)
	{
		m_ClientBuffer.CommitRead();

		// Send the same packet, but with modified Entity ID:
		cByteBuffer Packet(512);
		Packet.WriteByte(0x02);
		Packet.WriteBEInt(m_ServerEntityID);
		Packet.WriteChar(MouseButton);
		AString Pkt;
		Packet.ReadAll(Pkt);
		cByteBuffer ToServer(512);
		ToServer.WriteVarUTF8String(Pkt);
		SERVERSEND(ToServer);
	}
	else
	{
		COPY_TO_SERVER();
	}

	return true;
}





bool cConnection::HandleClientWindowClick(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadChar,    char,  WindowID);
	HANDLE_CLIENT_PACKET_READ(ReadBEShort, short, SlotNum);
	HANDLE_CLIENT_PACKET_READ(ReadChar,    char,  Button);
	HANDLE_CLIENT_PACKET_READ(ReadBEShort, short, TransactionID);
	HANDLE_CLIENT_PACKET_READ(ReadChar,    char,  Mode);
	AString Item;
	if (!ParseSlot(m_ClientBuffer, Item))
	{
		return false;
	}

	COPY_TO_SERVER();
	return true;
}





bool cConnection::HandleClientWindowClose(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadChar, char, WindowID);

	COPY_TO_SERVER();
	return true;
}





bool cConnection::HandleClientUnknownPacket(UInt32 a_PacketType, UInt32 a_PacketLen, UInt32 a_PacketReadSoFar)
{
	AString Data;
	if (!m_ClientBuffer.ReadString(Data, a_PacketLen - a_PacketReadSoFar))
	{
		return false;
	}

	COPY_TO_SERVER();

	return true;
}





///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// packet handling, server-side, login:

bool cConnection::HandleServerLoginDisconnect(void)
{
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, Reason);

	COPY_TO_CLIENT();
	return true;
}





bool cConnection::HandleServerLoginEncryptionKeyRequest(void)
{
	// Read the packet from the server:
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, ServerID);
	HANDLE_SERVER_PACKET_READ(ReadBEShort,       short,   PublicKeyLength);
	AString PublicKey;
	if (!m_ServerBuffer.ReadString(PublicKey, PublicKeyLength))
	{
		return false;
	}
	HANDLE_SERVER_PACKET_READ(ReadBEShort,       short,   NonceLength);
	AString Nonce;
	if (!m_ServerBuffer.ReadString(Nonce, NonceLength))
	{
		return false;
	}
	
	// Reply to the server:
	SendEncryptionKeyResponse(PublicKey, Nonce);
	
	// Do not send to client - we want the client connection open
	return true;
}





bool cConnection::HandleServerLoginSuccess(void)
{
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, UUID);
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, Username);

	if (m_SwitchServer)
	{
		m_ServerProtocolState = 3;
		return true;
	}

	m_ServerProtocolState = 3;
	
	if (m_IsServerEncrypted)
	{
		m_ServerState = csEncryptedUnderstood;
		SERVERENCRYPTSEND(m_ServerEncryptionBuffer.data(), m_ServerEncryptionBuffer.size());
		m_ServerEncryptionBuffer.clear();
	}
	COPY_TO_CLIENT();
	m_ClientProtocolState = 3;
	return true;
}





///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// packet handling, server-side, game:

bool cConnection::HandleServerAttachEntity(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int,  EntityID);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int,  VehicleID);
	HANDLE_SERVER_PACKET_READ(ReadBool,  bool, Leash);

	if (EntityID == m_ServerEntityID)
	{
		m_ServerBuffer.CommitRead();

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
	}
	else
	{
		COPY_TO_CLIENT();
	}

	return true;
}





bool cConnection::HandleServerBlockAction(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt,   int,    BlockX);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short,  BlockY);
	HANDLE_SERVER_PACKET_READ(ReadBEInt,   int,    BlockZ);
	HANDLE_SERVER_PACKET_READ(ReadByte,    Byte,   Byte1);
	HANDLE_SERVER_PACKET_READ(ReadByte,    Byte,   Byte2);
	HANDLE_SERVER_PACKET_READ(ReadVarInt,  UInt32, BlockID);

	COPY_TO_CLIENT();
	return true;
}





bool cConnection::HandleServerBlockChange(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt,   int,    BlockX);
	HANDLE_SERVER_PACKET_READ(ReadByte,    Byte,   BlockY);
	HANDLE_SERVER_PACKET_READ(ReadBEInt,   int,    BlockZ);
	HANDLE_SERVER_PACKET_READ(ReadVarInt,  UInt32, BlockType);
	HANDLE_SERVER_PACKET_READ(ReadChar,    char,   BlockMeta);

	COPY_TO_CLIENT();
	return true;
}





bool cConnection::HandleServerChangeGameState(void)
{
	HANDLE_SERVER_PACKET_READ(ReadChar,    char,  Reason);
	HANDLE_SERVER_PACKET_READ(ReadBEFloat, float, Data);

	COPY_TO_CLIENT();
	return true;
}





bool cConnection::HandleServerChatMessage(void)
{
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, Message);

	COPY_TO_CLIENT();
	return true;
}





bool cConnection::HandleServerCollectPickup(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, CollectedID);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, CollectorID);

	COPY_TO_CLIENT();
	return true;
}





bool cConnection::HandleServerCompass(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, SpawnX);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, SpawnY);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, SpawnZ);

	COPY_TO_CLIENT();
	return true;
}





bool cConnection::HandleServerDestroyEntities(void)
{
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, NumEntities);
	if (!m_ServerBuffer.SkipRead((int)NumEntities * 4))
	{
		return false;
	}

	COPY_TO_CLIENT();
	return true;
}





bool cConnection::HandleServerEntity(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, EntityID);

	if (EntityID == m_ServerEntityID)
	{
		m_ServerBuffer.CommitRead();

		// Send the same packet, but with modified Entity ID:
		cByteBuffer Packet(512);
		Packet.WriteByte(0x14);
		Packet.WriteBEInt(m_ClientEntityID);
		AString Pkt;
		Packet.ReadAll(Pkt);
		cByteBuffer ToClient(512);
		ToClient.WriteVarUTF8String(Pkt);
		CLIENTSEND(ToClient);
	}
	else
	{
		COPY_TO_CLIENT();
	}

	return true;
}





bool cConnection::HandleServerEntityEquipment(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt,   int,   EntityID);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, SlotNum);

	AString Item;
	if (!ParseSlot(m_ServerBuffer, Item))
	{
		return false;
	}

	// TODO: Add Entity ID switching

	COPY_TO_CLIENT();

	return true;
}





bool cConnection::HandleServerEntityHeadLook(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int,  EntityID);
	HANDLE_SERVER_PACKET_READ(ReadByte,  Byte, HeadYaw);

	if (EntityID == m_ServerEntityID)
	{
		m_ServerBuffer.CommitRead();

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
	}
	else
	{
		COPY_TO_CLIENT();
	}

	return true;
}





bool cConnection::HandleServerEntityLook(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int,  EntityID);
	HANDLE_SERVER_PACKET_READ(ReadByte,  Byte, Yaw);
	HANDLE_SERVER_PACKET_READ(ReadByte,  Byte, Pitch);

	if (EntityID == m_ServerEntityID)
	{
		m_ServerBuffer.CommitRead();

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
	}
	else
	{
		COPY_TO_CLIENT();
	}

	return true;
}





bool cConnection::HandleServerEntityMetadata(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, EntityID);
	AString Metadata;
	if (!ParseMetadata(m_ServerBuffer, Metadata))
	{
		return false;
	}

	// TODO: Add entity ID switching

	COPY_TO_CLIENT();

	return true;
}





bool cConnection::HandleServerEntityProperties(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, EntityID);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, Count);
	
	for (int i = 0; i < Count; i++)
	{
		HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, Key);
		HANDLE_SERVER_PACKET_READ(ReadBEDouble,      double,  Value);
		HANDLE_SERVER_PACKET_READ(ReadBEShort, short, ListLength);
		for (short j = 0; j < ListLength; j++)
		{
			HANDLE_SERVER_PACKET_READ(ReadBEInt64,  Int64,  UUIDHi);
			HANDLE_SERVER_PACKET_READ(ReadBEInt64,  Int64,  UUIDLo);
			HANDLE_SERVER_PACKET_READ(ReadBEDouble, double, DblVal);
			HANDLE_SERVER_PACKET_READ(ReadByte,     Byte,   ByteVal);
		}
	}  // for i


	// TODO: Switch EntityID

	COPY_TO_CLIENT();
	return true;
}





bool cConnection::HandleServerEntityRelativeMove(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int,  EntityID);
	HANDLE_SERVER_PACKET_READ(ReadByte,  Byte, dx);
	HANDLE_SERVER_PACKET_READ(ReadByte,  Byte, dy);
	HANDLE_SERVER_PACKET_READ(ReadByte,  Byte, dz);

	if (EntityID == m_ServerEntityID)
	{
		m_ServerBuffer.CommitRead();

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
	}
	else
	{
		COPY_TO_CLIENT();
	}

	return true;
}





bool cConnection::HandleServerEntityRelativeMoveLook(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, EntityID);
	HANDLE_SERVER_PACKET_READ(ReadByte,  Byte, dx);
	HANDLE_SERVER_PACKET_READ(ReadByte,  Byte, dy);
	HANDLE_SERVER_PACKET_READ(ReadByte,  Byte, dz);
	HANDLE_SERVER_PACKET_READ(ReadByte,  Byte, Yaw);
	HANDLE_SERVER_PACKET_READ(ReadByte,  Byte, Pitch);

	if (EntityID == m_ServerEntityID)
	{
		m_ServerBuffer.CommitRead();

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
	}
	else
	{
		COPY_TO_CLIENT();
	}

	return true;
}





bool cConnection::HandleServerEntityStatus(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int,  EntityID);
	HANDLE_SERVER_PACKET_READ(ReadByte,  Byte, Status);

	if (EntityID == m_ServerEntityID)
	{
		m_ServerBuffer.CommitRead();

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
	}
	else
	{
		COPY_TO_CLIENT();
	}

	return true;
}





bool cConnection::HandleServerEntityTeleport(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int,  EntityID);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int,  AbsX);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int,  AbsY);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int,  AbsZ);
	HANDLE_SERVER_PACKET_READ(ReadByte,  Byte, Yaw);
	HANDLE_SERVER_PACKET_READ(ReadByte,  Byte, Pitch);

	if (EntityID == m_ServerEntityID)
	{
		m_ServerBuffer.CommitRead();

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
	}
	else
	{
		COPY_TO_CLIENT();
	}

	return true;
}





bool cConnection::HandleServerEntityVelocity(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt,   int,   EntityID);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, VelocityX);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, VelocityY);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, VelocityZ);

	if (EntityID == m_ServerEntityID)
	{
		m_ServerBuffer.CommitRead();

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
	}
	else
	{
		COPY_TO_CLIENT();
	}

	return true;
}





bool cConnection::HandleServerExplosion(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEFloat, float, PosX);
	HANDLE_SERVER_PACKET_READ(ReadBEFloat, float, PosY);
	HANDLE_SERVER_PACKET_READ(ReadBEFloat, float, PosZ);
	HANDLE_SERVER_PACKET_READ(ReadBEFloat, float, Force);
	HANDLE_SERVER_PACKET_READ(ReadBEInt,   int,   NumRecords);
	for (int i = 0; i < NumRecords; i++)
	{
		HANDLE_SERVER_PACKET_READ(ReadChar, char, rx);
		HANDLE_SERVER_PACKET_READ(ReadChar, char, ry);
		HANDLE_SERVER_PACKET_READ(ReadChar, char, rz);
	}
	HANDLE_SERVER_PACKET_READ(ReadBEFloat, float, PlayerMotionX);
	HANDLE_SERVER_PACKET_READ(ReadBEFloat, float, PlayerMotionY);
	HANDLE_SERVER_PACKET_READ(ReadBEFloat, float, PlayerMotionZ);

	COPY_TO_CLIENT();
	return true;
}





bool cConnection::HandleServerIncrementStatistic(void)
{
	// 0xc8
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, StatisticID);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, Amount);

	COPY_TO_CLIENT();
	return true;
}





bool cConnection::HandleServerJoinGame(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt,         int,     EntityID);
	HANDLE_SERVER_PACKET_READ(ReadChar,          char,    GameMode);
	HANDLE_SERVER_PACKET_READ(ReadChar,          char,    Dimension);
	HANDLE_SERVER_PACKET_READ(ReadChar,          char,    Difficulty);
	HANDLE_SERVER_PACKET_READ(ReadChar,          char,    MaxPlayers);
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, LevelType);

	if (!m_SwitchServer)
	{
		m_ClientEntityID = EntityID;
		m_ServerEntityID = EntityID;
	}
	else
	{
		m_SwitchServer = false;
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

		m_Server.m_SocketThreads.RemoveClient(m_OldServerConnection);

		return true;
	}

	COPY_TO_CLIENT();
	return true;
}





bool cConnection::HandleServerKeepAlive(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, PingID);

	COPY_TO_CLIENT()
	return true;
}





bool cConnection::HandleServerKick(void)
{
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, Reason);
	if (m_HasClientPinged)
	{
		AStringVector Split;
		
		// Split by NULL chars (StringSplit() won't work here):
		size_t Last = 0;
		size_t Len = Reason.size();
		for (size_t i = 0; i < Len; i++)
		{
			if (Reason[i] == 0)
			{
				Split.push_back(Reason.substr(Last, i - Last));
				Last = i + 1;
			}
		}
		if (Last < Len)
		{
			Split.push_back(Reason.substr(Last));
		}
		
		if (Split.size() == 6)
		{
			// Modify the MOTD to show that it's being MCProxied:
			Reason.assign(Split[0]);
			Reason.push_back(0);
			Reason.append(Split[1]);
			Reason.push_back(0);
			Reason.append(Split[2]);
			Reason.push_back(0);
			Reason.append(Printf("MCProxy: %s", Split[3].c_str()));
			Reason.push_back(0);
			Reason.append(Split[4]);
			Reason.push_back(0);
			Reason.append(Split[5]);
			AString ReasonBE16;
			UTF8ToRawBEUTF16(Reason.data(), Reason.size(), ReasonBE16);
			AString PacketStart("\xff");
			PacketStart.push_back((ReasonBE16.size() / 2) / 256);
			PacketStart.push_back((ReasonBE16.size() / 2) % 256);
			CLIENTSEND(PacketStart.data(), PacketStart.size());
			CLIENTSEND(ReasonBE16.data(), ReasonBE16.size());
			return true;
		}
	}

	COPY_TO_CLIENT();
	return true;
}





bool cConnection::HandleServerMapChunk(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt,   int,   ChunkX);
	HANDLE_SERVER_PACKET_READ(ReadBEInt,   int,   ChunkZ);
	HANDLE_SERVER_PACKET_READ(ReadChar,    char,  IsContiguous);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, PrimaryBitmap);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, AdditionalBitmap);
	HANDLE_SERVER_PACKET_READ(ReadBEInt,   int,   CompressedSize);
	AString CompressedData;
	if (!m_ServerBuffer.ReadString(CompressedData, CompressedSize))
	{
		return false;
	}
	
	COPY_TO_CLIENT()
	return true;
}





bool cConnection::HandleServerMapChunkBulk(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, ChunkCount);
	HANDLE_SERVER_PACKET_READ(ReadBEInt,   int,   CompressedSize);
	HANDLE_SERVER_PACKET_READ(ReadBool,    bool,  IsSkyLightSent);
	AString CompressedData;
	if (!m_ServerBuffer.ReadString(CompressedData, CompressedSize))
	{
		return false;
	}
	
	// Read individual chunk metas.
	for (short i = 0; i < ChunkCount; i++)
	{
		HANDLE_SERVER_PACKET_READ(ReadBEInt,   int,   ChunkX);
		HANDLE_SERVER_PACKET_READ(ReadBEInt,   int,   ChunkZ);
		HANDLE_SERVER_PACKET_READ(ReadBEShort, short, PrimaryBitmap);
		HANDLE_SERVER_PACKET_READ(ReadBEShort, short, AddBitmap);
	}
	
	COPY_TO_CLIENT();
	return true;
}





bool cConnection::HandleServerMultiBlockChange(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt,   int,   ChunkX);
	HANDLE_SERVER_PACKET_READ(ReadBEInt,   int,   ChunkZ);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, NumBlocks);
	HANDLE_SERVER_PACKET_READ(ReadBEInt,   int,   DataSize);
	AString BlockChangeData;
	if (!m_ServerBuffer.ReadString(BlockChangeData, DataSize))
	{
		return false;
	}

	COPY_TO_CLIENT();
	return true;
}





bool cConnection::HandleServerNamedSoundEffect(void)
{
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, SoundName);
	HANDLE_SERVER_PACKET_READ(ReadBEInt,         int,     PosX);
	HANDLE_SERVER_PACKET_READ(ReadBEInt,         int,     PosY);
	HANDLE_SERVER_PACKET_READ(ReadBEInt,         int,     PosZ);
	HANDLE_SERVER_PACKET_READ(ReadBEFloat,       float,   Volume);
	HANDLE_SERVER_PACKET_READ(ReadByte,          Byte,    Pitch);

	COPY_TO_CLIENT();
	return true;
}





bool cConnection::HandleServerPlayerAbilities(void)
{
	HANDLE_SERVER_PACKET_READ(ReadChar, char, Flags);
	HANDLE_SERVER_PACKET_READ(ReadBEFloat, float, FlyingSpeed);
	HANDLE_SERVER_PACKET_READ(ReadBEFloat, float, WalkingSpeed);

	COPY_TO_CLIENT();
	return true;
}





bool cConnection::HandleServerPlayerAnimation(void)
{
	HANDLE_SERVER_PACKET_READ(ReadVarInt, UInt32, PlayerID);
	HANDLE_SERVER_PACKET_READ(ReadByte,   Byte,   AnimationID);

	if (PlayerID == m_ServerEntityID)
	{
		m_ServerBuffer.CommitRead();

		// Send the same packet, but with modified Entity ID:
		cByteBuffer Packet(512);
		Packet.WriteByte(0x0A);
		Packet.WriteVarInt(m_ClientEntityID);
		Packet.WriteByte(AnimationID);
		AString Pkt;
		Packet.ReadAll(Pkt);
		cByteBuffer ToClient(512);
		ToClient.WriteVarUTF8String(Pkt);
		CLIENTSEND(ToClient);
	}
	else
	{
		COPY_TO_CLIENT();
	}

	return true;
}





bool cConnection::HandleServerPlayerListItem(void)
{
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, PlayerName);
	HANDLE_SERVER_PACKET_READ(ReadChar,            char,    IsOnline);
	HANDLE_SERVER_PACKET_READ(ReadBEShort,         short,   Ping);

	COPY_TO_CLIENT();
	return true;
}





bool cConnection::HandleServerPlayerPositionLook(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEDouble, double, PosX);
	HANDLE_SERVER_PACKET_READ(ReadBEDouble, double, PosY);
	HANDLE_SERVER_PACKET_READ(ReadBEDouble, double, PosZ);
	HANDLE_SERVER_PACKET_READ(ReadBEFloat,  float,  Yaw);
	HANDLE_SERVER_PACKET_READ(ReadBEFloat,  float,  Pitch);
	HANDLE_SERVER_PACKET_READ(ReadChar,     char,   IsOnGround);
	
	COPY_TO_CLIENT();
	return true;
}





bool cConnection::HandleServerPluginMessage(void)
{
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, ChannelName);
	HANDLE_SERVER_PACKET_READ(ReadBEShort,         short,   Length);
	AString Data;
	if (!m_ServerBuffer.ReadString(Data, Length))
	{
		return false;
	}

	COPY_TO_CLIENT();
	return true;
}





bool cConnection::HandleServerRespawn(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt,         int,     Dimension);
	HANDLE_SERVER_PACKET_READ(ReadChar,          char,    Difficulty);
	HANDLE_SERVER_PACKET_READ(ReadChar,          char,    GameMode);
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, LevelType);

	COPY_TO_CLIENT();
	return true;
}





bool cConnection::HandleServerSetExperience(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEFloat, float, ExperienceBar);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, Level);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, TotalExperience);

	COPY_TO_CLIENT();
	return true;
}





bool cConnection::HandleServerSetSlot(void)
{
	HANDLE_SERVER_PACKET_READ(ReadChar,    char,  WindowID);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, SlotNum);
	AString Item;
	if (!ParseSlot(m_ServerBuffer, Item))
	{
		return false;
	}

	COPY_TO_CLIENT();
	return true;
}





bool cConnection::HandleServerSlotSelect(void)
{
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, SlotNum);

	COPY_TO_CLIENT();
	return true;
}





bool cConnection::HandleServerSoundEffect(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt,   int,   EffectID);
	HANDLE_SERVER_PACKET_READ(ReadBEInt,   int,   PosX);
	HANDLE_SERVER_PACKET_READ(ReadByte,    Byte,  PosY);
	HANDLE_SERVER_PACKET_READ(ReadBEInt,   int,   PosZ);
	HANDLE_SERVER_PACKET_READ(ReadBEInt,   int,   Data);
	HANDLE_SERVER_PACKET_READ(ReadByte,    Byte,  NoVolumeDecrease);

	COPY_TO_CLIENT();
	return true;
}





bool cConnection::HandleServerSpawnExperienceOrbs(void)
{
	HANDLE_SERVER_PACKET_READ(ReadVarInt,  UInt32, EntityID);
	HANDLE_SERVER_PACKET_READ(ReadBEInt,   int,    PosX);
	HANDLE_SERVER_PACKET_READ(ReadBEInt,   int,    PosY);
	HANDLE_SERVER_PACKET_READ(ReadBEInt,   int,    PosZ);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short,  Count);

	if (EntityID == m_ServerEntityID)
	{
		m_ServerBuffer.CommitRead();

		// Send the same packet, but with modified Entity ID:
		cByteBuffer Packet(512);
		Packet.WriteByte(0x11);
		Packet.WriteVarInt(m_ClientEntityID);
		Packet.WriteBEInt(PosX);
		Packet.WriteBEInt(PosY);
		Packet.WriteBEInt(PosZ);
		Packet.WriteBEShort(Count);
		AString Pkt;
		Packet.ReadAll(Pkt);
		cByteBuffer ToClient(512);
		ToClient.WriteVarUTF8String(Pkt);
		CLIENTSEND(ToClient);
	}
	else
	{
		COPY_TO_CLIENT();
	}

	return true;
}





bool cConnection::HandleServerSpawnMob(void)
{
	HANDLE_SERVER_PACKET_READ(ReadVarInt,  UInt32, EntityID);
	HANDLE_SERVER_PACKET_READ(ReadChar,    char,   MobType);
	HANDLE_SERVER_PACKET_READ(ReadBEInt,   int,    PosX);
	HANDLE_SERVER_PACKET_READ(ReadBEInt,   int,    PosY);
	HANDLE_SERVER_PACKET_READ(ReadBEInt,   int,    PosZ);
	HANDLE_SERVER_PACKET_READ(ReadByte,    Byte,   Yaw);
	HANDLE_SERVER_PACKET_READ(ReadByte,    Byte,   Pitch);
	HANDLE_SERVER_PACKET_READ(ReadByte,    Byte,   HeadYaw);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short,  VelocityX);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short,  VelocityY);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short,  VelocityZ);
	AString Metadata;
	if (!ParseMetadata(m_ServerBuffer, Metadata))
	{
		return false;
	}

	// TODO: Add Entity ID Switching


	COPY_TO_CLIENT();

	return true;
}





bool cConnection::HandleServerSpawnNamedEntity(void)
{
	HANDLE_SERVER_PACKET_READ(ReadVarInt,        UInt32,  EntityID);
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, EntityUUID);
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, EntityName);
	HANDLE_SERVER_PACKET_READ(ReadVarInt,        UInt32,  DataCount);
	for (UInt32 i = 0; i < DataCount; i++)
	{
		HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, Name)
		HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, Value)
		HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, Signature)
	}
	HANDLE_SERVER_PACKET_READ(ReadBEInt,         int,     PosX);
	HANDLE_SERVER_PACKET_READ(ReadBEInt,         int,     PosY);
	HANDLE_SERVER_PACKET_READ(ReadBEInt,         int,     PosZ);
	HANDLE_SERVER_PACKET_READ(ReadByte,          Byte,    Yaw);
	HANDLE_SERVER_PACKET_READ(ReadByte,          Byte,    Pitch);
	HANDLE_SERVER_PACKET_READ(ReadBEShort,       short,   CurrentItem);
	AString Metadata;
	if (!ParseMetadata(m_ServerBuffer, Metadata))
	{
		return false;
	}


	// TODO: Add entity ID switching


	COPY_TO_CLIENT();
	return true;
}





bool cConnection::HandleServerSpawnObjectVehicle(void)
{
	#ifdef _DEBUG
	// DEBUG:
	// This packet is still troublesome when DataIndicator != 0
	AString Buffer;
	m_ServerBuffer.ResetRead();
	m_ServerBuffer.ReadAll(Buffer);
	m_ServerBuffer.ResetRead();
	UInt32 PacketLen, PacketType;
	m_ServerBuffer.ReadVarInt(PacketLen);
	m_ServerBuffer.ReadVarInt(PacketType);
	if (Buffer.size() > 128)
	{
		// Only log up to 128 bytes
		Buffer.erase(128, AString::npos);
	}
	#endif  // _DEBUG
	
	HANDLE_SERVER_PACKET_READ(ReadVarInt,  UInt32, EntityID);
	HANDLE_SERVER_PACKET_READ(ReadByte,    Byte,   ObjType);
	HANDLE_SERVER_PACKET_READ(ReadBEInt,   int,    PosX);
	HANDLE_SERVER_PACKET_READ(ReadBEInt,   int,    PosY);
	HANDLE_SERVER_PACKET_READ(ReadBEInt,   int,    PosZ);
	HANDLE_SERVER_PACKET_READ(ReadByte,    Byte,   Pitch);
	HANDLE_SERVER_PACKET_READ(ReadByte,    Byte,   Yaw);
	HANDLE_SERVER_PACKET_READ(ReadBEInt,   int,    DataIndicator);
	AString ExtraData;
	short VelocityX = 0;
	short VelocityY = 0;
	short VelocityZ = 0;

	if (DataIndicator != 0)
	{
		HANDLE_SERVER_PACKET_READ(ReadBEShort, short, SpeedX);
		HANDLE_SERVER_PACKET_READ(ReadBEShort, short, SpeedY);
		HANDLE_SERVER_PACKET_READ(ReadBEShort, short, SpeedZ);
		VelocityX = SpeedX; VelocityY = SpeedY; VelocityZ = SpeedZ;  // Speed vars are local to this scope, but we need them available later
		/*
		// This doesn't seem to work - for a falling block I'm getting no extra data at all
		int ExtraLen = 0;
		switch (ObjType)
		{
			case OBJECT_FALLING_BLOCK: ExtraLen = 4; break;  // int: BlockType | (BlockMeta << 12)
			case OBJECT_ARROW:
			case OBJECT_SNOWBALL:
			case OBJECT_EGG:
			case OBJECT_EYE_OF_ENDER:
			case OBJECT_DRAGON_EGG:
			case OBJECT_FISHING_FLOAT:
			{
				ExtraLen = 4; break;  // int: EntityID of the thrower
			}
			// TODO: Splash potions
		}
		if ((ExtraLen > 0) && !m_ServerBuffer.ReadString(ExtraData, ExtraLen))
		{
			return false;
		}
		*/
	}

	if (EntityID == m_ServerEntityID)
	{
		m_ServerBuffer.CommitRead();

		// Send the same packet, but with modified Entity ID:
		cByteBuffer Packet(512);
		Packet.WriteByte(0x0E);
		Packet.WriteVarInt(m_ClientEntityID);
		Packet.WriteByte(ObjType);
		Packet.WriteBEInt(PosX);
		Packet.WriteBEInt(PosY);
		Packet.WriteBEInt(PosZ);
		Packet.WriteByte(Pitch);
		Packet.WriteByte(Yaw);
		Packet.WriteBEInt(DataIndicator);

		if (DataIndicator != 0)
		{
			Packet.WriteBEShort(VelocityX);
			Packet.WriteBEShort(VelocityY);
			Packet.WriteBEShort(VelocityZ);
		}

		AString Pkt;
		Packet.ReadAll(Pkt);
		cByteBuffer ToClient(512);
		ToClient.WriteVarUTF8String(Pkt);
		CLIENTSEND(ToClient);
	}
	else
	{
		COPY_TO_CLIENT();
	}

	return true;
}





bool cConnection::HandleServerSpawnPainting(void)
{
	HANDLE_SERVER_PACKET_READ(ReadVarInt,        UInt32,  EntityID);
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, ImageName);
	HANDLE_SERVER_PACKET_READ(ReadBEInt,         int,     PosX);
	HANDLE_SERVER_PACKET_READ(ReadBEInt,         int,     PosY);
	HANDLE_SERVER_PACKET_READ(ReadBEInt,         int,     PosZ);
	HANDLE_SERVER_PACKET_READ(ReadBEInt,         int,     Direction);

	if (EntityID == m_ServerEntityID)
	{
		m_ServerBuffer.CommitRead();

		// Send the same packet, but with modified Entity ID:
		cByteBuffer Packet(512);
		Packet.WriteByte(0x10);
		Packet.WriteVarInt(m_ClientEntityID);
		Packet.WriteVarUTF8String(ImageName);
		Packet.WriteBEInt(PosX);
		Packet.WriteBEInt(PosY);
		Packet.WriteBEInt(PosZ);
		Packet.WriteBEInt(Direction);
		AString Pkt;
		Packet.ReadAll(Pkt);
		cByteBuffer ToClient(512);
		ToClient.WriteVarUTF8String(Pkt);
		CLIENTSEND(ToClient);
	}
	else
	{
		COPY_TO_CLIENT();
	}

	return true;
}





bool cConnection::HandleServerSpawnPickup(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt,   int,   EntityID);
	AString ItemDesc;
	if (!ParseSlot(m_ServerBuffer, ItemDesc))
	{
		return false;
	}
	HANDLE_SERVER_PACKET_READ(ReadBEInt,   int,   PosX);
	HANDLE_SERVER_PACKET_READ(ReadBEInt,   int,   PosY);
	HANDLE_SERVER_PACKET_READ(ReadBEInt,   int,   PosZ);
	HANDLE_SERVER_PACKET_READ(ReadByte,    Byte,  Rotation);
	HANDLE_SERVER_PACKET_READ(ReadByte,    Byte,  Pitch);
	HANDLE_SERVER_PACKET_READ(ReadByte,    Byte,  Roll);


	// TODO: Add Entity ID switching


	COPY_TO_CLIENT();
	return true;
}





bool cConnection::HandleServerStatistics(void)
{
	HANDLE_SERVER_PACKET_READ(ReadVarInt, UInt32, NumEntries);
	for (UInt32 i = 0; i < NumEntries; i++)
	{
		HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, StatName);
		HANDLE_SERVER_PACKET_READ(ReadVarInt,        UInt32,  StatValue);
	}
	COPY_TO_CLIENT();
	return true;
}




bool cConnection::HandleServerStatusPing(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt64, Int64, Time);

	COPY_TO_CLIENT();
	return true;
}





bool cConnection::HandleServerStatusResponse(void)
{
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, Response);
	
	// Modify the response to show that it's being mc-proxied:
	const char DescSearch[] = "\"description\":{\"text\":\"";
	size_t idx = Response.find(DescSearch);
	if (idx != AString::npos)
	{
		Response.assign(Response.substr(0, idx + sizeof(DescSearch) - 1) + "MCProxy: " + Response.substr(idx + sizeof(DescSearch) - 1));
	}
	cByteBuffer Packet(Response.size() + 50);
	Packet.WriteVarInt(0);  // Packet type - status response
	Packet.WriteVarUTF8String(Response);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToClient(Response.size() + 50);
	ToClient.WriteVarUTF8String(Pkt);
	CLIENTSEND(ToClient);
	return true;
}





bool cConnection::HandleServerTabCompletion(void)
{
	HANDLE_SERVER_PACKET_READ(ReadVarInt,        UInt32,  NumResults);
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, Results);

	COPY_TO_CLIENT();
	return true;
}





bool cConnection::HandleServerTimeUpdate(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt64, Int64, WorldAge);
	HANDLE_SERVER_PACKET_READ(ReadBEInt64, Int64, TimeOfDay);

	COPY_TO_CLIENT();
	return true;
}





bool cConnection::HandleServerUpdateHealth(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEFloat, float, Health);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, Food);
	HANDLE_SERVER_PACKET_READ(ReadBEFloat, float, Saturation);

	COPY_TO_CLIENT();
	return true;
}





bool cConnection::HandleServerUpdateSign(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt,           int,   BlockX);
	HANDLE_SERVER_PACKET_READ(ReadBEShort,         short, BlockY);
	HANDLE_SERVER_PACKET_READ(ReadBEInt,           int,   BlockZ);
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, Line1);
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, Line2);
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, Line3);
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, Line4);

	COPY_TO_CLIENT();
	return true;
}





bool cConnection::HandleServerUpdateTileEntity(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt,   int,   BlockX);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, BlockY);
	HANDLE_SERVER_PACKET_READ(ReadBEInt,   int,   BlockZ);
	HANDLE_SERVER_PACKET_READ(ReadByte,    Byte,  Action);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, DataLength);	

	AString Data;
	if ((DataLength > 0) && !m_ServerBuffer.ReadString(Data, DataLength))
	{
		return false;
	}

	COPY_TO_CLIENT();
	return true;
}





bool cConnection::HandleServerUseBed(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int,  EntityID);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int,  BedX);
	HANDLE_SERVER_PACKET_READ(ReadByte,  Byte, BedY);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int,  BedZ);

	if (EntityID == m_ServerEntityID)
	{
		m_ServerBuffer.CommitRead();

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
	}
	else
	{
		COPY_TO_CLIENT();
	}

	return true;
}





bool cConnection::HandleServerWindowClose(void)
{
	HANDLE_SERVER_PACKET_READ(ReadChar, char, WindowID);

	COPY_TO_CLIENT();
	return true;
}





bool cConnection::HandleServerWindowContents(void)
{
	HANDLE_SERVER_PACKET_READ(ReadChar, char, WindowID);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, NumSlots);

	AStringVector Items;
	for (short i = 0; i < NumSlots; i++)
	{
		AString Item;
		if (!ParseSlot(m_ServerBuffer, Item))
		{
			return false;
		}
	}

	COPY_TO_CLIENT();
	return true;
}





bool cConnection::HandleServerWindowOpen(void)
{
	HANDLE_SERVER_PACKET_READ(ReadChar,            char,    WindowID);
	HANDLE_SERVER_PACKET_READ(ReadChar,            char,    WindowType);
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, Title);
	HANDLE_SERVER_PACKET_READ(ReadByte,            Byte,    NumSlots);
	HANDLE_SERVER_PACKET_READ(ReadByte,            Byte,    UseProvidedTitle);
	if (WindowType == 11)  // Horse / Donkey / Mule
	{
		HANDLE_SERVER_PACKET_READ(ReadBEInt, int, intHorseInt);
	}

	COPY_TO_CLIENT();
	return true;
}





bool cConnection::HandleServerScoreboardObjective(void)
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





bool cConnection::HandleServerTeams(void)
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





bool cConnection::HandleServerUnknownPacket(UInt32 a_PacketType, UInt32 a_PacketLen, UInt32 a_PacketReadSoFar)
{
	AString Data;
	ASSERT(a_PacketLen >= a_PacketReadSoFar);
	if (!m_ServerBuffer.ReadString(Data, a_PacketLen - a_PacketReadSoFar))
	{
		return false;
	}

	COPY_TO_CLIENT();
	return true;
}





bool cConnection::ParseSlot(cByteBuffer & a_Buffer, AString & a_ItemDesc)
{
	short ItemType;
	if (!a_Buffer.ReadBEShort(ItemType))
	{
		return false;
	}
	if (ItemType <= 0)
	{
		a_ItemDesc = "<empty>";
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
	Printf(a_ItemDesc, "%d:%d * %d", ItemType, ItemDamage, ItemCount);
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
	
	return true;
}





bool cConnection::ParseMetadata(cByteBuffer & a_Buffer, AString & a_Metadata)
{
	char x;
	if (!a_Buffer.ReadChar(x))
	{
		return false;
	}
	a_Metadata.push_back(x);
	while (x != 0x7f)
	{
		// int Index = ((unsigned)((unsigned char)x)) & 0x1f;  // Lower 5 bits = index
		int Type  = ((unsigned)((unsigned char)x)) >> 5;    // Upper 3 bits = type
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
				a_Metadata.append(VarLen);
				Length = Len;
				break;
			}
			case 5:
			{
				int Before = a_Buffer.GetReadableSpace();
				AString ItemDesc;
				if (!ParseSlot(a_Buffer, ItemDesc))
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
		a_Metadata.append(data);
		if (!a_Buffer.ReadChar(x))
		{
			return false;
		}
		a_Metadata.push_back(x);
	}  // while (x != 0x7f)
	return true;
}





void cConnection::SendEncryptionKeyResponse(const AString & a_ServerPublicKey, const AString & a_Nonce)
{
	// Generate the shared secret and encrypt using the server's public key
	Byte SharedSecret[16];
	Byte EncryptedSecret[128];
	memset(SharedSecret, 0, sizeof(SharedSecret));  // Use all zeroes for the initial secret
	cPublicKey PubKey(a_ServerPublicKey);
	int res = PubKey.Encrypt(SharedSecret, sizeof(SharedSecret), EncryptedSecret, sizeof(EncryptedSecret));
	if (res < 0)
	{
		return;
	}

	m_ServerEncryptor.Init(SharedSecret, SharedSecret);
	m_ServerDecryptor.Init(SharedSecret, SharedSecret);
	
	// Encrypt the nonce:
	Byte EncryptedNonce[128];
	res = PubKey.Encrypt((const Byte *)a_Nonce.data(), a_Nonce.size(), EncryptedNonce, sizeof(EncryptedNonce));
	if (res < 0)
	{
		return;
	}
	
	// Send the packet to the server:
	cByteBuffer ToServer(1024);
	ToServer.WriteByte(0x01);  // To server: Encryption key response
	ToServer.WriteBEShort((short)sizeof(EncryptedSecret));
	ToServer.WriteBuf(EncryptedSecret, sizeof(EncryptedSecret));
	ToServer.WriteBEShort((short)sizeof(EncryptedNonce));
	ToServer.WriteBuf(EncryptedNonce, sizeof(EncryptedNonce));
	cByteBuffer Len(5);
	Len.WriteVarInt(ToServer.GetReadableSpace());
	SERVERSEND(Len);
	SERVERSEND(ToServer);
	m_ServerState = csEncryptedUnderstood;
	m_IsServerEncrypted = true;
}





void cConnection::DataReceived(const char * a_Data, size_t a_Size)
{
	switch (m_ClientState)
	{
		case csUnencrypted:
		case csWaitingForEncryption:
		{
			DecodeClientsPackets(a_Data, a_Size);
			return;
		}
		case csEncryptedUnderstood:
		{
			DecodeClientsPackets(a_Data, a_Size);
			return;
		}
		case csEncryptedUnknown:
		{
			m_ServerEncryptor.ProcessData((Byte *)a_Data, (Byte *)a_Data, a_Size);
			SERVERSEND(a_Data, a_Size);
			return;
		}
	}
}





void cConnection::GetOutgoingData(AString & a_Data)
{
}





void cConnection::SocketClosed(void)
{
	m_Server.m_SocketThreads.RemoveClient(this);
	m_Server.m_SocketThreads.RemoveClient(m_ServerConnection);
}





bool cConnection::SendToClient(const char * a_Data, size_t a_Size)
{
	switch (m_ServerState)
	{
		case csUnencrypted:
		case csWaitingForEncryption:
		{
			return DecodeServersPackets(a_Data, a_Size);
		}
		case csEncryptedUnderstood:
		{
			m_ServerDecryptor.ProcessData((Byte *)a_Data, (Byte *)a_Data, a_Size);
			return DecodeServersPackets(a_Data, a_Size);
		}
		/**case csEncryptedUnknown:
		{
			m_ServerDecryptor.ProcessData((Byte *)a_Data, (Byte *)a_Data, a_Size);
			return CLIENTSEND(a_Data, a_Size);
		}*/
	}
	return false;
}




