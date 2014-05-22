
// Connection.cpp

// Interfaces to the cConnection class representing a single pair of connected sockets

#include "Globals.h"
#include "Connection.h"
#include "Server.h"
#include "ServerConnection.h"
#include "PolarSSL++/PublicKey.h"
#include "PolarSSL++/Sha1Checksum.h"
#include <iostream>

#ifdef _WIN32
	#include <direct.h>  // For _mkdir()
#endif




const int MAX_ENC_LEN = 512;  // Maximum size of the encrypted message; should be 128, but who knows...





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

#define CLIENTSEND(...) \
	{ \
		if (m_IsClientEncrypted) \
		{ \
			SendEncryptedData(m_ClientSocket, m_ClientEncryptor, __VA_ARGS__, "Client"); \
		} \
		else \
		{ \
			SendData(m_ClientSocket, __VA_ARGS__, "Client"); \
		} \
	}
#define SERVERSEND(...) SendData(m_ServerSocket, __VA_ARGS__, "Server")
#define CLIENTENCRYPTSEND(...) SendEncryptedData(m_ClientSocket, m_ClientEncryptor, __VA_ARGS__, "Client")
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
			case csWaitingForEncryption: \
			{ \
				m_ClientEncryptionBuffer.append(ToClient.data(), ToClient.size()); \
				break; \
			} \
		} \
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
	m_ServerProtocolState(-1),
	m_ClientProtocolState(-1),
	m_IsServerEncrypted(false),
	m_IsClientEncrypted(false),
	m_SwitchServer(false),
	m_AlreadyCountPlayer(false),
	m_AlreadyRemovedPlayer(false)
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
					case 0x01: HANDLE_CLIENT_READ(HandleClientChatMessage()); break;
					case 0x03: HANDLE_CLIENT_READ(HandleClientPlayerOnGround()); break;
					case 0x0a: HANDLE_CLIENT_READ(HandleClientAnimation()); break;
					case 0x0b: HANDLE_CLIENT_READ(HandleClientEntityAction()); break;
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
				HANDLE_SERVER_READ(HandleServerUnknownPacket(PacketType, PacketLen, PacketReadSoFar));
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
					default:   HANDLE_SERVER_READ(HandleServerUnknownPacket(PacketType, PacketLen, PacketReadSoFar)); break;
				}  // switch (PacketType)
				break;
			}  // case 3 - Game
			
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
	Packet.WriteBEShort(m_Server.m_ListenPort);
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
	HANDLE_CLIENT_PACKET_READ(ReadBEShort, short, EncKeyLength);
	AString EncKey;
	if (!m_ClientBuffer.ReadString(EncKey, EncKeyLength))
	{
		return false;
	}

	HANDLE_CLIENT_PACKET_READ(ReadBEShort, short, EncNonceLength);
	AString EncNonce;
	if (!m_ClientBuffer.ReadString(EncNonce, EncNonceLength))
	{
		return false;
	}

	m_ClientBuffer.CommitRead();

	if ((EncKeyLength > MAX_ENC_LEN) || (EncNonceLength > MAX_ENC_LEN))
	{
		LOGD("Too long encryption");
		Kick("Hacked client");
		return false;
	}

	// Decrypt EncNonce using privkey
	cRsaPrivateKey & rsaDecryptor = m_Server.m_PrivateKey;
	Int32 DecryptedNonce[MAX_ENC_LEN / sizeof(Int32)];
	int res = rsaDecryptor.Decrypt((const Byte *)EncNonce.data(), EncNonce.size(), (Byte *)DecryptedNonce, sizeof(DecryptedNonce));
	if (res != 4)
	{
		LOGD("Bad nonce length: got %d, exp %d", res, 4);
		Kick("Hacked client");
		return false;
	}
	if (ntohl(DecryptedNonce[0]) != (unsigned)(uintptr_t)this)
	{
		LOGD("Bad nonce value");
		Kick("Hacked client");
		return false;
	}

	// Decrypt the symmetric encryption key using privkey:
	Byte DecryptedKey[MAX_ENC_LEN];
	res = rsaDecryptor.Decrypt((const Byte *)EncKey.data(), EncKey.size(), DecryptedKey, sizeof(DecryptedKey));
	if (res != 16)
	{
		LOGD("Bad key length");
		Kick("Hacked client");
		return false;
	}

	StartEncryption(DecryptedKey);

	m_Server.m_Authenticator.Authenticate(m_UserName, m_AuthServerID);

	return true;
}





bool cConnection::HandleClientLoginStart(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadVarUTF8String, AString, UserName);

	m_UserName = UserName;

	if (cServer::Get()->m_ShouldAuthenticate)
	{
		m_ClientBuffer.CommitRead();

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
			SendChatMessage("Can't load server data from config!", "c");
			return true;
		}

		AStringVector ServerData = StringSplit(ServerConfig, ":");
		AString ServerAddress = ServerData[0];
		int ServerPort = atoi(ServerData[1].c_str());

		SOCKET ServerSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (ServerSocket == INVALID_SOCKET)
		{
			SendChatMessage("Can't connect to server!", "c");
			return true;
		}

		cSocket Socket = cSocket(ServerSocket);
		if (!Socket.ConnectIPv4(ServerAddress, ServerPort))
		{
			SendChatMessage("Can't connect to server!", "c");
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
			ScoreboardPacket.WriteVarUTF8String(*it);
			ScoreboardPacket.WriteByte(1);
			AString ScoreboardPkt;
			ScoreboardPacket.ReadAll(ScoreboardPkt);
			cByteBuffer ScoreboardToClient(512);
			ScoreboardToClient.WriteVarUTF8String(ScoreboardPkt);
			CLIENTSEND(ScoreboardToClient);
		}
		m_Teams.clear();

		// Remove Players from Tablist
		for (cTabPlayers::iterator it = m_TabPlayers.begin(); it != m_TabPlayers.end(); ++it)
		{
			if (*it == m_UserName)
			{
				continue;
			}
			cByteBuffer TabPacket(512);
			TabPacket.WriteByte(0x38);
			TabPacket.WriteVarUTF8String(*it);
			TabPacket.WriteBool(false);
			TabPacket.WriteBEShort(0);
			AString TabPkt;
			TabPacket.ReadAll(TabPkt);
			cByteBuffer TabToClient(512);
			TabToClient.WriteVarUTF8String(TabPkt);
			CLIENTSEND(TabToClient);
		}
		m_TabPlayers.clear();

		cServerConnection * Server = new cServerConnection(this, m_Server);
		m_Server.m_SocketThreads.AddClient(Socket, Server);

		m_OldServerConnection = m_ServerConnection;
		m_ServerConnection = Server;
		m_ServerSocket = Socket;

		cByteBuffer HandshakePacket(512);
		HandshakePacket.WriteByte(0x00);
		HandshakePacket.WriteVarInt(5);
		HandshakePacket.WriteVarUTF8String(ServerAddress);
		HandshakePacket.WriteBEShort(ServerPort);
		HandshakePacket.WriteVarInt(2);
		AString HandshakePkt;
		HandshakePacket.ReadAll(HandshakePkt);
		cByteBuffer HandshakeToServer(512);
		HandshakeToServer.WriteVarUTF8String(HandshakePkt);
		SERVERSEND(HandshakeToServer);

		cByteBuffer LoginStartPacket(512);
		LoginStartPacket.WriteByte(0x00);
		LoginStartPacket.WriteVarUTF8String(m_UserName);
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





bool cConnection::HandleClientPlayerOnGround(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadChar, char, OnGround);

	if (m_SwitchServer)
	{
		m_ClientBuffer.CommitRead();
	}
	else
	{
		COPY_TO_SERVER();
	}
	
	return true;
}





bool cConnection::HandleClientStatusPing(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadBEInt64, Int64, Time);

	m_ClientBuffer.CommitRead();

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





bool cConnection::HandleClientStatusRequest(void)
{
	// Send the response:
	AString Response = "{\"version\":{\"name\":\"1.7.6\",\"protocol\":5},\"players\":{";
	AppendPrintf(Response, "\"max\":%u,\"online\":%u,\"sample\":[]},",
		m_Server.m_MaxPlayers,
		m_Server.m_PlayerAmount
		);
	AppendPrintf(Response, "\"description\":{\"text\":\"%s\"},",
		m_Server.m_MOTD.c_str()
		);
	AppendPrintf(Response, "\"favicon\":\"data:image/png;base64,%s\"",
		m_Server.m_FaviconData.c_str()
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
		m_ServerBuffer.CommitRead();
		m_ServerProtocolState = 3;
		return true;
	}

	m_ServerProtocolState = 3;

	if (m_IsClientEncrypted)
	{
		m_ClientState = csEncryptedUnderstood;
		CLIENTENCRYPTSEND(m_ClientEncryptionBuffer.data(), m_ClientEncryptionBuffer.size());
		m_ClientEncryptionBuffer.clear();
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





bool cConnection::HandleServerCollectPickup(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, CollectedID);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, CollectorID);

	if (CollectorID == m_ServerEntityID)
	{
		m_ServerBuffer.CommitRead();

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
	}
	else
	{
		COPY_TO_CLIENT();
	}

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

	cByteBuffer Packet(512);
	
	if (EntityID == m_ServerEntityID)
	{
		Packet.WriteByte(0x1C);
		Packet.WriteBEInt(m_ClientEntityID);

		if (!ParseMetadata(m_ServerBuffer, Packet))
		{
			return false;
		}

		m_ServerBuffer.CommitRead();

		AString Pkt;
		Packet.ReadAll(Pkt);
		cByteBuffer ToClient(512);
		ToClient.WriteVarUTF8String(Pkt);
		CLIENTSEND(ToClient);
	}
	else
	{
		AString Metadata;
		if (!ParseMetadata(m_ServerBuffer, Packet))
		{
			return false;
		}

		COPY_TO_CLIENT();
	}

	return true;
}





bool cConnection::HandleServerEntityProperties(void)
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

		m_ServerBuffer.CommitRead();

		AString Pkt;
		Packet.ReadAll(Pkt);
		cByteBuffer ToClient(512);
		ToClient.WriteVarUTF8String(Pkt);
		CLIENTSEND(ToClient);

		return true;
	}
	else
	{
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

		m_Server.m_PlayerAmount += 1;
		m_AlreadyCountPlayer = true;
	}
	else
	{
		m_ServerBuffer.CommitRead();

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





bool cConnection::HandleServerPlayerAnimation(void)
{
	HANDLE_SERVER_PACKET_READ(ReadVarInt, UInt32, PlayerID);
	HANDLE_SERVER_PACKET_READ(ReadByte,   Byte,   AnimationID);

	if (PlayerID == m_ServerEntityID)
	{
		m_ServerBuffer.CommitRead();

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
	}
	else
	{
		COPY_TO_CLIENT();
	}

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





bool cConnection::HandleServerPlayerListItem(void)
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





bool cConnection::ParseSlot(cByteBuffer & a_Buffer, cByteBuffer & a_Packet)
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





bool cConnection::ParseMetadata(cByteBuffer & a_Buffer, cByteBuffer & a_Packet)
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
				//a_Metadata.append(VarLen);
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





void cConnection::Authenticate(AString a_Name)
{
	m_UserName = a_Name;

	cByteBuffer LoginStartPacket(512);
	LoginStartPacket.WriteByte(0x00);
	LoginStartPacket.WriteVarUTF8String(m_UserName);
	AString LoginStartPkt;
	LoginStartPacket.ReadAll(LoginStartPkt);
	cByteBuffer LoginStartToServer(512);
	LoginStartToServer.WriteVarUTF8String(LoginStartPkt);
	SERVERSEND(LoginStartToServer);
}





void cConnection::SendChatMessage(AString a_Message, AString a_Color)
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





void cConnection::Kick(AString a_Reason)
{
	switch (m_ClientProtocolState)
	{
		case 2:
		{
			cByteBuffer Packet(512);
			Packet.WriteByte(0x00);
			Packet.WriteVarUTF8String(Printf("{\"text\":\"%s\"}", EscapeString(a_Reason).c_str()));
			AString Pkt;
			Packet.ReadAll(Pkt);
			cByteBuffer ToClient(512);
			ToClient.WriteVarUTF8String(Pkt);
			CLIENTSEND(ToClient);
			break;
		}
		case 3:
		{
			cByteBuffer Packet(512);
			Packet.WriteByte(0x40);
			Packet.WriteVarUTF8String(Printf("{\"text\":\"%s\"}", EscapeString(a_Reason).c_str()));
			AString Pkt;
			Packet.ReadAll(Pkt);
			cByteBuffer ToClient(512);
			ToClient.WriteVarUTF8String(Pkt);
			CLIENTSEND(ToClient);
			break;
		}
	}
	
}





void cConnection::StartEncryption(const Byte * a_Key)
{
	m_ClientEncryptor.Init(a_Key, a_Key);
	m_ClientDecryptor.Init(a_Key, a_Key);
	m_IsClientEncrypted = true;

	// Prepare the m_AuthServerID:
	cSha1Checksum Checksum;
	AString ServerID = cServer::Get()->m_ServerID;
	Checksum.Update((const Byte *)ServerID.c_str(), ServerID.length());
	Checksum.Update(a_Key, 16);
	Checksum.Update((const Byte *)cServer::Get()->m_PublicKeyDER.data(), cServer::Get()->m_PublicKeyDER.size());
	Byte Digest[20];
	Checksum.Finalize(Digest);
	cSha1Checksum::DigestToJava(Digest, m_AuthServerID);
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
			m_ClientDecryptor.ProcessData((Byte *)a_Data, (Byte *)a_Data, a_Size);
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

	if ((m_AlreadyCountPlayer) && (!m_AlreadyRemovedPlayer))
	{
		m_Server.m_PlayerAmount -= 1;
		m_AlreadyRemovedPlayer = true;
	}
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




