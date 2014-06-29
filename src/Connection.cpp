
// Connection.cpp

// Interfaces to the cConnection class representing a single pair of connected sockets

#include "Globals.h"
#include "Protocol17x.h"
#include "Protocol18x.h"
#include "Connection.h"
#include "Server.h"
#include "ServerConnection.h"
#include "PolarSSL++/PublicKey.h"
#include "PolarSSL++/Sha1Checksum.h"
#include <iostream>

#ifdef _WIN32
	#include <direct.h>  // For _mkdir()
#endif





#define HANDLE_CLIENT_PACKET_READ(Proc, Type, Var) \
	Type Var; \
	{ \
		if (!m_ClientBuffer.Proc(Var)) \
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





typedef unsigned char Byte;





///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// cConnection:

cConnection::cConnection(cSocket a_ClientSocket, cSocket a_ServerSocket, cServer & a_Server) :
	m_Server(a_Server),
	m_ClientSocket(a_ClientSocket),
	m_ServerSocket(a_ServerSocket),
	m_ClientBuffer(1024 KiB),
	m_ServerBuffer(1024 KiB),
        m_ClientState(csUnencrypted),
	m_ServerState(csUnencrypted),
	m_IsServerEncrypted(false),
	m_IsClientEncrypted(false),
	m_SwitchServer(false),
	m_AlreadyCountPlayer(false),
	m_AlreadyRemovedPlayer(false),
	m_Protocol(NULL),
	m_SendedHandshake(false)
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

		if (m_SendedHandshake)
		{
			m_Protocol->HandleClientPackets(PacketType, PacketLen, PacketReadSoFar);
		}
		else
		{
			HANDLE_CLIENT_READ(HandleClientHandshake());
		}

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

		m_Protocol->HandleServerPackets(PacketType, PacketLen, PacketReadSoFar);

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

	if (ProtocolVersion == 4)
	{
		m_Protocol = new cProtocol172(this);
	}
	else if (ProtocolVersion == 5)
	{
		m_Protocol = new cProtocol176(this);
	}
	else if (ProtocolVersion == 19)
	{
		m_Protocol = new cProtocol180(this);
	}
	else
	{
		// Kick the client and don't send the handshake to the server
		cByteBuffer Packet(512);
		Packet.WriteByte(0x00);
		Packet.WriteVarUTF8String(Printf("{\"text\":\"Unsupported Protocol Version!\"}"));
		AString Pkt;
		Packet.ReadAll(Pkt);
		cByteBuffer ToClient(512);
		ToClient.WriteVarUTF8String(Pkt);
		CLIENTSEND(ToClient);

		return true;
	}

	// Send the same packet to the server, but with our port:
	cByteBuffer Packet(512);
	Packet.WriteVarInt(0);  // Packet type - initial handshake
	Packet.WriteVarInt(5);
	Packet.WriteVarUTF8String(ServerHost);
	Packet.WriteBEShort(cServer::Get()->m_ListenPort);
	Packet.WriteVarInt(NextState);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToServer(512);
	ToServer.WriteVarUTF8String(Pkt);
	SERVERSEND(ToServer);

	m_SendedHandshake = true;
	
	m_Protocol->m_ClientProtocolState = (int)NextState;
	m_Protocol->m_ServerProtocolState = (int)NextState;

	return true;
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





void cConnection::Authenticate(AString a_Name, AString a_UUID)
{
	m_UserName = a_Name;
	m_UUID = a_UUID;

	cByteBuffer LoginStartPacket(512);
	LoginStartPacket.WriteByte(0x00);
	LoginStartPacket.WriteVarUTF8String(m_UserName);
	AString LoginStartPkt;
	LoginStartPacket.ReadAll(LoginStartPkt);
	cByteBuffer LoginStartToServer(512);
	LoginStartToServer.WriteVarUTF8String(LoginStartPkt);
	SERVERSEND(LoginStartToServer);
}





void cConnection::SwitchServer(AString a_ServerAddress, short a_ServerPort)
{
	SOCKET ServerSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (ServerSocket == INVALID_SOCKET)
	{
		m_Protocol->SendChatMessage("Can't connect to server!", "c");
		return;
	}

	cSocket Socket = cSocket(ServerSocket);
	if (!Socket.ConnectIPv4(a_ServerAddress, a_ServerPort))
	{
		m_Protocol->SendChatMessage("Can't connect to server!", "c");
		return;
	}

	m_SwitchServer = true;
	m_ServerConnection->m_ShouldSend = false;

	// Clear Buffers
	AString data;
	m_ServerBuffer.ReadAll(data);
	m_ServerBuffer.CommitRead();
	m_ServerEncryptionBuffer.clear();

	// Remove Scoreboards
	for (cScoreboards::iterator it = m_Protocol->m_Scoreboards.begin(); it != m_Protocol->m_Scoreboards.end(); ++it)
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
	m_Protocol->m_Scoreboards.clear();

	// Remove Teams
	for (cTeams::iterator it = m_Protocol->m_Teams.begin(); it != m_Protocol->m_Teams.end(); ++it)
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
	m_Protocol->m_Teams.clear();

	// Remove Players from Tablist
	for (cTabPlayers::iterator it = m_Protocol->m_TabPlayers.begin(); it != m_Protocol->m_TabPlayers.end(); ++it)
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
	m_Protocol->m_TabPlayers.clear();

	cServerConnection * Server = new cServerConnection(this, m_Server);
	m_Server.m_SocketThreads.AddClient(Socket, Server);

	m_OldServerConnection = m_ServerConnection;
	m_ServerConnection = Server;
	m_ServerSocket = Socket;

	cByteBuffer HandshakePacket(512);
	HandshakePacket.WriteByte(0x00);
	HandshakePacket.WriteVarInt(5);
	HandshakePacket.WriteVarUTF8String(a_ServerAddress);
	HandshakePacket.WriteBEShort(a_ServerPort);
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

	m_Protocol->m_ServerProtocolState = 2;

	m_Server.m_SocketThreads.RemoveClient(m_OldServerConnection);
}





void cConnection::Kick(AString a_Reason)
{
	switch (m_Protocol->m_ClientProtocolState)
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
		default: break;
	}
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
			m_ClientDecryptor.ProcessData((Byte *)a_Data, (Byte *)a_Data, a_Size);
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
		case csEncryptedUnknown:
		{
			m_ServerDecryptor.ProcessData((Byte *)a_Data, (Byte *)a_Data, a_Size);
			CLIENTSEND(a_Data, a_Size);
			return true;
		}
	}
	return false;
}




