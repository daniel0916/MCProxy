
// Protocol17x.cpp

#include "Globals.h"
#include "Protocol18x.h"
#include "Server.h"





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
	
#define HANDLE_SERVER_READ(Proc) \
	{ \
		if (!Proc) \
		{ \
			m_Connection->m_ServerBuffer.ResetRead(); \
			return true; \
		} \
	}





///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// cProtocol180:

cProtocol180::cProtocol180(cConnection * a_Connection) :
	super(a_Connection)
{
}





bool cProtocol180::HandleClientPackets(UInt32 a_PacketType, UInt32 a_PacketLen, UInt32 a_PacketReadSoFar)
{
	//LOG("0x%0x", a_PacketType);

	if (m_ClientProtocolState == 3)
	{
		// Game:
		switch (a_PacketType)
		{
			case 0x15: HANDLE_SERVER_READ(HandleClientClientSettings()); return true;
			case 0x07: HANDLE_SERVER_READ(HandleClientPlayerDigging()); return true;
			case 0x08: HANDLE_SERVER_READ(HandleClientPlayerBlockPlacement()); return true;
			case 0x12: HANDLE_SERVER_READ(HandleClientUpdateSign()); return true;
			case 0x00: HANDLE_SERVER_READ(HandleClientKeepAlive()); return true;
			case 0x02: HANDLE_SERVER_READ(HandleClientUseEntity()); return true;
			case 0x0c: HANDLE_SERVER_READ(HandleClientSteerVehicle()); return true;
			case 0x16: HANDLE_SERVER_READ(HandleClientClientStatus()); return true;
			case 0x04: HANDLE_SERVER_READ(HandleClientPlayerPosition()); return true;
			case 0x06: HANDLE_SERVER_READ(HandleClientPlayerPositionLook()); return true;
			case 0x18: HANDLE_SERVER_READ(HandleClientSpectate()); return true;
			case 0x17: HANDLE_SERVER_READ(HandleClientPluginMessage()); return true;
			default: break;
		}  // switch (PacketType)
	}

	super::HandleClientPackets(a_PacketType, a_PacketLen, a_PacketReadSoFar);
	return true;
}





bool cProtocol180::HandleServerPackets(UInt32 a_PacketType, UInt32 a_PacketLen, UInt32 a_PacketReadSoFar)
{
	//LOG("0x%0x", a_PacketType);

	if (m_ServerProtocolState == 3)
	{
		// Game:
		switch (a_PacketType)
		{
			case 0x02: HANDLE_SERVER_READ(HandleServerChatMessage()); return true;
			case 0x08: HANDLE_SERVER_READ(HandleServerPlayerPositionLook()); return true;
			case 0x2d: HANDLE_SERVER_READ(HandleServerOpenWindow()); return true;
			case 0x05: HANDLE_SERVER_READ(HandleServerSpawnPosition()); return true;
			case 0x23: HANDLE_SERVER_READ(HandleServerBlockChange()); return true;
			case 0x24: HANDLE_SERVER_READ(HandleServerBlockAction()); return true;
			case 0x25: HANDLE_SERVER_READ(HandleServerBlockBreakAnimation()); return true;
			case 0x28: HANDLE_SERVER_READ(HandleServerEffect()); return true;
			case 0x33: HANDLE_SERVER_READ(HandleServerUpdateSign()); return true;
			case 0x35: HANDLE_SERVER_READ(HandleServerUpdateBlockEntity()); return true;
			case 0x36: HANDLE_SERVER_READ(HandleServerSignEditorOpen()); return true;
			case 0x04: HANDLE_SERVER_READ(HandleServerEntityEquipment()); return true;
			case 0x06: HANDLE_SERVER_READ(HandleServerUpdateHealth()); return true;
			case 0x13: HANDLE_SERVER_READ(HandleServerDestroyEntities()); return true;
			case 0x1d: HANDLE_SERVER_READ(HandleServerEntityEffect()); return true;
			case 0x1e: HANDLE_SERVER_READ(HandleServerRemoveEntityEffect()); return true;
			case 0x1f: HANDLE_SERVER_READ(HandleServerSetExperience()); return true;
			case 0x3c: HANDLE_SERVER_READ(HandleServerUpdateScore()); return true;
			case 0x10: HANDLE_SERVER_READ(HandleServerSpawnPainting()); return true;
			default: break;
		}  // switch (PacketType)
	}

	super::HandleServerPackets(a_PacketType, a_PacketLen, a_PacketReadSoFar);
	return true;
}





bool cProtocol180::HandleServerChatMessage(void)
{
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, Message);

	m_Connection->m_ServerBuffer.CommitRead();

	cByteBuffer Packet(512);
	Packet.WriteByte(0x02);
	Packet.WriteVarUTF8String(Message);
	Packet.WriteByte(0);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToClient(512);
	ToClient.WriteVarUTF8String(Pkt);
	CLIENTSEND(ToClient);
	
	return true;
}





bool cProtocol180::HandleServerPlayerPositionLook(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEDouble, double, PosX);
	HANDLE_SERVER_PACKET_READ(ReadBEDouble, double, PosY);
	HANDLE_SERVER_PACKET_READ(ReadBEDouble, double, PosZ);
	HANDLE_SERVER_PACKET_READ(ReadBEFloat, float, Yaw);
	HANDLE_SERVER_PACKET_READ(ReadBEFloat, float, Pitch);
	HANDLE_SERVER_PACKET_READ(ReadBool, bool, OnGround);

	m_Connection->m_ServerBuffer.CommitRead();

	cByteBuffer Packet(512);
	Packet.WriteByte(0x08);
	Packet.WriteBEDouble(PosX);
	Packet.WriteBEDouble(PosY);
	Packet.WriteBEDouble(PosZ);
	Packet.WriteBEFloat(Yaw);
	Packet.WriteBEFloat(Pitch);
	Packet.WriteByte(0);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToClient(512);
	ToClient.WriteVarUTF8String(Pkt);
	CLIENTSEND(ToClient);

	return true;
}





bool cProtocol180::HandleServerOpenWindow(void)
{
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, WindowID);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, InventoryType);
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, WindowTitle);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, SlotNumbers);
	HANDLE_SERVER_PACKET_READ(ReadBool, bool, ProvidedWindowTitle);

	int HorseEntityID = 0;
	if (InventoryType == 11)
	{
		HANDLE_SERVER_PACKET_READ(ReadBEInt, int, EntityID);
		HorseEntityID = EntityID;
	}

	m_Connection->m_ServerBuffer.CommitRead();

	// TODO: Fix Windows!

	cByteBuffer Packet(512);
	Packet.WriteByte(0x2D);
	Packet.WriteByte(WindowID);

	AString InventoryTypeString;
	switch (InventoryType)
	{
		case 0: InventoryTypeString = "minecraft:chest"; break;
		case 1: InventoryTypeString = "minecraft:crafting_table"; break;
		case 2: InventoryTypeString = "minecraft:furnace"; break;
		case 3: InventoryTypeString = "minecraft:dispenser"; break;
		case 4: InventoryTypeString = "minecraft:enchanting_table"; break;
		case 5: InventoryTypeString = "minecraft:brewing_stand"; break;
		case 6: InventoryTypeString = "minecraft:villager"; break;
		case 7: InventoryTypeString = "minecraft:beacon"; break;
		case 8: InventoryTypeString = "minecraft:anvil"; break;
		case 9: InventoryTypeString = "minecraft:hopper"; break;
		default: ASSERT(!"Invalid WindowType!"); InventoryTypeString = "";
	}
	Packet.WriteVarUTF8String(InventoryTypeString);

	Packet.WriteVarUTF8String("{text:\"" + WindowTitle + "\"}");
	Packet.WriteByte(SlotNumbers);

	if (InventoryType == 11)
	{
		Packet.WriteBEInt(HorseEntityID);
	}
	
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToClient(512);
	ToClient.WriteVarUTF8String(Pkt);
	CLIENTSEND(ToClient);

	return true;
}





bool cProtocol180::HandleServerSpawnPosition(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, PosX);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, PosY);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, PosZ);

	m_Connection->m_ServerBuffer.CommitRead();

	cByteBuffer Packet(512);
	Packet.WriteByte(0x05);
	Packet.WritePosition(PosX, PosY, PosZ);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToClient(512);
	ToClient.WriteVarUTF8String(Pkt);
	CLIENTSEND(ToClient);

	return true;
}





bool cProtocol180::HandleServerUseBed(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, EntityID);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, PosX);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, PosY);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, PosZ);

	m_Connection->m_ServerBuffer.CommitRead();

	if (EntityID == m_ServerEntityID)
	{
		EntityID = m_ClientEntityID;
	}

	cByteBuffer Packet(512);
	Packet.WriteByte(0x0A);
	Packet.WriteVarInt((UInt32)EntityID);
	Packet.WritePosition(PosX, PosY, PosZ);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToClient(512);
	ToClient.WriteVarUTF8String(Pkt);
	CLIENTSEND(ToClient);

	return true;
}





bool cProtocol180::HandleServerBlockChange(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, PosX);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, PosY);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, PosZ);
	HANDLE_SERVER_PACKET_READ(ReadVarInt, UInt32, BlockID);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, BlockMetadata);

	m_Connection->m_ServerBuffer.CommitRead();

	cByteBuffer Packet(512);
	Packet.WriteByte(0x23);
	Packet.WritePosition(PosX, PosY, PosZ);
	Packet.WriteVarInt(BlockID);
	Packet.WriteByte(BlockMetadata);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToClient(512);
	ToClient.WriteVarUTF8String(Pkt);
	CLIENTSEND(ToClient);

	return true;
}





bool cProtocol180::HandleServerBlockAction(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, PosX);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, PosY);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, PosZ);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, Byte1);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, Byte2);
	HANDLE_SERVER_PACKET_READ(ReadVarInt, UInt32, BlockType);

	m_Connection->m_ServerBuffer.CommitRead();

	cByteBuffer Packet(512);
	Packet.WriteByte(0x24);
	Packet.WritePosition(PosX, PosY, PosZ);
	Packet.WriteByte(Byte1);
	Packet.WriteByte(Byte2);
	Packet.WriteVarInt(BlockType);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToClient(512);
	ToClient.WriteVarUTF8String(Pkt);
	CLIENTSEND(ToClient);

	return true;
}





bool cProtocol180::HandleServerBlockBreakAnimation(void)
{
	HANDLE_SERVER_PACKET_READ(ReadVarInt, UInt32, EntityID);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, PosX);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, PosY);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, PosZ);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, DestroyStage);

	m_Connection->m_ServerBuffer.CommitRead();

	cByteBuffer Packet(512);
	Packet.WriteByte(0x25);
	Packet.WriteVarInt(EntityID);
	Packet.WritePosition(PosX, PosY, PosZ);
	Packet.WriteByte(DestroyStage);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToClient(512);
	ToClient.WriteVarUTF8String(Pkt);
	CLIENTSEND(ToClient);

	return true;
}





bool cProtocol180::HandleServerEffect(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, EffectID);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, PosX);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, PosY);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, PosZ);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, Data);
	HANDLE_SERVER_PACKET_READ(ReadBool, bool, DisableRelativeVolume);

	m_Connection->m_ServerBuffer.CommitRead();

	cByteBuffer Packet(512);
	Packet.WriteByte(0x28);
	Packet.WriteBEInt(EffectID);
	Packet.WritePosition(PosX, PosY, PosZ);
	Packet.WriteBEInt(Data);
	Packet.WriteBool(DisableRelativeVolume);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToClient(512);
	ToClient.WriteVarUTF8String(Pkt);
	CLIENTSEND(ToClient);

	return true;
}





bool cProtocol180::HandleServerUpdateSign(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, PosX);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, PosY);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, PosZ);
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, Line1);
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, Line2);
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, Line3);
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, Line4);

	m_Connection->m_ServerBuffer.CommitRead();

	cByteBuffer Packet(512);
	Packet.WriteByte(0x33);
	Packet.WritePosition(PosX, PosY, PosZ);
	Packet.WriteVarUTF8String(Line1);
	Packet.WriteVarUTF8String(Line2);
	Packet.WriteVarUTF8String(Line3);
	Packet.WriteVarUTF8String(Line4);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToClient(512);
	ToClient.WriteVarUTF8String(Pkt);
	CLIENTSEND(ToClient);

	return true;
}





bool cProtocol180::HandleServerUpdateBlockEntity(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, PosX);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, PosY);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, PosZ);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, Action);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, DataLength);
	AString NBTData;
	if (DataLength > 0)
	{
		if (!m_Connection->m_ServerBuffer.ReadBuf((void *)NBTData.data(), DataLength))
		{
			return false;
		}
	}

	m_Connection->m_ServerBuffer.CommitRead();

	cByteBuffer Packet(512);
	Packet.WriteByte(0x35);
	Packet.WritePosition(PosX, PosY, PosZ);
	Packet.WriteByte(Action);
	Packet.WriteBEShort(DataLength);
	if (DataLength > 0)
	{
		Packet.WriteBuf((void *)NBTData.data(), DataLength);
	}
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToClient(512);
	ToClient.WriteVarUTF8String(Pkt);
	CLIENTSEND(ToClient);

	return true;
}





bool cProtocol180::HandleServerSignEditorOpen(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, PosX);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, PosY);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, PosZ);

	m_Connection->m_ServerBuffer.CommitRead();

	cByteBuffer Packet(512);
	Packet.WriteByte(0x36);
	Packet.WritePosition(PosX, PosY, PosZ);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToClient(512);
	ToClient.WriteVarUTF8String(Pkt);
	CLIENTSEND(ToClient);

	return true;
}





bool cProtocol180::HandleServerEntityEquipment(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, EntityID);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, Slot);

	cByteBuffer Packet(512);
	Packet.WriteByte(0x04);
	Packet.WriteVarInt((UInt32)EntityID);
	Packet.WriteBEShort(Slot);

	if (!ParseSlot(m_Connection->m_ServerBuffer, Packet))
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





bool cProtocol180::HandleServerUpdateHealth(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEFloat, float, Health);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, Food);
	HANDLE_SERVER_PACKET_READ(ReadBEFloat, float, FoodSaturation);

	m_Connection->m_ServerBuffer.CommitRead();

	cByteBuffer Packet(512);
	Packet.WriteByte(0x06);
	Packet.WriteBEFloat(Health);
	Packet.WriteVarInt((UInt32)Food);
	Packet.WriteBEFloat(FoodSaturation);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToClient(512);
	ToClient.WriteVarUTF8String(Pkt);
	CLIENTSEND(ToClient);

	return true;
}





bool cProtocol180::HandleServerSpawnPlayer(void)
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

	m_Connection->m_ServerBuffer.CommitRead();

	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToClient(512);
	ToClient.WriteVarUTF8String(Pkt);
	CLIENTSEND(ToClient);

	return true;
}





bool cProtocol180::HandleServerCollectPickup(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, CollectedID);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, CollectorID);

	if (CollectorID == m_ServerEntityID)
	{
		CollectorID = m_ClientEntityID;
	}

	m_Connection->m_ServerBuffer.CommitRead();

	cByteBuffer Packet(512);
	Packet.WriteByte(0x0D);
	Packet.WriteVarInt((UInt32)CollectedID);
	Packet.WriteVarInt((UInt32)CollectorID);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToClient(512);
	ToClient.WriteVarUTF8String(Pkt);
	CLIENTSEND(ToClient);

	return true;
}





bool cProtocol180::HandleServerEntityVelocity(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, EntityID);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, VelocityX);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, VelocityY);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, VelocityZ);

	m_Connection->m_ServerBuffer.CommitRead();

	if (EntityID == m_ServerEntityID)
	{
		EntityID = m_ClientEntityID;
	}

	cByteBuffer Packet(512);
	Packet.WriteByte(0x12);
	Packet.WriteVarInt((UInt32)EntityID);
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





bool cProtocol180::HandleServerDestroyEntities(void)
{
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, ArrayLength);

	cByteBuffer Packet(512);
	Packet.WriteByte(0x13);
	Packet.WriteVarInt(ArrayLength);

	for (int i = 0; i < ArrayLength; i++)
	{
		HANDLE_SERVER_PACKET_READ(ReadBEInt, int, EntityID);

		Packet.WriteVarInt((UInt32)EntityID);
	}

	m_Connection->m_ServerBuffer.CommitRead();

	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToClient(512);
	ToClient.WriteVarUTF8String(Pkt);
	CLIENTSEND(ToClient);

	return true;
}





bool cProtocol180::HandleServerEntity(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, EntityID);

	m_Connection->m_ServerBuffer.CommitRead();

	if (EntityID == m_ServerEntityID)
	{
		EntityID = m_ClientEntityID;
	}

	cByteBuffer Packet(512);
	Packet.WriteByte(0x14);
	Packet.WriteVarInt((UInt32)EntityID);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToClient(512);
	ToClient.WriteVarUTF8String(Pkt);
	CLIENTSEND(ToClient);

	return true;
}





bool cProtocol180::HandleServerEntityRelativeMove(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, EntityID);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, dx);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, dy);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, dz);

	m_Connection->m_ServerBuffer.CommitRead();

	if (EntityID == m_ServerEntityID)
	{
		EntityID = m_ClientEntityID;
	}

	cByteBuffer Packet(512);
	Packet.WriteByte(0x15);
	Packet.WriteVarInt((UInt32)EntityID);
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





bool cProtocol180::HandleServerEntityLook(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, EntityID);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, Yaw);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, Pitch);

	m_Connection->m_ServerBuffer.CommitRead();

	if (EntityID == m_ServerEntityID)
	{
		EntityID = m_ClientEntityID;
	}

	cByteBuffer Packet(512);
	Packet.WriteByte(0x16);
	Packet.WriteVarInt((UInt32)EntityID);
	Packet.WriteByte(Yaw);
	Packet.WriteByte(Pitch);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToClient(512);
	ToClient.WriteVarUTF8String(Pkt);
	CLIENTSEND(ToClient);

	return true;
}





bool cProtocol180::HandleServerEntityRelativeMoveLook(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, EntityID);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, dx);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, dy);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, dz);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, Yaw);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, Pitch);

	m_Connection->m_ServerBuffer.CommitRead();

	if (EntityID == m_ServerEntityID)
	{
		EntityID = m_ClientEntityID;
	}

	cByteBuffer Packet(512);
	Packet.WriteByte(0x17);
	Packet.WriteVarInt((UInt32)EntityID);
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





bool cProtocol180::HandleServerEntityTeleport(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, EntityID);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, AbsX);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, AbsY);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, AbsZ);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, Yaw);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, Pitch);

	m_Connection->m_ServerBuffer.CommitRead();

	if (EntityID == m_ServerEntityID)
	{
		EntityID = m_ClientEntityID;
	}

	cByteBuffer Packet(512);
	Packet.WriteByte(0x18);
	Packet.WriteVarInt((UInt32)EntityID);
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





bool cProtocol180::HandleServerEntityHeadLook(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, EntityID);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, HeadYaw);

	m_Connection->m_ServerBuffer.CommitRead();

	if (EntityID == m_ServerEntityID)
	{
		EntityID = m_ClientEntityID;
	}

	cByteBuffer Packet(512);
	Packet.WriteByte(0x19);
	Packet.WriteVarInt((UInt32)EntityID);
	Packet.WriteByte(HeadYaw);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToClient(512);
	ToClient.WriteVarUTF8String(Pkt);
	CLIENTSEND(ToClient);

	return true;
}





bool cProtocol180::HandleServerEntityMetadata(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, EntityID);

	if (EntityID == m_ServerEntityID)
	{
		EntityID = m_ClientEntityID;
	}

	cByteBuffer Packet(512);
	Packet.WriteByte(0x1C);
	Packet.WriteVarInt((UInt32)EntityID);

	if (!ParseMetadata(m_Connection->m_ServerBuffer, Packet))
	{
		return false;
	}

	m_Connection->m_ServerBuffer.CommitRead();

	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToClient(512);
	ToClient.WriteVarUTF8String(Pkt);
	//CLIENTSEND(ToClient);   // TODO: Fix Entity Metadata!

	return true;
}





bool cProtocol180::HandleServerEntityEffect(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, EntityID);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, EffectID);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, Amplifier);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, Duration);

	m_Connection->m_ServerBuffer.CommitRead();

	cByteBuffer Packet(512);
	Packet.WriteByte(0x1D);
	Packet.WriteVarInt((UInt32)EntityID);
	Packet.WriteByte(EffectID);
	Packet.WriteByte(Amplifier);
	Packet.WriteVarInt(Duration);
	Packet.WriteBool(false);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToClient(512);
	ToClient.WriteVarUTF8String(Pkt);
	CLIENTSEND(ToClient);

	return true;
}





bool cProtocol180::HandleServerRemoveEntityEffect(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, EntityID);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, EffectID);

	m_Connection->m_ServerBuffer.CommitRead();

	cByteBuffer Packet(512);
	Packet.WriteByte(0x1E);
	Packet.WriteVarInt((UInt32)EntityID);
	Packet.WriteByte(EffectID);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToClient(512);
	ToClient.WriteVarUTF8String(Pkt);
	CLIENTSEND(ToClient);

	return true;
}





bool cProtocol180::HandleServerSetExperience(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEFloat, float, ExperienceBar);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, Level);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, TotalExperience);

	m_Connection->m_ServerBuffer.CommitRead();

	cByteBuffer Packet(512);
	Packet.WriteByte(0x1F);
	Packet.WriteBEFloat(ExperienceBar);
	Packet.WriteVarInt((UInt32)Level);
	Packet.WriteVarInt((UInt32)TotalExperience);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToClient(512);
	ToClient.WriteVarUTF8String(Pkt);
	CLIENTSEND(ToClient);

	return true;
}





bool cProtocol180::HandleServerEntityProperties(void)
{
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, EntityID);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, Count);

	if (EntityID == m_ServerEntityID)
	{
		EntityID = m_ClientEntityID;
	}

	cByteBuffer Packet(512);
	Packet.WriteByte(0x20);
	Packet.WriteVarInt((UInt32)EntityID);
	Packet.WriteBEInt(Count);

	for (int i = 0; i < Count; i++)
	{
		HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, Key);
		HANDLE_SERVER_PACKET_READ(ReadBEDouble, double, Value);
		HANDLE_SERVER_PACKET_READ(ReadBEShort, short, ListLength);

		Packet.WriteVarUTF8String(Key);
		Packet.WriteBEDouble(Value);
		Packet.WriteVarInt((UInt32)ListLength);

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





bool cProtocol180::HandleServerPlayerListItem(void)
{
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, PlayerName);
	HANDLE_SERVER_PACKET_READ(ReadBool, bool, Online);
	HANDLE_SERVER_PACKET_READ(ReadBEShort, short, Ping);

	m_Connection->m_ServerBuffer.CommitRead();

	// TODO: Add Player List Item!

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

	return true;
}





bool cProtocol180::HandleServerUpdateScore(void)
{
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, ItemName);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, UpdateRemove);
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, ScoreName);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, Value);

	m_Connection->m_ServerBuffer.CommitRead();

	cByteBuffer Packet(512);
	Packet.WriteByte(0x3C);
	Packet.WriteVarUTF8String(ItemName);
	Packet.WriteByte(UpdateRemove);
	Packet.WriteVarUTF8String(ScoreName);
	Packet.WriteVarInt((UInt32)Value);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToClient(512);
	ToClient.WriteVarUTF8String(Pkt);
	CLIENTSEND(ToClient);

	return true;
}





bool cProtocol180::HandleServerTeams(void)
{
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, TeamName);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, Mode);

	cByteBuffer Packet(512);
	Packet.WriteByte(0x3E);
	Packet.WriteVarUTF8String(TeamName);
	Packet.WriteByte(Mode);

	if ((Mode == 0) || (Mode == 2))
	{
		HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, TeamDisplayName);
		HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, TeamPrefix);
		HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, TeamSuffix);
		HANDLE_SERVER_PACKET_READ(ReadByte, Byte, FriendlyFire);

		Packet.WriteVarUTF8String(TeamDisplayName);
		Packet.WriteVarUTF8String(TeamPrefix);
		Packet.WriteVarUTF8String(TeamSuffix);
		Packet.WriteByte(FriendlyFire);
		Packet.WriteVarUTF8String("always");
		Packet.WriteByte(0);
	}
	if ((Mode == 0) || (Mode == 3) || (Mode == 4))
	{
		HANDLE_SERVER_PACKET_READ(ReadBEShort, short, PlayerCount);

		Packet.WriteVarInt((UInt32)PlayerCount);

		for (short i = 0; i < PlayerCount; i++)
		{
			HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, Player);

			Packet.WriteVarUTF8String(Player);
		}
	}

	m_Connection->m_ServerBuffer.CommitRead();

	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToClient(512);
	ToClient.WriteVarUTF8String(Pkt);
	CLIENTSEND(ToClient);

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

	return true;
}





bool cProtocol180::HandleServerSpawnPainting(void)
{
	HANDLE_SERVER_PACKET_READ(ReadVarInt, UInt32, EntityID);
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, Title);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, PosX);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, PosY);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, PosZ);
	HANDLE_SERVER_PACKET_READ(ReadBEInt, int, Direction);

	m_Connection->m_ServerBuffer.CommitRead();

	cByteBuffer Packet(512);
	Packet.WriteByte(0x10);
	Packet.WriteVarInt(EntityID);
	Packet.WriteVarUTF8String(Title);
	Packet.WritePosition(PosX, PosY, PosZ);
	Packet.WriteByte(Direction);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToClient(512);
	ToClient.WriteVarUTF8String(Pkt);
	CLIENTSEND(ToClient);

	return true;
}





bool cProtocol180::HandleServerScoreboardObjective(void)
{
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, ObjectiveName);
	HANDLE_SERVER_PACKET_READ(ReadVarUTF8String, AString, ObjectiveValue);
	HANDLE_SERVER_PACKET_READ(ReadByte, Byte, Value);

	cByteBuffer Packet(512);
	Packet.WriteByte(0x3B);
	Packet.WriteVarUTF8String(ObjectiveName);
	Packet.WriteByte(Value);
	Packet.WriteVarUTF8String(ObjectiveValue);
	Packet.WriteVarUTF8String("integer");
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToClient(512);
	ToClient.WriteVarUTF8String(Pkt);
	CLIENTSEND(ToClient);

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

	return true;
}





bool cProtocol180::HandleClientStatusRequest(void)
{
	// Send the response:
	AString Response = "{\"version\":{\"name\":\"14w21b\",\"protocol\":20},\"players\":{";
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





bool cProtocol180::HandleClientClientSettings(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadVarUTF8String, AString, Locale);
	HANDLE_CLIENT_PACKET_READ(ReadByte, Byte, ViewDistance);
	HANDLE_CLIENT_PACKET_READ(ReadByte, Byte, ChatFlags);
	HANDLE_CLIENT_PACKET_READ(ReadBool, bool, ChatColors);
	HANDLE_CLIENT_PACKET_READ(ReadByte, Byte, DisplayedSkinParts);

	m_Connection->m_ClientBuffer.CommitRead();

	cByteBuffer Packet(512);
	Packet.WriteByte(0x15);
	Packet.WriteVarUTF8String(Locale);
	Packet.WriteByte(ViewDistance);
	Packet.WriteByte(ChatFlags);
	Packet.WriteBool(ChatColors);
	Packet.WriteByte(0);
	Packet.WriteBool(false);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToServer(512);
	ToServer.WriteVarUTF8String(Pkt);
	SERVERSEND(ToServer);

	return true;
}





bool cProtocol180::HandleClientPlayerDigging(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadByte, Byte, Status);
	HANDLE_CLIENT_PACKET_READ(ReadBEInt64, Int64, Position);
	HANDLE_CLIENT_PACKET_READ(ReadByte, Byte, Face);

	m_Connection->m_ClientBuffer.CommitRead();

	cByteBuffer Packet(512);
	Packet.WriteByte(0x07);
	Packet.WriteByte(Status);

	int BlockX = Position >> 38;
	int BlockY = Position << 26 >> 52;
	int BlockZ = Position << 38 >> 38;
	Packet.WriteBEInt(BlockX);
	Packet.WriteByte(BlockY);
	Packet.WriteBEInt(BlockZ);

	Packet.WriteByte(Face);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToServer(512);
	ToServer.WriteVarUTF8String(Pkt);
	SERVERSEND(ToServer);

	return true;
}





bool cProtocol180::HandleClientPlayerBlockPlacement(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadBEInt64, Int64, Location);
	HANDLE_CLIENT_PACKET_READ(ReadByte, Byte, Direction);

	cByteBuffer Packet(512);
	Packet.WriteByte(0x08);

	int BlockX = Location >> 38;
	int BlockY = Location << 26 >> 52;
	int BlockZ = Location << 38 >> 38;
	Packet.WriteBEInt(BlockX);
	Packet.WriteByte((Byte)BlockY);
	Packet.WriteBEInt(BlockZ);
	Packet.WriteByte(Direction);

	if (!ParseSlot(m_Connection->m_ClientBuffer, Packet))
	{
		return false;
	}

	HANDLE_CLIENT_PACKET_READ(ReadByte, Byte, CursorPosX);
	HANDLE_CLIENT_PACKET_READ(ReadByte, Byte, CursorPosY);
	HANDLE_CLIENT_PACKET_READ(ReadByte, Byte, CursorPosZ);

	m_Connection->m_ClientBuffer.CommitRead();

	Packet.WriteByte(CursorPosX);
	Packet.WriteByte(CursorPosY);
	Packet.WriteByte(CursorPosZ);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToServer(512);
	ToServer.WriteVarUTF8String(Pkt);
	SERVERSEND(ToServer);

	return true;
}





bool cProtocol180::HandleClientUpdateSign(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadBEInt64, Int64, Location);
	HANDLE_CLIENT_PACKET_READ(ReadVarUTF8String, AString, Line1);
	HANDLE_CLIENT_PACKET_READ(ReadVarUTF8String, AString, Line2);
	HANDLE_CLIENT_PACKET_READ(ReadVarUTF8String, AString, Line3);
	HANDLE_CLIENT_PACKET_READ(ReadVarUTF8String, AString, Line4);

	m_Connection->m_ClientBuffer.CommitRead();

	cByteBuffer Packet(512);
	Packet.WriteByte(0x12);

	int BlockX = Location >> 38;
	int BlockY = Location << 26 >> 52;
	int BlockZ = Location << 38 >> 38;
	Packet.WriteBEInt(BlockX);
	Packet.WriteBEShort((short)BlockY);
	Packet.WriteBEInt(BlockZ);

	Packet.WriteVarUTF8String(Line1);
	Packet.WriteVarUTF8String(Line2);
	Packet.WriteVarUTF8String(Line3);
	Packet.WriteVarUTF8String(Line4);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToServer(512);
	ToServer.WriteVarUTF8String(Pkt);
	SERVERSEND(ToServer);

	return true;
}





bool cProtocol180::HandleClientKeepAlive(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadVarInt, UInt32, KeepAliveID);

	m_Connection->m_ClientBuffer.CommitRead();

	cByteBuffer Packet(512);
	Packet.WriteByte(0x00);
	Packet.WriteBEInt((int)KeepAliveID);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToServer(512);
	ToServer.WriteVarUTF8String(Pkt);
	SERVERSEND(ToServer);

	return true;
}





bool cProtocol180::HandleClientUseEntity(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadVarInt, UInt32, Target);
	HANDLE_CLIENT_PACKET_READ(ReadByte, Byte, Mouse);

	m_Connection->m_ClientBuffer.CommitRead();

	cByteBuffer Packet(512);
	Packet.WriteByte(0x02);
	Packet.WriteBEInt((int)Target);
	Packet.WriteByte(Mouse);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToServer(512);
	ToServer.WriteVarUTF8String(Pkt);
	SERVERSEND(ToServer);

	return true;
}





bool cProtocol180::HandleClientAnimation(void)
{
	return true;
}





bool cProtocol180::HandleClientEntityAction(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadVarInt, UInt32, EntityID);
	HANDLE_CLIENT_PACKET_READ(ReadByte, Byte, ActionID);
	HANDLE_CLIENT_PACKET_READ(ReadVarInt, UInt32, JumpBoost);

	m_Connection->m_ClientBuffer.CommitRead();

	if ((int)EntityID == m_ClientEntityID)
	{
		EntityID = (int)m_ServerEntityID;
	}

	cByteBuffer Packet(512);
	Packet.WriteByte(0x0B);
	Packet.WriteBEInt((int)EntityID);

	ActionID += 1;
	Packet.WriteByte(ActionID);

	Packet.WriteBEInt((int)JumpBoost);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToServer(512);
	ToServer.WriteVarUTF8String(Pkt);
	SERVERSEND(ToServer);

	return true;
}





bool cProtocol180::HandleClientSteerVehicle(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadBEFloat, float, Sideways);
	HANDLE_CLIENT_PACKET_READ(ReadBEFloat, float, Forward);
	HANDLE_CLIENT_PACKET_READ(ReadByte, Byte, Flags);

	m_Connection->m_ClientBuffer.CommitRead();

	cByteBuffer Packet(512);
	Packet.WriteByte(0x0C);
	Packet.WriteBEFloat(Sideways);
	Packet.WriteBEFloat(Forward);

	if (Flags == 0x1)
	{
		Packet.WriteBool(true);
		Packet.WriteBool(false);
	}
	else if (Flags == 0x2)
	{
		Packet.WriteBool(false);
		Packet.WriteBool(true);
	}

	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToServer(512);
	ToServer.WriteVarUTF8String(Pkt);
	SERVERSEND(ToServer);

	return true;
}





bool cProtocol180::HandleClientClientStatus(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadByte, Byte, ActionID);

	m_Connection->m_ClientBuffer.CommitRead();

	cByteBuffer Packet(512);
	Packet.WriteByte(0x16);
	Packet.WriteByte(ActionID);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToServer(512);
	ToServer.WriteVarUTF8String(Pkt);
	SERVERSEND(ToServer);

	return true;
}





bool cProtocol180::HandleClientPlayerPosition(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadBEDouble, double, PosX);
	HANDLE_CLIENT_PACKET_READ(ReadBEDouble, double, FeetY);
	HANDLE_CLIENT_PACKET_READ(ReadBEDouble, double, PosZ);
	HANDLE_CLIENT_PACKET_READ(ReadBool, bool, OnGround);

	m_Connection->m_ClientBuffer.CommitRead();

	cByteBuffer Packet(512);
	Packet.WriteByte(0x04);
	Packet.WriteBEDouble(PosX);
	Packet.WriteBEDouble(FeetY);
	Packet.WriteBEDouble(FeetY + 0.13);  // Modify it to prevent "Illegal stance"
	Packet.WriteBEDouble(PosZ);
	Packet.WriteBool(OnGround);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToServer(512);
	ToServer.WriteVarUTF8String(Pkt);
	SERVERSEND(ToServer);

	return true;
}





bool cProtocol180::HandleClientPlayerPositionLook(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadBEDouble, double, PosX);
	HANDLE_CLIENT_PACKET_READ(ReadBEDouble, double, FeetY);
	HANDLE_CLIENT_PACKET_READ(ReadBEDouble, double, PosZ);
	HANDLE_CLIENT_PACKET_READ(ReadBEFloat, float, Yaw);
	HANDLE_CLIENT_PACKET_READ(ReadBEFloat, float, Pitch);
	HANDLE_CLIENT_PACKET_READ(ReadBool, bool, OnGround);

	m_Connection->m_ClientBuffer.CommitRead();

	cByteBuffer Packet(512);
	Packet.WriteByte(0x06);
	Packet.WriteBEDouble(PosX);
	Packet.WriteBEDouble(FeetY);
	Packet.WriteBEDouble(FeetY + 0.13);  // Modify it to prevent "Illegal stance"
	Packet.WriteBEDouble(PosZ);
	Packet.WriteBEFloat(Yaw);
	Packet.WriteBEFloat(Pitch);
	Packet.WriteBool(OnGround);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToServer(512);
	ToServer.WriteVarUTF8String(Pkt);
	SERVERSEND(ToServer);

	return true;
}





bool cProtocol180::HandleClientSpectate(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadVarUTF8String, AString, UUID);

	m_Connection->m_ClientBuffer.CommitRead();

	cByteBuffer Packet(512);
	Packet.WriteByte(0x18);
	Packet.WriteVarUTF8String(UUID);
	AString Pkt;
	Packet.ReadAll(Pkt);
	cByteBuffer ToServer(512);
	ToServer.WriteVarUTF8String(Pkt);
	SERVERSEND(ToServer);

	return true;
}





bool cProtocol180::HandleClientPluginMessage(void)
{
	HANDLE_CLIENT_PACKET_READ(ReadVarUTF8String, AString, Channel);
	HANDLE_CLIENT_PACKET_READ(ReadBEShort, short, Length);

	AString data;
	if (!m_Connection->m_ClientBuffer.ReadString(data, Length))
	{
		return false;
	}

	m_Connection->m_ClientBuffer.CommitRead();

	return true;
}




