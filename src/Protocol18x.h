
// Protocol17x.h


#pragma once

#include "Protocol17x.h"
#include "Connection.h"





class cProtocol180 :
	public cProtocol176
{
	typedef cProtocol176 super;

public:
	cProtocol180(cConnection * a_Connection);

	virtual bool HandleClientPackets(UInt32 a_PacketType, UInt32 a_PacketLen, UInt32 a_PacketReadSoFar) override;
	virtual bool HandleServerPackets(UInt32 a_PacketType, UInt32 a_PacketLen, UInt32 a_PacketReadSoFar) override;

	bool HandleServerChatMessage(void);
	bool HandleServerPlayerPositionLook(void);
	bool HandleServerOpenWindow(void);
	bool HandleServerSpawnPosition(void);
	virtual bool HandleServerUseBed(void) override;
	bool HandleServerBlockChange(void);
	bool HandleServerBlockAction(void);
	bool HandleServerBlockBreakAnimation(void);
	bool HandleServerEffect(void);
	bool HandleServerUpdateSign(void);
	bool HandleServerUpdateBlockEntity(void);
	bool HandleServerSignEditorOpen(void);
	bool HandleServerEntityEquipment(void);
	bool HandleServerUpdateHealth(void);
	virtual bool HandleServerSpawnPlayer(void) override;
	virtual bool HandleServerCollectPickup(void) override;
	virtual bool HandleServerEntityVelocity(void) override;
	bool HandleServerDestroyEntities(void);
	virtual bool HandleServerEntity(void) override;
	virtual bool HandleServerEntityRelativeMove(void) override;
	virtual bool HandleServerEntityLook(void) override;
	virtual bool HandleServerEntityRelativeMoveLook(void) override;
	virtual bool HandleServerEntityTeleport(void) override;
	virtual bool HandleServerEntityHeadLook(void) override;
	virtual bool HandleServerEntityMetadata(void) override;
	bool HandleServerEntityEffect(void);
	bool HandleServerRemoveEntityEffect(void);
	bool HandleServerSetExperience(void);
	virtual bool HandleServerEntityProperties(void) override;
	virtual bool HandleServerPlayerListItem(void) override;
	bool HandleServerUpdateScore(void);
	virtual bool HandleServerTeams(void) override;
	bool HandleServerSpawnPainting(void);
	virtual bool HandleServerScoreboardObjective(void) override;

	virtual bool HandleClientStatusRequest(void) override;
	bool HandleClientClientSettings(void);
	bool HandleClientPlayerDigging(void);
	bool HandleClientPlayerBlockPlacement(void);
	bool HandleClientUpdateSign(void);
	bool HandleClientKeepAlive(void);
	bool HandleClientUseEntity(void);
	virtual bool HandleClientAnimation(void) override;
	virtual bool HandleClientEntityAction(void) override;
	bool HandleClientSteerVehicle(void);
	bool HandleClientClientStatus(void);
	bool HandleClientPlayerPosition(void);
	bool HandleClientPlayerPositionLook(void);
	bool HandleClientSpectate(void);
	bool HandleClientPluginMessage(void);
};
