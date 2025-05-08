from pydantic import BaseModel

class AttackLogEntry(BaseModel):
    time: str
    type: str
    confidence: str
    src_ip: str
    packets: float

class MitigationLogEntry(BaseModel):
    time: str
    action: int
    target: str
    attack: str
    effectiveness: float

class StatusResponse(BaseModel):
    running: bool
    lastAction: int
    currentThreat: str
    attackerIp: str
    lastReward: float