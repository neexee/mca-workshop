from dataclasses import dataclass
import datetime

    
@dataclass
class Event:
    Time: datetime.datetime
    EventId: int
    GUID: str
    ProcessName: str
    Image: str
    User: str
    Host: str
    Details: dict
    Score: float # enriched event
    Risk: tuple # from model
