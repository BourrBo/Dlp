from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.models.incident import Incident, IncidentEvent
from app.models.persisted_finding import FindingStatus


class IncidentWithEvents(Incident):
    events: list[IncidentEvent]


class IncidentUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: FindingStatus | None = None
    assignee: str | None = Field(default=None, max_length=255)

    @model_validator(mode="after")
    def validate_patch(self) -> "IncidentUpdate":
        if not self.model_fields_set:
            raise ValueError("At least one of status or assignee must be provided")
        if "status" in self.model_fields_set and self.status is None:
            raise ValueError("status cannot be null")
        return self
