from collections import Counter
from datetime import date, datetime, time, timedelta, timezone

from fastapi import APIRouter, Query

from app.database import get_supabase


router = APIRouter(prefix="/api/overview", tags=["overview"])


@router.get("")
def get_overview(org_id: str, days: int = Query(default=30, ge=1, le=90)):
    end = datetime.now(timezone.utc)
    first_day = end.date() - timedelta(days=days - 1)
    start = datetime.combine(first_day, time.min, tzinfo=timezone.utc)

    query = (
        get_supabase()
        .table("dlp_events")
        .select("id,channel,data_type,confidence,destination,decision,created_at")
        .eq("org_id", org_id)
    )
    query.params["and"] = (
        f"(created_at.gte.{start.isoformat()},created_at.lte.{end.isoformat()})"
    )
    events = query.execute().data

    decision_counts = Counter()
    data_type_counts = Counter()
    channel_counts = Counter()
    daily_counts = Counter()

    for event in events:
        if event.get("decision"):
            decision_counts[event["decision"]] += 1
        if event.get("data_type"):
            data_type_counts[event["data_type"]] += 1
        if event.get("channel"):
            channel_counts[event["channel"]] += 1
        if event.get("created_at"):
            event_date = datetime.fromisoformat(
                event["created_at"].replace("Z", "+00:00")
            ).date()
            daily_counts[event_date] += 1

    daily_trend = []
    for offset in range(days):
        trend_date = first_day + timedelta(days=offset)
        daily_trend.append(
            {"date": trend_date.isoformat(), "count": daily_counts[trend_date]}
        )
    recent_events = sorted(
        events,
        key=lambda event: event.get("created_at") or "",
        reverse=True,
    )[:10]
    safe_recent_events = [
        {
            "id": event.get("id"),
            "channel": event.get("channel"),
            "data_type": event.get("data_type"),
            "confidence": event.get("confidence"),
            "destination": event.get("destination"),
            "decision": event.get("decision"),
            "created_at": event.get("created_at"),
        }
        for event in recent_events
    ]

    return {
        "total_events": len(events),
        "decision_counts": dict(decision_counts),
        "data_type_counts": dict(data_type_counts),
        "channel_counts": dict(channel_counts),
        "daily_trend": daily_trend,
        "recent_events": safe_recent_events,
        "severity_counts": {},
        "classification_counts": {},
    }
