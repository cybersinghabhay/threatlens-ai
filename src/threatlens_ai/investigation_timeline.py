
from datetime import datetime, timezone


def sort_events_chronologically(events):
    """
    Sort security events by timestamp from earliest to latest.

    Timezone-aware timestamps are converted to UTC.
    Naive timestamps are treated as UTC because their timezone
    is unknown and must not be inferred.

    Events with missing or invalid timestamps are placed at the end.
    Their original relative order is preserved.
    The original list remains unchanged.
    """

    def get_sort_key(event):
        timestamp = event.get("timestamp")

        if not isinstance(timestamp, str):
            return (1, datetime.max.replace(tzinfo=timezone.utc))

        try:
            parsed_timestamp = datetime.fromisoformat(timestamp)

            if parsed_timestamp.tzinfo is None:
                parsed_timestamp = parsed_timestamp.replace(
                    tzinfo=timezone.utc
                )
            else:
                parsed_timestamp = parsed_timestamp.astimezone(
                    timezone.utc
                )

            return (0, parsed_timestamp)

        except ValueError:
            return (1, datetime.max.replace(tzinfo=timezone.utc))

    return sorted(events, key=get_sort_key)
