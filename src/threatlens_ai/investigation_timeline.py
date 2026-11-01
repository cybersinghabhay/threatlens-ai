from datetime import datetime


def sort_events_chronologically(events):
    """
    Sort security events by timestamp from earliest to latest.

    Events with missing or invalid timestamps are placed at the end.
    Their original relative order is preserved.
    The original list remains unchanged.
    """

    def get_sort_key(event):
        timestamp = event.get("timestamp")

        if not isinstance(timestamp, str):
            return (1, None)

        try:
            parsed_timestamp = datetime.fromisoformat(timestamp)
            return (0, parsed_timestamp)

        except ValueError:
            return (1, None)

    return sorted(events, key=get_sort_key)