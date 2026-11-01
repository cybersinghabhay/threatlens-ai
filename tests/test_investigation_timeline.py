from threatlens_ai.investigation_timeline import sort_events_chronologically


def test_events_are_sorted_by_timestamp():
    events = [
        {"timestamp": "2026-10-30T10:05:00", "event_type": "failed_login"},
        {"timestamp": "2026-10-30T10:02:00", "event_type": "successful_login"},
        {"timestamp": "2026-10-30T10:08:00", "event_type": "critical"},
    ]

    result = sort_events_chronologically(events)

    assert result == [
        {"timestamp": "2026-10-30T10:02:00", "event_type": "successful_login"},
        {"timestamp": "2026-10-30T10:05:00", "event_type": "failed_login"},
        {"timestamp": "2026-10-30T10:08:00", "event_type": "critical"},
    ]


def test_original_events_list_remains_unchanged():
    events = [
        {"timestamp": "2026-10-30T10:05:00", "event_type": "failed_login"},
        {"timestamp": "2026-10-30T10:02:00", "event_type": "successful_login"},
    ]

    original_events = events.copy()

    result = sort_events_chronologically(events)

    assert events == original_events
    assert result is not events


def test_events_without_timestamps_are_placed_at_the_end():
    events = [
        {"timestamp": None, "event_type": "warning"},
        {"timestamp": "2026-10-30T10:05:00", "event_type": "failed_login"},
        {"event_type": "unknown_event"},
        {"timestamp": "2026-10-30T10:02:00", "event_type": "successful_login"},
    ]

    result = sort_events_chronologically(events)

    assert result == [
        {"timestamp": "2026-10-30T10:02:00", "event_type": "successful_login"},
        {"timestamp": "2026-10-30T10:05:00", "event_type": "failed_login"},
        {"timestamp": None, "event_type": "warning"},
        {"event_type": "unknown_event"},
    ]


def test_events_with_invalid_timestamps_are_placed_at_the_end():
    events = [
        {"timestamp": "2026-00-01T00:00:00", "event_type": "warning"},
        {"timestamp": "2026-10-30T10:05:00", "event_type": "failed_login"},
        {"timestamp": "2026-10-30T10:02:00", "event_type": "successful_login"},
    ]

    result = sort_events_chronologically(events)

    assert result == [
        {"timestamp": "2026-10-30T10:02:00", "event_type": "successful_login"},
        {"timestamp": "2026-10-30T10:05:00", "event_type": "failed_login"},
        {"timestamp": "2026-00-01T00:00:00", "event_type": "warning"},
    ]

def test_empty_event_list_returns_empty_list():
    events = []

    result = sort_events_chronologically(events)

    assert result == []
    assert result is not events