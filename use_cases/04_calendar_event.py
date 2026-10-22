"""Show the week's agenda, then add a demo event and cancel it.

Creates and cancels one private event (no attendees, so no invitations are
emailed). Run with PROTONLITE_SESSION set.
"""

import datetime as dt

from protonlite import ProtonMail


def main() -> None:
    client = ProtonMail.from_session()
    calendars = client.list_calendars()
    if not calendars:
        print("This account has no calendar; provisioning a default one.")
        cal_id = client.provision_default_calendar()
    else:
        cal_id = calendars[0]["ID"]

    now = dt.datetime.now(dt.timezone.utc)
    start = now + dt.timedelta(days=1)
    end = start + dt.timedelta(hours=1)

    print("Creating a demo event tomorrow ...")
    created = client.create_event(
        cal_id, summary="protonlite demo event", start=start, end=end,
        description="Created by the protonlite use-case example.",
    )
    event_id = created.get("id", "")
    print(f"  created (id {event_id or '?'}).")

    begin = int((now - dt.timedelta(days=1)).timestamp())
    finish = int((now + dt.timedelta(days=3)).timestamp())
    agenda = client.list_events(cal_id, start=begin, end=finish)
    print(f"Agenda has {len(agenda)} event(s) in the window:")
    for ev in agenda:
        when = dt.datetime.fromtimestamp(ev.start, dt.timezone.utc).strftime("%Y-%m-%d %H:%M")
        print(f"  {when}  {ev.title}")

    if not event_id:  # fall back to finding our event by title
        event_id = next((ev.id for ev in agenda if ev.title == "protonlite demo event"), "")
    if event_id:
        client.delete_event(cal_id, event_id)
        print("Cancelled the demo event -- calendar clean.")


if __name__ == "__main__":
    main()
