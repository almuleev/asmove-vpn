from calendar import monthrange
from datetime import date, datetime, time, timedelta, timezone


MOSCOW = timezone(timedelta(hours=3), "МСК")


def access_date(timestamp):
    return datetime.fromtimestamp(timestamp, MOSCOW).date()


def noon(day):
    return int(datetime.combine(day, time(12), MOSCOW).timestamp())


MAX_ACCESS_UNTIL = noon(date.max)


def next_month(timestamp, day):
    current = access_date(timestamp)
    year, month = current.year, current.month + 1
    if month == 13:
        year, month = year + 1, 1
    return noon(date(year, month, min(day, monthrange(year, month)[1])))


def expired(account, timestamp):
    return account["access_until"] is not None and account["access_until"] <= timestamp
