"""Stable, revocable subscription addresses independent of a VPN node's IP."""
import hmac
import re


def signature(settings, account):
    message = "vpn-subscription-v1:" + account["id"] + ":" + account["auth_version"]
    return hmac.digest(settings.access_key, message.encode(), "sha256").hex()


def subscription_url(settings, account):
    return settings.origin + "/sub/" + account["id"] + "/" + signature(settings, account)


def authorized(settings, account, supplied):
    return bool(account and re.fullmatch(r"[a-f0-9]{64}", supplied)
                and hmac.compare_digest(signature(settings, account), supplied))
