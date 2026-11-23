"""VDSina public API v1. Monetary values remain in the account currency."""

import http.client
import ipaddress
import json
import os
from decimal import Decimal
from .reminders import SocksHTTPSConnection, ReminderError

REQUIRED_DAILY_COST = Decimal('0.07')


class ProviderError(Exception):
    pass


class ProviderValidationError(ProviderError):
    """An explicit validation rejection: no service creation was accepted."""
    pass


class Vdsina:
    def __init__(self, host="userapi.vdsina.com", *, direct=False):
        if host != "userapi.vdsina.com":
            raise ValueError("Only VDSina.com USD accounts are supported")
        self.host = host
        self.direct = direct

    def request(self, method, path, data=None):
        token = os.environ.get("VDSINA_API_TOKEN", "")
        if not token or any(character.isspace() for character in token):
            raise ProviderError("provider_token_missing")
        try:
            proxy = None if self.direct else os.environ.get("VDSINA_SOCKS_PROXY")
            connection = SocksHTTPSConnection(self.host, proxy) if proxy else http.client.HTTPSConnection(self.host, timeout=12)
        except ReminderError:
            raise ProviderError("provider_proxy_invalid") from None
        try:
            connection.request(method, "/v1/" + path, json.dumps(data) if data is not None else None,
                               {"Authorization": token, "Content-Type": "application/json"})
            response = connection.getresponse()
            body = response.read(2 * 1024 * 1024 + 1)
            if response.status in {400, 422} and len(body) <= 2 * 1024 * 1024:
                try:
                    failure = json.loads(body)
                except ValueError:
                    failure = {}
                if isinstance(failure, dict) and failure.get("status") == "error" and failure.get("description") == "Validation Error":
                    fields = failure.get("data", {})
                    quota = isinstance(fields, dict) and any(
                        "cannot order more services" in str(value).lower() for value in fields.get("server-plan", [])
                    )
                    raise ProviderValidationError("provider_tariff_limit" if quota else "provider_validation_error")
            if not 200 <= response.status < 300 or len(body) > 2 * 1024 * 1024:
                raise ProviderError("provider_http_" + str(response.status))
            if response.status == 204:
                return {}
            result = json.loads(body)
            if result.get("status") != "ok":
                raise ProviderError("provider_rejected")
            return result["data"]
        except (OSError, ValueError, KeyError, http.client.HTTPException):
            raise ProviderError("provider_unavailable") from None
        finally:
            connection.close()

    def servers(self):
        rows = self.request("GET", "server")
        # VDSina returns data:null after deleting the account's last VPS.
        if rows is None:
            return []
        if not isinstance(rows, list):
            raise ProviderError("provider_server_list_invalid")
        return [row for row in rows if row.get("status") != "deleted"]

    def quote(self, candidate, *, retiring_service_id=None):
        plans = self.request("GET", "server-plan/" + str(candidate["group_id"]))
        plan = next((row for row in plans if row["id"] == candidate["plan_id"]), None)
        datacenters = self.request("GET", "datacenter")
        dc = next((row for row in datacenters if row["id"] == candidate["datacenter_id"]), None)
        templates = self.request("GET", "template")
        template = next((row for row in templates if row["id"] == candidate["template_id"]), None)
        if (not plan or not plan.get("active") or not plan.get("enable") or plan.get("has_params")
                or plan.get("period") != "day" or not dc or not dc.get("active")
                or dc.get("country", "").lower() != candidate["country"]
                or not template or not template.get("active") or not template.get("ssh-key")
                or candidate["plan_id"] not in template.get("server-plan", [])):
            raise ProviderError("provider_offer_unavailable")
        for resource, limit in template.get("limits", {}).items():
            minimum = Decimal(str(limit.get("min", 0)))
            capacity = Decimal(str(plan.get("data", {}).get(resource, {}).get("value", 0)))
            if capacity < minimum:
                raise ProviderError("provider_template_requirements")
        price = Decimal(str(plan["cost"]))
        if price != REQUIRED_DAILY_COST or Decimal(str(candidate['daily_cost'])) != REQUIRED_DAILY_COST:
            raise ProviderValidationError('provider_tariff_price_mismatch')
        if candidate.get("max_existing") is not None:
            count = 0
            for row in self.servers():
                if row["id"] == retiring_service_id:
                    continue
                details = row.get("server-plan")
                if not isinstance(details, dict):
                    details = self.server(row["id"]).get("server-plan")
                if not isinstance(details, dict) or type(details.get("id")) is not int:
                    raise ProviderError("provider_inventory_incomplete")
                count += details["id"] == candidate["plan_id"]
            if count >= candidate["max_existing"]:
                raise ProviderValidationError("provider_tariff_limit")
        minimum = max(price, Decimal(str(plan.get("min_money", 0))))
        balance = Decimal(str(self.request("GET", "account.balance").get("real", 0)))
        if not price.is_finite() or price <= 0 or balance < minimum:
            raise ProviderError("provider_balance_insufficient")
        return price

    def order(self, name, candidate):
        # Every order path checks the live native price immediately before POST.
        try:
            self.quote(candidate)
        except ProviderError as error:
            raise ProviderValidationError('order_preflight:'+str(error)) from None
        result = self.request("POST", "server", {
            "name": name, "datacenter": candidate["datacenter_id"], "server-plan": candidate["plan_id"],
            "template": candidate["template_id"], "ssh-key": candidate["ssh_key_id"],
        })
        if type(result.get("id")) is not int or result["id"] <= 0:
            raise ProviderError("provider_order_response_invalid")
        return result["id"]

    def reconcile(self, name):
        matches = [row for row in self.servers() if row.get("name") == name]
        if len(matches) > 1:
            raise ProviderError("provider_order_ambiguous")
        return matches[0]["id"] if matches else None

    def server(self, server_id):
        row = self.request("GET", "server/" + str(server_id))
        if row.get("id") != server_id:
            raise ProviderError("provider_identity_mismatch")
        return row

    def server_or_none(self, server_id):
        try:
            return self.server(server_id)
        except ProviderError as error:
            if str(error) == "provider_http_404":
                return None
            raise

    def delete(self, server_id):
        if type(server_id) is not int or server_id <= 0:
            raise ValueError("Invalid server ID")
        return self.request("DELETE", "server/" + str(server_id))

    @staticmethod
    def address(server):
        values = server.get("ip", [])
        if isinstance(values, dict):
            values = [values]
        candidates = [entry.get("ip") for entry in values if entry.get("type", "4") == "4"]
        if len(candidates) != 1:
            raise ProviderError("provider_address_ambiguous")
        address = ipaddress.ip_address(candidates[0])
        if address.version != 4 or not address.is_global:
            raise ProviderError("provider_address_invalid")
        return str(address)
