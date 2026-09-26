from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True, slots=True)
class RuleDefinition:
    rule_id: str
    title: str
    category: str
    default_severity: str
    description: str
    reference: str
    version: str = "1.0"


CATEGORY_ORDER = (
    "Interfaces",
    "IP addressing",
    "DHCP",
    "Services",
    "Layer 2 management",
    "Security services",
    "Firewall",
    "NAT",
    "Routes",
)

SEVERITY_ORDER = (
    "critical",
    "high",
    "medium",
    "low",
    "information",
)


def _build_rules(
    category: str,
    reference: str,
    items: tuple[tuple[str, str, str, str], ...],
) -> tuple[RuleDefinition, ...]:
    return tuple(
        RuleDefinition(
            rule_id=rule_id,
            title=title,
            category=category,
            default_severity=severity,
            description=description,
            reference=reference,
        )
        for rule_id, title, severity, description in items
    )


RULE_DEFINITIONS = (
    *_build_rules(
        category="Interfaces",
        reference="MikroTik RouterOS Interfaces and Interface Lists",
        items=(
            (
                "IF-001",
                "Undefined parent interface",
                "high",
                "Detects interface objects that reference a parent interface not present in the export.",
            ),
            (
                "IF-002",
                "Undefined interface-list member",
                "high",
                "Detects interface-list members that reference an undefined interface.",
            ),
            (
                "IF-003",
                "Undefined interface list",
                "high",
                "Detects memberships that reference an interface list not present in the export.",
            ),
            (
                "IF-004",
                "Undefined bridge-port interface",
                "high",
                "Detects bridge ports that reference an undefined interface.",
            ),
            (
                "IF-005",
                "Undefined bridge",
                "high",
                "Detects bridge ports that reference an undefined bridge.",
            ),
        ),
    ),
    *_build_rules(
        category="IP addressing",
        reference="MikroTik RouterOS IP Addressing",
        items=(
            (
                "IP-001",
                "Duplicate IP address assignment",
                "high",
                "Detects the same host address assigned more than once.",
            ),
            (
                "IP-002",
                "Overlapping interface networks",
                "medium",
                "Detects overlapping IPv4 or IPv6 networks that may create ambiguous routing.",
            ),
            (
                "IP-003",
                "Invalid IP address or prefix",
                "high",
                "Detects invalid, missing, or malformed IP address entries.",
            ),
            (
                "IP-004",
                "Undefined IP-address interface",
                "high",
                "Detects IP addresses assigned to interfaces not present in the configuration inventory.",
            ),
            (
                "IP-005",
                "Same subnet on multiple interfaces",
                "high",
                "Detects the same routed subnet assigned to different interfaces.",
            ),
            (
                "IP-006",
                "Missing interface assignment",
                "high",
                "Detects enabled IP addresses that are not attached to an interface.",
            ),
            (
                "IP-007",
                "Network address used as host",
                "high",
                "Detects an IPv4 network identifier assigned as a router host address.",
            ),
            (
                "IP-008",
                "Broadcast address used as host",
                "high",
                "Detects an IPv4 broadcast address assigned as a router host address.",
            ),
        ),
    ),
    *_build_rules(
        category="DHCP",
        reference="MikroTik RouterOS DHCP Server",
        items=(
            (
                "DHCP-001",
                "Invalid DHCP pool definition",
                "high",
                "Detects missing, malformed, empty, or reversed DHCP address ranges.",
            ),
            (
                "DHCP-002",
                "Overlapping DHCP pools",
                "high",
                "Detects multiple pools that can allocate the same client address.",
            ),
            (
                "DHCP-003",
                "Missing DHCP pool reference",
                "high",
                "Detects DHCP servers that reference a pool not present in the export.",
            ),
            (
                "DHCP-004",
                "DHCP network has no gateway",
                "medium",
                "Detects DHCP network entries that do not distribute a default gateway.",
            ),
            (
                "DHCP-005",
                "Undefined DHCP interface",
                "high",
                "Detects DHCP servers attached to interfaces not present in the configuration inventory.",
            ),
            (
                "DHCP-006",
                "Invalid DHCP network address",
                "high",
                "Detects missing or malformed DHCP network prefixes.",
            ),
            (
                "DHCP-007",
                "Duplicate DHCP network entry",
                "medium",
                "Detects the same DHCP subnet configured more than once.",
            ),
            (
                "DHCP-008",
                "Pool outside interface subnet",
                "high",
                "Detects DHCP address ranges that do not fit inside the server interface network.",
            ),
            (
                "DHCP-009",
                "Pool includes router address",
                "critical",
                "Detects pools that can allocate an address already assigned to the router.",
            ),
            (
                "DHCP-010",
                "Pool includes reserved subnet address",
                "high",
                "Detects network or broadcast addresses included in an IPv4 client pool.",
            ),
            (
                "DHCP-011",
                "Gateway inside client pool",
                "critical",
                "Detects a DHCP gateway address that can be allocated to a client.",
            ),
            (
                "DHCP-012",
                "Missing matching DHCP network",
                "high",
                "Detects DHCP servers without a network entry matching the interface subnet.",
            ),
            (
                "DHCP-013",
                "Invalid DHCP gateway",
                "high",
                "Detects malformed gateways or gateways outside the configured DHCP network.",
            ),
        ),
    ),
    *_build_rules(
        category="Services",
        reference="MikroTik RouterOS IP Services",
        items=(
            (
                "SRV-001",
                "Telnet service enabled",
                "high",
                "Detects the unencrypted Telnet management service.",
            ),
            (
                "SRV-002",
                "FTP service enabled",
                "medium",
                "Detects the unencrypted FTP management service.",
            ),
            (
                "SRV-003",
                "Unencrypted WebFig enabled",
                "medium",
                "Detects WebFig HTTP management without transport encryption.",
            ),
            (
                "SRV-004",
                "WinBox unrestricted",
                "high",
                "Detects WinBox management without trusted source-address restrictions.",
            ),
            (
                "SRV-005",
                "SSH unrestricted",
                "high",
                "Detects SSH management without trusted source-address restrictions.",
            ),
            (
                "SRV-006",
                "RouterOS API unrestricted",
                "high",
                "Detects the RouterOS API exposed without source restrictions.",
            ),
            (
                "SRV-007",
                "API-SSL without certificate",
                "high",
                "Detects API-SSL enabled without an assigned certificate.",
            ),
            (
                "SRV-008",
                "API-SSL unrestricted",
                "high",
                "Detects API-SSL exposed without trusted source restrictions.",
            ),
        ),
    ),
    *_build_rules(
        category="Layer 2 management",
        reference="MikroTik RouterOS MAC Server, Neighbor Discovery, and RoMON",
        items=(
            (
                "SEC-002",
                "Broad MAC Telnet access",
                "high",
                "Detects MAC Telnet enabled on broad or untrusted interface lists.",
            ),
            (
                "SEC-003",
                "Broad MAC WinBox access",
                "high",
                "Detects MAC WinBox enabled on broad or untrusted interface lists.",
            ),
            (
                "SEC-004",
                "MAC Ping server enabled",
                "low",
                "Detects the Layer-2 MAC Ping service when it is enabled.",
            ),
            (
                "SEC-005",
                "Broad neighbor discovery",
                "medium",
                "Detects neighbor discovery advertising router information on broad interface lists.",
            ),
            (
                "SEC-006",
                "Broad RoMON participation",
                "high",
                "Detects RoMON enabled without restrictive interface participation.",
            ),
        ),
    ),
    *_build_rules(
        category="Security services",
        reference="MikroTik RouterOS DNS, Proxy, SOCKS, SNMP, and Bandwidth Test",
        items=(
            (
                "SEC-001",
                "Remote DNS exposed",
                "critical",
                "Detects remote DNS requests exposed through an unrestricted WAN-facing firewall rule.",
            ),
            (
                "SEC-007",
                "Unauthenticated bandwidth server",
                "high",
                "Detects the bandwidth-test server accepting unauthenticated clients.",
            ),
            (
                "SEC-008",
                "Web proxy without deny policy",
                "high",
                "Detects an enabled web proxy without an evident restrictive access policy.",
            ),
            (
                "SEC-009",
                "SOCKS proxy without deny policy",
                "critical",
                "Detects an enabled SOCKS proxy without an evident restrictive access policy.",
            ),
            (
                "SEC-010",
                "Insecure SNMP community",
                "high",
                "Detects public, unrestricted, or unauthenticated SNMP communities.",
            ),
            (
                "SEC-011",
                "SNMP write access enabled",
                "critical",
                "Detects SNMP communities that can modify supported RouterOS objects.",
            ),
        ),
    ),
    *_build_rules(
        category="Firewall",
        reference="MikroTik RouterOS Firewall Filter",
        items=(
            (
                "FW-001",
                "Missing input default drop",
                "critical",
                "Detects an input chain without a broad final drop or reject rule.",
            ),
            (
                "FW-002",
                "Missing established and related accept",
                "medium",
                "Detects input chains without an explicit established and related accept rule.",
            ),
            (
                "FW-003",
                "Missing invalid-state drop",
                "medium",
                "Detects input chains without an explicit invalid-connection drop rule.",
            ),
            (
                "FW-004",
                "Broad input accept rule",
                "critical",
                "Detects unrestricted accept rules in the input chain.",
            ),
            (
                "FW-005",
                "Disabled security rule",
                "low",
                "Detects disabled rules that appear intended to block unwanted traffic.",
            ),
            (
                "FW-006",
                "Unreachable firewall rule",
                "medium",
                "Detects rules placed after an unrestricted terminal rule.",
            ),
            (
                "FW-007",
                "Undefined firewall interface",
                "high",
                "Detects firewall rules that reference undefined interfaces.",
            ),
            (
                "FW-008",
                "Undefined firewall interface list",
                "high",
                "Detects firewall rules that reference undefined interface lists.",
            ),
            (
                "FW-009",
                "Duplicate firewall rule",
                "medium",
                "Detects exact duplicate firewall filter rules.",
            ),
            (
                "FW-010",
                "Shadowed firewall rule",
                "high",
                "Detects later rules fully covered by earlier terminal rules.",
            ),
            (
                "FW-011",
                "Missing forward default drop",
                "high",
                "Detects an active forward chain without a broad final drop or reject rule.",
            ),
            (
                "FW-012",
                "Stateful accept placed too late",
                "medium",
                "Detects established and related accept rules placed after broad terminal rules.",
            ),
            (
                "FW-013",
                "Invalid drop placed too late",
                "medium",
                "Detects invalid-state drop rules placed after broad terminal rules.",
            ),
            (
                "FW-014",
                "FastTrack missing follow-up accept",
                "medium",
                "Detects FastTrack rules without a later stateful accept rule.",
            ),
            (
                "FW-015",
                "Invalid firewall matcher",
                "high",
                "Detects invalid address, port, or port-range expressions.",
            ),
            (
                "FW-016",
                "Management ports exposed",
                "critical",
                "Detects WAN-facing management ports accepted without trusted source restrictions.",
            ),
            (
                "FW-017",
                "Broad forward accept rule",
                "high",
                "Detects unrestricted accept rules in the forward chain.",
            ),
        ),
    ),
    *_build_rules(
        category="NAT",
        reference="MikroTik RouterOS NAT",
        items=(
            (
                "NAT-001",
                "Duplicate masquerade rule",
                "medium",
                "Detects duplicate source NAT masquerade rules.",
            ),
            (
                "NAT-002",
                "Broad destination NAT exposure",
                "critical",
                "Detects destination NAT rules without meaningful protocol, port, address, or ingress restrictions.",
            ),
            (
                "NAT-003",
                "Undefined NAT interface",
                "high",
                "Detects NAT rules that reference interfaces not present in the inventory.",
            ),
            (
                "NAT-004",
                "Undefined NAT interface list",
                "high",
                "Detects NAT rules that reference undefined interface lists.",
            ),
            (
                "NAT-005",
                "Invalid NAT chain or action",
                "high",
                "Detects enabled NAT rules with missing actions or invalid chains.",
            ),
            (
                "NAT-006",
                "Invalid translated address",
                "high",
                "Detects malformed or reversed to-addresses values.",
            ),
            (
                "NAT-007",
                "Invalid NAT port",
                "high",
                "Detects invalid destination or translated port expressions.",
            ),
            (
                "NAT-008",
                "Duplicate destination NAT",
                "medium",
                "Detects exact duplicate port-forwarding rules.",
            ),
            (
                "NAT-009",
                "Conflicting destination NAT",
                "high",
                "Detects identical matches translated to different targets.",
            ),
            (
                "NAT-010",
                "Sensitive port publicly forwarded",
                "critical",
                "Detects public forwarding of common management ports without trusted source restrictions.",
            ),
            (
                "NAT-011",
                "Destination NAT lacks firewall protection",
                "high",
                "Detects destination NAT rules without a matching forward-chain protection rule.",
            ),
            (
                "NAT-012",
                "Missing NAT translation target",
                "high",
                "Detects NAT actions that require to-addresses but do not define one.",
            ),
        ),
    ),
    *_build_rules(
        category="Routes",
        reference="MikroTik RouterOS IP Routing",
        items=(
            (
                "ROUTE-001",
                "Invalid route destination",
                "high",
                "Detects malformed or unsupported static route destination prefixes.",
            ),
            (
                "ROUTE-002",
                "Static route has no gateway",
                "high",
                "Detects enabled unicast routes without a next hop.",
            ),
            (
                "ROUTE-003",
                "Invalid or undefined gateway",
                "high",
                "Detects malformed gateways or gateway interfaces not present in the inventory.",
            ),
            (
                "ROUTE-004",
                "Unresolvable route gateway",
                "high",
                "Detects gateways with no connected or recursive path.",
            ),
            (
                "ROUTE-005",
                "Duplicate static route",
                "medium",
                "Detects exact duplicate static routes.",
            ),
            (
                "ROUTE-006",
                "Gateway uses router address",
                "critical",
                "Detects a route using one of the router's own addresses as the next hop.",
            ),
            (
                "ROUTE-007",
                "Gateway uses reserved subnet address",
                "high",
                "Detects gateways using an IPv4 network or broadcast address.",
            ),
            (
                "ROUTE-008",
                "Unsafe interface-only gateway",
                "medium",
                "Detects remote routes using only a broadcast interface as the gateway.",
            ),
            (
                "ROUTE-009",
                "Gateway check without gateway address",
                "medium",
                "Detects check-gateway used with an interface-only next hop.",
            ),
            (
                "ROUTE-010",
                "Conflicting unicast and discard routes",
                "high",
                "Detects forwarding and discard routes with the same destination and distance.",
            ),
            (
                "ROUTE-011",
                "Invalid route distance",
                "medium",
                "Detects route distance values outside the supported numeric range.",
            ),
        ),
    ),
)


RULES_BY_ID = {
    rule.rule_id: rule
    for rule in RULE_DEFINITIONS
}


class RuleRegistry:
    """Registry of all known RouterOS audit rules with query helpers."""

    def __init__(self):
        self._rules = RULE_DEFINITIONS
        self._by_id = RULES_BY_ID

    def get_rule(self, rule_id: str) -> RuleDefinition | None:
        return self._by_id.get(rule_id)

    def get_statistics(self) -> dict[str, object]:
        category_counts: dict[str, int] = {}
        severity_counts: dict[str, int] = {}

        for rule in self._rules:
            category_counts[rule.category] = (
                category_counts.get(rule.category, 0) + 1
            )
            severity_counts[rule.default_severity] = (
                severity_counts.get(rule.default_severity, 0) + 1
            )

        return {
            "total": len(self._rules),
            "category_count": len(category_counts),
            "category_counts": category_counts,
            "severity_counts": severity_counts,
        }

    def filter_rules(
        self,
        query: str = "",
        category: str = "",
        severity: str = "",
    ) -> list[RuleDefinition]:
        normalized_query = query.strip().lower()
        normalized_category = category.strip()
        normalized_severity = severity.strip().lower()

        results = []

        for rule in self._rules:
            if normalized_category and rule.category != normalized_category:
                continue

            if normalized_severity and rule.default_severity != normalized_severity:
                continue

            searchable_text = " ".join(
                (
                    rule.rule_id,
                    rule.title,
                    rule.category,
                    rule.description,
                    rule.reference,
                )
            ).lower()

            if normalized_query and normalized_query not in searchable_text:
                continue

            results.append(rule)

        return results

    def group_rules(
        self,
        rules: Iterable[RuleDefinition],
    ) -> dict[str, list[RuleDefinition]]:
        grouped: dict[str, list[RuleDefinition]] = {}
        materialized_rules = list(rules)

        for category in CATEGORY_ORDER:
            category_rules = [
                rule for rule in materialized_rules if rule.category == category
            ]
            if category_rules:
                grouped[category] = category_rules

        remaining_categories = sorted(
            {rule.category for rule in materialized_rules} - set(CATEGORY_ORDER)
        )

        for category in remaining_categories:
            grouped[category] = [
                rule for rule in materialized_rules if rule.category == category
            ]

        return grouped


# singleton + backward-compat wrappers
_registry = RuleRegistry()


def get_rule(rule_id: str) -> RuleDefinition | None:
    return _registry.get_rule(rule_id)


def get_rule_statistics() -> dict[str, object]:
    return _registry.get_statistics()


def filter_rules(
    query: str = "",
    category: str = "",
    severity: str = "",
) -> list[RuleDefinition]:
    return _registry.filter_rules(query, category, severity)


def group_rules(rules: Iterable[RuleDefinition]) -> dict[str, list[RuleDefinition]]:
    return _registry.group_rules(rules)
