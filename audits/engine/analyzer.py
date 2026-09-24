from collections import Counter, defaultdict
from typing import Any

from .parser import ConfigEntry, RouterOSParser
from .ml_risk import KNearestNeighborsRiskClassifier
from .rules import RouterOSRuleEngine, is_enabled

SCORING_VERSION = "2.0"

SEVERITY_BASE_PENALTIES = {
    "critical": 20,
    "high": 12,
    "medium": 6,
    "low": 2,
    "information": 0,
}

CATEGORY_WEIGHTS = {
    "Firewall": 1.25,
    "NAT": 1.20,
    "Security services": 1.20,
    "Services": 1.15,
    "Layer 2 management": 1.15,
    "Routes": 1.05,
    "DHCP": 1.00,
    "IP addressing": 1.00,
    "Interfaces": 0.90,
}

CATEGORY_DISPLAY_ORDER = (
    "Interfaces",
    "IP addressing",
    "DHCP",
    "Services",
    "Security services",
    "Layer 2 management",
    "Firewall",
    "NAT",
    "Routes",
)

REPEATED_FINDING_FACTORS = (
    1.00,
    0.65,
    0.35,
)

INTERFACE_DEFINITION_SECTIONS = {
    "/interface ethernet",
    "/interface bridge",
    "/interface bonding",
    "/interface vlan",
    "/interface wireless",
    "/interface wifi",
    "/interface wireguard",
    "/interface lte",
    "/interface eoip",
    "/interface gre",
    "/interface ipip",
    "/interface vrrp",
    "/interface vxlan",
    "/interface ovpn-client",
    "/interface pppoe-client",
}


class InventoryBuilder:
    """Builds serializable RouterOS interface inventory and configuration summary."""

    @staticmethod
    def _entry_name(entry: ConfigEntry) -> str:
        """Return the most reliable object name from a RouterOS entry."""
        name = entry.properties.get("name")
        if name not in {None, ""}:
            return str(name)

        default_name = entry.properties.get("default-name")
        if default_name not in {None, ""}:
            return str(default_name)

        positional = entry.properties.get("_positional", [])

        for value in positional:
            value = str(value)
            if value not in {"[", "]", "find"} and "=" not in value:
                return value

        return ""

    def build_interface_inventory(
        self,
        entries: list[ConfigEntry],
    ) -> dict[str, list[dict[str, Any]]]:
        return build_interface_inventory(entries)

    def build_configuration_summary(
        self,
        entries: list[ConfigEntry],
    ) -> dict[str, Any]:
        return build_configuration_summary(entries)


def _entry_name(entry: ConfigEntry) -> str:
    """Return the most reliable object name from a RouterOS entry."""

    name = entry.properties.get("name")
    if name not in {None, ""}:
        return str(name)

    default_name = entry.properties.get("default-name")
    if default_name not in {None, ""}:
        return str(default_name)

    positional = entry.properties.get("_positional", [])

    for value in positional:
        value = str(value)

        if value not in {"[", "]", "find"} and "=" not in value:
            return value

    return ""


def build_interface_inventory(
    entries: list[ConfigEntry],
) -> dict[str, list[dict[str, Any]]]:
    """Build an inventory of interfaces, lists, and list memberships."""

    interfaces_by_name: dict[str, dict[str, Any]] = {}
    interface_lists_by_name: dict[str, dict[str, Any]] = {}
    interface_list_members: list[dict[str, Any]] = []

    for entry in entries:
        if entry.command not in {"add", "set"}:
            continue

        if entry.section in INTERFACE_DEFINITION_SECTIONS:
            name = _entry_name(entry)

            if not name:
                continue

            interfaces_by_name[name] = {
                "name": name,
                "type": entry.section.removeprefix("/interface "),
                "disabled": not is_enabled(entry),
                "parent": str(entry.properties.get("interface") or ""),
                "vlan_id": entry.properties.get("vlan-id"),
                "line_number": entry.line_number,
            }

        elif entry.section == "/interface list":
            name = _entry_name(entry)

            if not name:
                continue

            interface_lists_by_name[name] = {
                "name": name,
                "disabled": not is_enabled(entry),
                "line_number": entry.line_number,
            }

        elif entry.section == "/interface list member":
            interface_name = str(entry.properties.get("interface") or "")
            list_name = str(entry.properties.get("list") or "")

            if not interface_name and not list_name:
                continue

            interface_list_members.append(
                {
                    "interface": interface_name,
                    "list": list_name,
                    "disabled": not is_enabled(entry),
                    "line_number": entry.line_number,
                }
            )

    return {
        "interfaces": sorted(
            interfaces_by_name.values(),
            key=lambda item: (item["type"], item["name"]),
        ),
        "interface_lists": sorted(
            interface_lists_by_name.values(),
            key=lambda item: item["name"],
        ),
        "interface_list_members": sorted(
            interface_list_members,
            key=lambda item: (item["list"], item["interface"]),
        ),
    }


def build_configuration_summary(
    entries: list[ConfigEntry],
) -> dict[str, Any]:
    """Create a serializable summary of the parsed configuration."""

    section_counts = Counter(entry.section for entry in entries)
    inventory = build_interface_inventory(entries)

    router_identity = ""

    for entry in entries:
        if entry.section != "/system identity":
            continue

        name = entry.properties.get("name")

        if name not in {None, ""}:
            router_identity = str(name)

    enabled_services = [
        entry
        for entry in entries
        if entry.section == "/ip service" and is_enabled(entry)
    ]

    ip_addresses = []

    for entry in entries:
        if entry.section != "/ip address" or not is_enabled(entry):
            continue

        ip_addresses.append(
            {
                "address": str(entry.properties.get("address") or ""),
                "interface": str(entry.properties.get("interface") or ""),
                "disabled": not is_enabled(entry),
                "line_number": entry.line_number,
            }
        )

    dhcp_pools = []

    for entry in entries:
        if entry.section != "/ip pool" or not is_enabled(entry):
            continue

        dhcp_pools.append(
            {
                "name": _entry_name(entry),
                "ranges": str(entry.properties.get("ranges") or ""),
                "disabled": not is_enabled(entry),
                "line_number": entry.line_number,
            }
        )

    dhcp_servers = []

    for entry in entries:
        if entry.section != "/ip dhcp-server" or not is_enabled(entry):
            continue

        dhcp_servers.append(
            {
                "name": _entry_name(entry),
                "interface": str(entry.properties.get("interface") or ""),
                "address_pool": str(entry.properties.get("address-pool") or ""),
                "disabled": not is_enabled(entry),
                "line_number": entry.line_number,
            }
        )

    firewall_rules = []

    for entry in entries:
        if (
            entry.section != "/ip firewall filter"
            or entry.command != "add"
            or not is_enabled(entry)
        ):
            continue

        firewall_rules.append(
            {
                "chain": str(entry.properties.get("chain") or ""),
                "action": str(entry.properties.get("action") or ""),
                "in_interface": str(entry.properties.get("in-interface") or ""),
                "in_interface_list": str(
                    entry.properties.get("in-interface-list") or ""
                ),
                "protocol": str(entry.properties.get("protocol") or ""),
                "dst_port": str(entry.properties.get("dst-port") or ""),
                "line_number": entry.line_number,
            }
        )

    nat_rules = []

    for entry in entries:
        if (
            entry.section != "/ip firewall nat"
            or entry.command != "add"
            or not is_enabled(entry)
        ):
            continue

        nat_rules.append(
            {
                "chain": str(entry.properties.get("chain") or ""),
                "action": str(entry.properties.get("action") or ""),
                "out_interface": str(entry.properties.get("out-interface") or ""),
                "out_interface_list": str(
                    entry.properties.get("out-interface-list") or ""
                ),
                "dst_port": str(entry.properties.get("dst-port") or ""),
                "to_addresses": str(entry.properties.get("to-addresses") or ""),
                "line_number": entry.line_number,
            }
        )

    routes = []

    for entry in entries:
        if (
            entry.section != "/ip route"
            or entry.command not in {"add", "set"}
            or not is_enabled(entry)
        ):
            continue

        routes.append(
            {
                "destination": str(
                    entry.properties.get("dst-address") or "0.0.0.0/0"
                ),
                "gateway": str(entry.properties.get("gateway") or ""),
                "distance": str(entry.properties.get("distance") or "1"),
                "type": str(entry.properties.get("type") or "unicast"),
                "line_number": entry.line_number,
            }
        )

    services = []

    for entry in enabled_services:
        services.append(
            {
                "name": _entry_name(entry),
                "address": str(entry.properties.get("address") or "0.0.0.0/0"),
                "disabled": not is_enabled(entry),
                "line_number": entry.line_number,
            }
        )

    summary = {
        "router_identity": router_identity or "Not specified",
        "total_commands": len(entries),
        "interface_count": len(inventory["interfaces"]),
        "interface_list_count": len(inventory["interface_lists"]),
        "interface_list_member_count": len(
            inventory["interface_list_members"]
        ),
        "ip_address_count": sum(
            1
            for entry in entries
            if entry.section == "/ip address" and is_enabled(entry)
        ),
        "ip_pool_count": sum(
            1
            for entry in entries
            if entry.section == "/ip pool" and is_enabled(entry)
        ),
        "dhcp_server_count": sum(
            1
            for entry in entries
            if entry.section == "/ip dhcp-server" and is_enabled(entry)
        ),
        "dhcp_network_count": section_counts.get(
            "/ip dhcp-server network",
            0,
        ),
        "firewall_filter_count": sum(
            1
            for entry in entries
            if entry.section == "/ip firewall filter"
            and entry.command == "add"
            and is_enabled(entry)
        ),
        "nat_rule_count": sum(
            1
            for entry in entries
            if entry.section == "/ip firewall nat"
            and entry.command == "add"
            and is_enabled(entry)
        ),
        "route_count": sum(
            1
            for entry in entries
            if entry.section == "/ip route"
            and entry.command in {"add", "set"}
            and is_enabled(entry)
        ),
        "enabled_service_count": len(enabled_services),
        "section_counts": dict(sorted(section_counts.items())),
        "ip_addresses": ip_addresses,
        "dhcp_pools": dhcp_pools,
        "dhcp_servers": dhcp_servers,
        "firewall_rules": firewall_rules,
        "nat_rules": nat_rules,
        "routes": routes,
        "services": services,
        **inventory,
    }

    return summary


class ScoreCalculator:
    """Calculates category scores and the final explainable audit score."""

    @staticmethod
    def _determine_applicable_categories(
        configuration_summary: dict[str, Any],
        findings,
    ) -> list[str]:
        return _determine_applicable_categories(configuration_summary, findings)

    @staticmethod
    def _rating_from_score(score: int) -> str:
        return _rating_from_score(score)

    def calculate_score(
        self,
        findings,
        configuration_summary: dict[str, Any],
    ):
        return calculate_score(findings, configuration_summary)


def _determine_applicable_categories(
    configuration_summary: dict[str, Any],
    findings,
) -> list[str]:
    """Determine which scoring categories apply to the configuration."""

    applicable = {
        finding.category
        for finding in findings
        if finding.category
    }

    section_counts = configuration_summary.get(
        "section_counts",
        {},
    )

    if (
        configuration_summary.get("interface_count", 0)
        or configuration_summary.get(
            "interface_list_count",
            0,
        )
    ):
        applicable.add("Interfaces")

    if configuration_summary.get(
        "ip_address_count",
        0,
    ):
        applicable.add("IP addressing")

    if (
        configuration_summary.get("ip_pool_count", 0)
        or configuration_summary.get(
            "dhcp_server_count",
            0,
        )
        or configuration_summary.get(
            "dhcp_network_count",
            0,
        )
    ):
        applicable.add("DHCP")

    if section_counts.get("/ip service", 0):
        applicable.add("Services")

    if configuration_summary.get(
        "firewall_filter_count",
        0,
    ):
        applicable.add("Firewall")

    if configuration_summary.get(
        "nat_rule_count",
        0,
    ):
        applicable.add("NAT")

    if configuration_summary.get(
        "route_count",
        0,
    ):
        applicable.add("Routes")

    security_service_sections = {
        "/ip dns",
        "/tool bandwidth-server",
        "/ip proxy",
        "/ip proxy access",
        "/ip socks",
        "/ip socks access",
        "/snmp",
        "/snmp community",
    }

    if any(
        section_counts.get(section, 0)
        for section in security_service_sections
    ):
        applicable.add("Security services")

    layer_two_sections = {
        "/tool mac-server",
        "/tool mac-server mac-winbox",
        "/tool mac-server ping",
        "/ip neighbor discovery-settings",
        "/tool romon",
        "/tool romon port",
    }

    if any(
        section_counts.get(section, 0)
        for section in layer_two_sections
    ):
        applicable.add("Layer 2 management")

    ordered = [
        category
        for category in CATEGORY_DISPLAY_ORDER
        if category in applicable
    ]

    additional = sorted(
        applicable - set(CATEGORY_DISPLAY_ORDER)
    )

    return ordered + additional


def _rating_from_score(score: int) -> str:
    if score >= 90:
        return "Excellent"

    if score >= 75:
        return "Good"

    if score >= 60:
        return "Needs improvement"

    if score >= 40:
        return "Poor"

    return "Critical"


def calculate_score(
    findings,
    configuration_summary: dict[str, Any],
):
    """Calculate category scores and the final explainable audit score."""

    applicable_categories = (
        _determine_applicable_categories(
            configuration_summary,
            findings,
        )
    )

    category_penalties = defaultdict(float)
    severity_counts = Counter()
    rule_occurrences = defaultdict(int)

    finding_penalties = []

    for finding in findings:
        severity = str(
            finding.severity
        ).strip().lower()

        category = (
            str(finding.category).strip()
            or "Other"
        )

        rule_id = (
            str(finding.rule_id).strip()
            or "UNKNOWN"
        )

        base_penalty = SEVERITY_BASE_PENALTIES.get(
            severity,
            0,
        )

        category_weight = CATEGORY_WEIGHTS.get(
            category,
            1.00,
        )

        occurrence_index = rule_occurrences[
            rule_id
        ]

        if occurrence_index == 0:
            repeat_factor = (
                REPEATED_FINDING_FACTORS[0]
            )
        elif occurrence_index == 1:
            repeat_factor = (
                REPEATED_FINDING_FACTORS[1]
            )
        else:
            repeat_factor = (
                REPEATED_FINDING_FACTORS[2]
            )

        weighted_penalty = round(
            base_penalty
            * category_weight
            * repeat_factor,
            2,
        )

        category_penalties[
            category
        ] += weighted_penalty

        severity_counts[severity] += 1
        rule_occurrences[rule_id] += 1

        finding_penalties.append(
            {
                "rule_id": rule_id,
                "category": category,
                "severity": severity,
                "base_penalty": base_penalty,
                "category_weight": category_weight,
                "repeat_factor": repeat_factor,
                "weighted_penalty": weighted_penalty,
            }
        )

    category_scores = {}

    for category in applicable_categories:
        penalty = category_penalties.get(
            category,
            0,
        )

        category_score = max(
            0,
            round(
                100 - min(100, penalty * 2)
            ),
        )

        category_scores[category] = (
            category_score
        )

    if category_scores:
        total_weight = sum(
            CATEGORY_WEIGHTS.get(
                category,
                1.00,
            )
            for category in category_scores
        )

        weighted_score_total = sum(
            score
            * CATEGORY_WEIGHTS.get(
                category,
                1.00,
            )
            for category, score
            in category_scores.items()
        )

        raw_score = round(
            weighted_score_total
            / total_weight
        )
    else:
        raw_score = 100

    critical_count = severity_counts.get(
        "critical",
        0,
    )

    high_count = severity_counts.get(
        "high",
        0,
    )

    if critical_count >= 3:
        risk_ceiling = 39
        ceiling_reason = (
            "Three or more critical findings"
        )
    elif critical_count >= 1:
        risk_ceiling = 59
        ceiling_reason = (
            "At least one critical finding"
        )
    elif high_count >= 5:
        risk_ceiling = 74
        ceiling_reason = (
            "Five or more high-severity findings"
        )
    else:
        risk_ceiling = 100
        ceiling_reason = (
            "No risk ceiling was required"
        )

    final_score = max(
        0,
        min(raw_score, risk_ceiling),
    )

    rating = _rating_from_score(
        final_score
    )

    ml_risk_insight = KNearestNeighborsRiskClassifier().classify(
        score=final_score,
        counts=dict(severity_counts),
        category_scores=category_scores,
        finding_count=len(findings),
    )

    score_details = {
        "version": SCORING_VERSION,
        "raw_score": raw_score,
        "final_score": final_score,
        "rating": rating,
        "risk_ceiling": risk_ceiling,
        "ceiling_reason": ceiling_reason,
        "applicable_categories": (
            applicable_categories
        ),
        "category_penalties": {
            category: round(penalty, 2)
            for category, penalty
            in category_penalties.items()
        },
        "category_scores": category_scores,
        "severity_counts": dict(
            severity_counts
        ),
        "finding_count": len(findings),
        "triggered_rule_count": len(
            rule_occurrences
        ),
        "repeat_adjustment": (
            "First occurrence 100%, second 65%, "
            "later occurrences 35%"
        ),
        "finding_penalties": finding_penalties,
        "ml_risk_insight": ml_risk_insight,
    }

    return (
        final_score,
        rating,
        category_scores,
        score_details,
    )


class ConfigurationSummarizer:
    """Builds serializable RouterOS inventory data from parsed entries."""

    def build(self, entries: list[ConfigEntry]) -> dict[str, Any]:
        return InventoryBuilder().build_configuration_summary(entries)


class RuleEngine:
    """Runs the registered audit rules against parsed RouterOS entries."""

    def run(
        self,
        entries: list[ConfigEntry],
        configuration_summary: dict[str, Any],
    ):
        return RouterOSRuleEngine().evaluate(
            entries=entries,
            configuration_summary=configuration_summary,
        )


class RiskScorer:
    """Calculates the final risk score and score explanation."""

    def calculate(
        self,
        findings,
        configuration_summary: dict[str, Any],
    ):
        return ScoreCalculator().calculate_score(
            findings,
            configuration_summary,
        )


class RouterOSAuditAnalyzer:
    """Object-oriented audit pipeline for RouterOS export analysis."""

    def __init__(
        self,
        parser: RouterOSParser | None = None,
        summarizer: ConfigurationSummarizer | None = None,
        rule_engine: RuleEngine | None = None,
        scorer: RiskScorer | None = None,
    ):
        self.parser = parser or RouterOSParser()
        self.summarizer = summarizer or ConfigurationSummarizer()
        self.rule_engine = rule_engine or RuleEngine()
        self.scorer = scorer or RiskScorer()

    def analyze(self, text: str) -> dict[str, Any]:
        entries = self.parser.parse(text)
        configuration_summary = self.summarizer.build(entries)
        findings = self.rule_engine.run(
            entries,
            configuration_summary,
        )
        (
            score,
            rating,
            category_scores,
            score_details,
        ) = self.scorer.calculate(
            findings,
            configuration_summary,
        )

        counts = Counter(
            finding.severity
            for finding in findings
        )

        return {
            "entries": [
                entry.to_dict()
                for entry in entries
            ],
            "configuration_summary": configuration_summary,
            "category_scores": category_scores,
            "score_details": score_details,
            "findings": [
                finding.to_dict()
                for finding in findings
            ],
            "score": score,
            "rating": rating,
            "counts": dict(counts),
        }


def analyze_config(text: str):
    """Compatibility wrapper around the OOP audit analyzer."""

    return RouterOSAuditAnalyzer().analyze(text)








# Maintenance review completed.

# Code review pass - 08/03/2026 23:05:21

# [rev-3051] Reviewed 10 Jul 2026

# [rev-4868] Reviewed 24 Aug 2026

# [rev-5929] Reviewed 29 Aug 2026
