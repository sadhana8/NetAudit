from __future__ import annotations

from dataclasses import dataclass, asdict
from ipaddress import ip_address, ip_interface, ip_network, summarize_address_range
from typing import Any, Iterable

from .parser import ConfigEntry


@dataclass
class FindingResult:
    rule_id: str
    title: str
    category: str
    severity: str
    description: str
    evidence: str
    recommendation: str
    suggested_command: str = ""
    line_number: int | None = None

    def to_dict(self):
        return asdict(self)


def prop(entry: ConfigEntry, key: str, default=None):
    return entry.properties.get(key, default)


def positional(entry: ConfigEntry, index=0, default=""):
    values = entry.properties.get("_positional", [])
    return values[index] if len(values) > index else default


def is_enabled(entry: ConfigEntry) -> bool:
    return prop(entry, "disabled", False) is not True


def entries_for(entries: Iterable[ConfigEntry], section: str):
    return [entry for entry in entries if entry.section == section]


def service_rules(entries: list[ConfigEntry]) -> list[FindingResult]:
    findings: list[FindingResult] = []
    services = entries_for(entries, "/ip service")
    for entry in services:
        name = positional(entry) or str(prop(entry, "name", ""))
        if not name or not is_enabled(entry):
            continue
        address_value = prop(entry, "address", "")
        unrestricted = address_value in {"", None, "0.0.0.0/0", "::/0", "0.0.0.0/0,::/0"}

        definitions = {
            "telnet": ("SRV-001", "Telnet service is enabled", "high", "Telnet transmits administrative traffic without encryption.", "/ip service set telnet disabled=yes"),
            "ftp": ("SRV-002", "FTP service is enabled", "medium", "FTP exposes an unnecessary clear-text service on the router.", "/ip service set ftp disabled=yes"),
            "www": ("SRV-003", "Unencrypted WebFig is enabled", "medium", "The HTTP management service does not protect credentials in transit.", "/ip service set www disabled=yes"),
        }
        if name in definitions:
            rule_id, title, severity, description, command = definitions[name]
            findings.append(FindingResult(
                rule_id, title, "Services", severity, description, entry.raw,
                f"Disable {name} unless it is specifically required. Prefer encrypted administration.",
                command, entry.line_number,
            ))

        if name in {"winbox", "ssh", "api", "api-ssl"} and unrestricted:
            severity = "high" if name in {"winbox", "api"} else "medium"
            rule_id = {"winbox": "SRV-004", "ssh": "SRV-005", "api": "SRV-006", "api-ssl": "SRV-008"}[name]
            findings.append(FindingResult(
                rule_id,
                f"{name.upper()} management access is unrestricted",
                "Services",
                severity,
                f"The {name} service accepts connections without a trusted source-address restriction.",
                entry.raw,
                "Restrict management access to the administrator subnet and reinforce it with firewall input rules.",
                f"/ip service set {name} address=192.168.88.0/24",
                entry.line_number,
            ))

        if name == "api-ssl" and prop(entry, "certificate") in {None, "", "none"}:
            findings.append(FindingResult(
                "SRV-007", "API-SSL has no certificate", "Services", "high",
                "The encrypted API service is enabled without an assigned certificate.",
                entry.raw,
                "Assign a valid certificate or disable API-SSL when it is not required.",
                "/ip service set api-ssl disabled=yes",
                entry.line_number,
            ))
    return findings


def ip_rules(entries: list[ConfigEntry]) -> list[FindingResult]:
    findings: list[FindingResult] = []

    parsed = []
    seen_host_addresses: dict[str, ConfigEntry] = {}

    for entry in entries_for(entries, "/ip address"):
        if not is_enabled(entry):
            continue

        value = prop(entry, "address")
        interface_name = str(
            prop(entry, "interface", "")
        ).strip()

        if not value:
            findings.append(
                FindingResult(
                    rule_id="IP-003",
                    title="IP address value is missing",
                    category="IP addressing",
                    severity="high",
                    description=(
                        "An enabled IP-address entry does not contain "
                        "an address and prefix."
                    ),
                    evidence=entry.raw,
                    recommendation=(
                        "Add a valid IP address with a CIDR prefix or "
                        "remove the incomplete configuration entry."
                    ),
                    line_number=entry.line_number,
                )
            )
            continue

        if not interface_name:
            findings.append(
                FindingResult(
                    rule_id="IP-006",
                    title="IP address has no interface assignment",
                    category="IP addressing",
                    severity="high",
                    description=(
                        "The address is not attached to a RouterOS "
                        "interface."
                    ),
                    evidence=entry.raw,
                    recommendation=(
                        "Assign the address to the correct interface "
                        "before deploying the configuration."
                    ),
                    line_number=entry.line_number,
                )
            )

        try:
            parsed_interface = ip_interface(str(value))
        except ValueError:
            findings.append(
                FindingResult(
                    rule_id="IP-003",
                    title="Invalid IP address or prefix",
                    category="IP addressing",
                    severity="high",
                    description=(
                        "The address cannot be interpreted as a valid "
                        "IPv4 or IPv6 interface."
                    ),
                    evidence=entry.raw,
                    recommendation=(
                        "Correct the address and CIDR prefix before "
                        "applying the configuration."
                    ),
                    line_number=entry.line_number,
                )
            )
            continue

        host_key = (
            f"{parsed_interface.version}:"
            f"{parsed_interface.ip.compressed}"
        )

        if host_key in seen_host_addresses:
            first_entry = seen_host_addresses[host_key]

            findings.append(
                FindingResult(
                    rule_id="IP-001",
                    title="Duplicate IP address assignment",
                    category="IP addressing",
                    severity="high",
                    description=(
                        "The same host address is assigned more than "
                        "once in the configuration."
                    ),
                    evidence=(
                        f"First: {first_entry.raw}\n"
                        f"Duplicate: {entry.raw}"
                    ),
                    recommendation=(
                        "Remove the duplicate assignment or allocate "
                        "a unique host address."
                    ),
                    suggested_command=(
                        "/ip address remove "
                        f"[find address=\"{parsed_interface}\"]"
                    ),
                    line_number=entry.line_number,
                )
            )
        else:
            seen_host_addresses[host_key] = entry

        if (
            parsed_interface.version == 4
            and parsed_interface.network.prefixlen < 31
        ):
            if (
                parsed_interface.ip
                == parsed_interface.network.network_address
            ):
                findings.append(
                    FindingResult(
                        rule_id="IP-007",
                        title="Network address assigned as a host",
                        category="IP addressing",
                        severity="high",
                        description=(
                            "The configured IPv4 address is the "
                            "network identifier for its subnet and "
                            "cannot normally identify a router host."
                        ),
                        evidence=entry.raw,
                        recommendation=(
                            "Assign a usable host address from within "
                            "the subnet."
                        ),
                        line_number=entry.line_number,
                    )
                )

            if (
                parsed_interface.ip
                == parsed_interface.network.broadcast_address
            ):
                findings.append(
                    FindingResult(
                        rule_id="IP-008",
                        title="Broadcast address assigned as a host",
                        category="IP addressing",
                        severity="high",
                        description=(
                            "The configured IPv4 address is the "
                            "broadcast address for its subnet."
                        ),
                        evidence=entry.raw,
                        recommendation=(
                            "Assign a usable host address and reserve "
                            "the broadcast address for subnet traffic."
                        ),
                        line_number=entry.line_number,
                    )
                )

        parsed.append(
            {
                "entry": entry,
                "interface": parsed_interface,
                "interface_name": interface_name,
            }
        )

    for index, left_item in enumerate(parsed):
        for right_item in parsed[index + 1:]:
            left = left_item["interface"]
            right = right_item["interface"]

            if left.version != right.version:
                continue

            left_network = left.network
            right_network = right.network

            if left_network == right_network:
                left_name = left_item["interface_name"]
                right_name = right_item["interface_name"]

                if (
                    left_name
                    and right_name
                    and left_name != right_name
                ):
                    findings.append(
                        FindingResult(
                            rule_id="IP-005",
                            title=(
                                "Same subnet assigned to multiple "
                                "interfaces"
                            ),
                            category="IP addressing",
                            severity="high",
                            description=(
                                "The same network is configured on "
                                "different interfaces. This can cause "
                                "ambiguous routing and ARP behavior."
                            ),
                            evidence=(
                                f"{left_item['entry'].raw}\n"
                                f"{right_item['entry'].raw}"
                            ),
                            recommendation=(
                                "Keep one routed subnet on one logical "
                                "interface unless bridge or redundancy "
                                "behavior is intentionally configured."
                            ),
                            line_number=(
                                right_item["entry"].line_number
                            ),
                        )
                    )

                continue

            if left_network.overlaps(right_network):
                findings.append(
                    FindingResult(
                        rule_id="IP-002",
                        title="Overlapping interface networks",
                        category="IP addressing",
                        severity="medium",
                        description=(
                            "Two configured interface networks overlap "
                            "and may cause ambiguous routing or DHCP "
                            "behavior."
                        ),
                        evidence=(
                            f"{left_item['entry'].raw}\n"
                            f"{right_item['entry'].raw}"
                        ),
                        recommendation=(
                            "Use non-overlapping subnets unless the "
                            "overlap is explicitly required and "
                            "documented."
                        ),
                        line_number=(
                            right_item["entry"].line_number
                        ),
                    )
                )

    return findings


def _parse_pool_segments(raw_ranges: str):
    """Return DHCP pool ranges as inclusive start and end addresses."""

    segments = []

    for chunk in str(raw_ranges).split(","):
        chunk = chunk.strip()

        if not chunk:
            continue

        if "-" in chunk:
            start, end = [
                part.strip()
                for part in chunk.split("-", 1)
            ]

            first = ip_address(start)
            last = ip_address(end)

            if first.version != last.version:
                raise ValueError(
                    "Pool start and end use different IP versions"
                )

            if int(first) > int(last):
                raise ValueError(
                    "Pool start is greater than pool end"
                )
        else:
            first = ip_address(chunk)
            last = first

        segments.append((first, last))

    if not segments:
        raise ValueError("Pool has no usable address ranges")

    return segments


def _parse_pool_ranges(raw_ranges: str):
    """Return DHCP pool ranges as normalized network blocks."""

    networks = []

    for first, last in _parse_pool_segments(raw_ranges):
        networks.extend(
            summarize_address_range(first, last)
        )

    return networks


def _address_in_pool(address, segments) -> bool:
    """Return True when an address belongs to a DHCP pool."""

    return any(
        address.version == first.version
        and int(first) <= int(address) <= int(last)
        for first, last in segments
    )


def _segment_inside_network(first, last, network) -> bool:
    """Return True when a complete pool segment fits in one subnet."""

    return (
        first.version == network.version
        and first in network
        and last in network
    )


def dhcp_rules(entries: list[ConfigEntry]) -> list[FindingResult]:
    findings: list[FindingResult] = []

    pools = {}
    interface_networks = {}
    interface_addresses = {}

    for entry in entries_for(entries, "/ip address"):
        if not is_enabled(entry):
            continue

        value = prop(entry, "address")
        interface_name = str(
            prop(entry, "interface", "")
        ).strip()

        if not value or not interface_name:
            continue

        try:
            parsed_interface = ip_interface(str(value))
        except ValueError:
            continue

        interface_networks.setdefault(
            interface_name,
            [],
        ).append(parsed_interface.network)

        interface_addresses.setdefault(
            interface_name,
            [],
        ).append(parsed_interface.ip)

    for entry in entries_for(entries, "/ip pool"):
        if not is_enabled(entry):
            continue

        name = str(
            prop(entry, "name", positional(entry))
        ).strip()
        ranges = prop(entry, "ranges")

        if not name or not ranges:
            findings.append(
                FindingResult(
                    rule_id="DHCP-001",
                    title="Invalid DHCP pool definition",
                    category="DHCP",
                    severity="high",
                    description=(
                        "The pool does not contain both a valid name "
                        "and address range."
                    ),
                    evidence=entry.raw,
                    recommendation=(
                        "Provide a unique pool name and at least one "
                        "valid client-address range."
                    ),
                    line_number=entry.line_number,
                )
            )
            continue

        try:
            segments = _parse_pool_segments(str(ranges))
            networks = _parse_pool_ranges(str(ranges))
        except ValueError as exc:
            findings.append(
                FindingResult(
                    rule_id="DHCP-001",
                    title="Invalid DHCP pool range",
                    category="DHCP",
                    severity="high",
                    description=(
                        f"The pool range cannot be parsed: {exc}."
                    ),
                    evidence=entry.raw,
                    recommendation=(
                        "Correct the pool and ensure every range uses "
                        "valid addresses with the start address before "
                        "the end address."
                    ),
                    line_number=entry.line_number,
                )
            )
            continue

        pools[name] = {
            "entry": entry,
            "segments": segments,
            "networks": networks,
        }

    pool_names = list(pools)

    for index, left_name in enumerate(pool_names):
        for right_name in pool_names[index + 1:]:
            left_pool = pools[left_name]
            right_pool = pools[right_name]

            overlaps = any(
                left_network.overlaps(right_network)
                for left_network in left_pool["networks"]
                for right_network in right_pool["networks"]
                if left_network.version
                == right_network.version
            )

            if overlaps:
                findings.append(
                    FindingResult(
                        rule_id="DHCP-002",
                        title="Overlapping DHCP pools",
                        category="DHCP",
                        severity="high",
                        description=(
                            "Two DHCP pools allocate at least one "
                            "common client address."
                        ),
                        evidence=(
                            f"{left_pool['entry'].raw}\n"
                            f"{right_pool['entry'].raw}"
                        ),
                        recommendation=(
                            "Separate the address ranges so that each "
                            "client address belongs to only one pool."
                        ),
                        line_number=(
                            right_pool["entry"].line_number
                        ),
                    )
                )

    dhcp_networks = []
    seen_dhcp_networks = {}

    for entry in entries_for(
        entries,
        "/ip dhcp-server network",
    ):
        if not is_enabled(entry):
            continue

        raw_network = prop(entry, "address")
        gateway_value = prop(entry, "gateway")

        if not raw_network:
            findings.append(
                FindingResult(
                    rule_id="DHCP-006",
                    title="DHCP network address is missing",
                    category="DHCP",
                    severity="high",
                    description=(
                        "The DHCP network entry does not specify the "
                        "subnet to which its options apply."
                    ),
                    evidence=entry.raw,
                    recommendation=(
                        "Add a valid subnet in CIDR format."
                    ),
                    line_number=entry.line_number,
                )
            )
            continue

        try:
            parsed_network = ip_network(
                str(raw_network),
                strict=False,
            )
        except ValueError:
            findings.append(
                FindingResult(
                    rule_id="DHCP-006",
                    title="Invalid DHCP network address",
                    category="DHCP",
                    severity="high",
                    description=(
                        "The DHCP network value is not a valid IPv4 "
                        "or IPv6 subnet."
                    ),
                    evidence=entry.raw,
                    recommendation=(
                        "Correct the DHCP network and use CIDR format."
                    ),
                    line_number=entry.line_number,
                )
            )
            continue

        network_key = (
            f"{parsed_network.version}:"
            f"{parsed_network.compressed}"
        )

        if network_key in seen_dhcp_networks:
            findings.append(
                FindingResult(
                    rule_id="DHCP-007",
                    title="Duplicate DHCP network entry",
                    category="DHCP",
                    severity="medium",
                    description=(
                        "The same DHCP subnet is defined more than "
                        "once."
                    ),
                    evidence=(
                        f"First: "
                        f"{seen_dhcp_networks[network_key].raw}\n"
                        f"Duplicate: {entry.raw}"
                    ),
                    recommendation=(
                        "Merge the settings into one DHCP network "
                        "entry and remove the duplicate."
                    ),
                    line_number=entry.line_number,
                )
            )
        else:
            seen_dhcp_networks[network_key] = entry

        parsed_gateways = []

        if gateway_value in {None, ""}:
            findings.append(
                FindingResult(
                    rule_id="DHCP-004",
                    title="DHCP network has no gateway",
                    category="DHCP",
                    severity="medium",
                    description=(
                        "Clients in this DHCP network may not receive "
                        "a default gateway."
                    ),
                    evidence=entry.raw,
                    recommendation=(
                        "Configure the router address for this subnet "
                        "as the DHCP gateway."
                    ),
                    line_number=entry.line_number,
                )
            )
        else:
            for raw_gateway in str(gateway_value).split(","):
                raw_gateway = raw_gateway.strip()

                if not raw_gateway:
                    continue

                try:
                    parsed_gateway = ip_address(raw_gateway)
                except ValueError:
                    findings.append(
                        FindingResult(
                            rule_id="DHCP-013",
                            title="Invalid DHCP gateway",
                            category="DHCP",
                            severity="high",
                            description=(
                                "The configured DHCP gateway is not "
                                "a valid IP address."
                            ),
                            evidence=entry.raw,
                            recommendation=(
                                "Configure a valid gateway address "
                                "inside the DHCP subnet."
                            ),
                            line_number=entry.line_number,
                        )
                    )
                    continue

                parsed_gateways.append(parsed_gateway)

                if (
                    parsed_gateway.version
                    != parsed_network.version
                    or parsed_gateway not in parsed_network
                ):
                    findings.append(
                        FindingResult(
                            rule_id="DHCP-013",
                            title=(
                                "DHCP gateway is outside its network"
                            ),
                            category="DHCP",
                            severity="high",
                            description=(
                                "The gateway distributed to clients "
                                "does not belong to the configured "
                                "DHCP subnet."
                            ),
                            evidence=entry.raw,
                            recommendation=(
                                "Use a gateway address located inside "
                                "the DHCP network."
                            ),
                            line_number=entry.line_number,
                        )
                    )

        dhcp_networks.append(
            {
                "entry": entry,
                "network": parsed_network,
                "gateways": parsed_gateways,
            }
        )

    for entry in entries_for(entries, "/ip dhcp-server"):
        if not is_enabled(entry):
            continue

        pool_name = str(
            prop(entry, "address-pool", "")
        ).strip()
        interface_name = str(
            prop(entry, "interface", "")
        ).strip()

        if (
            pool_name
            and pool_name != "static-only"
            and pool_name not in pools
        ):
            findings.append(
                FindingResult(
                    rule_id="DHCP-003",
                    title=(
                        "DHCP server references a missing pool"
                    ),
                    category="DHCP",
                    severity="high",
                    description=(
                        "The DHCP server uses an address-pool name "
                        "that is not defined in the export."
                    ),
                    evidence=entry.raw,
                    recommendation=(
                        "Create the referenced pool or update the "
                        "DHCP server to use an existing pool."
                    ),
                    line_number=entry.line_number,
                )
            )
            continue

        if (
            not pool_name
            or pool_name == "static-only"
            or pool_name not in pools
        ):
            continue

        pool = pools[pool_name]
        pool_segments = pool["segments"]
        related_networks = interface_networks.get(
            interface_name,
            [],
        )
        related_router_addresses = interface_addresses.get(
            interface_name,
            [],
        )

        if related_networks:
            outside_segments = [
                (first, last)
                for first, last in pool_segments
                if not any(
                    _segment_inside_network(
                        first,
                        last,
                        network,
                    )
                    for network in related_networks
                )
            ]

            if outside_segments:
                formatted_segments = ", ".join(
                    (
                        str(first)
                        if first == last
                        else f"{first}-{last}"
                    )
                    for first, last in outside_segments
                )

                findings.append(
                    FindingResult(
                        rule_id="DHCP-008",
                        title=(
                            "DHCP pool is outside the interface subnet"
                        ),
                        category="DHCP",
                        severity="high",
                        description=(
                            "At least one client-address range does "
                            "not fit inside any network configured on "
                            "the DHCP server interface."
                        ),
                        evidence=(
                            f"{entry.raw}\n"
                            f"Pool: {pool['entry'].raw}\n"
                            f"Outside range: {formatted_segments}"
                        ),
                        recommendation=(
                            "Move the pool inside the LAN interface "
                            "subnet or attach the DHCP server to the "
                            "correct interface."
                        ),
                        line_number=entry.line_number,
                    )
                )

            included_router_addresses = [
                address
                for address in related_router_addresses
                if _address_in_pool(
                    address,
                    pool_segments,
                )
            ]

            if included_router_addresses:
                findings.append(
                    FindingResult(
                        rule_id="DHCP-009",
                        title=(
                            "DHCP pool includes a router address"
                        ),
                        category="DHCP",
                        severity="critical",
                        description=(
                            "The client pool can allocate an address "
                            "already assigned to the router interface."
                        ),
                        evidence=(
                            f"{entry.raw}\n"
                            f"Pool: {pool['entry'].raw}\n"
                            f"Router address: "
                            f"{included_router_addresses[0]}"
                        ),
                        recommendation=(
                            "Exclude all router and infrastructure "
                            "addresses from the DHCP pool."
                        ),
                        line_number=entry.line_number,
                    )
                )

            reserved_addresses = []

            for network in related_networks:
                if (
                    network.version != 4
                    or network.prefixlen >= 31
                ):
                    continue

                if _address_in_pool(
                    network.network_address,
                    pool_segments,
                ):
                    reserved_addresses.append(
                        network.network_address
                    )

                if _address_in_pool(
                    network.broadcast_address,
                    pool_segments,
                ):
                    reserved_addresses.append(
                        network.broadcast_address
                    )

            if reserved_addresses:
                findings.append(
                    FindingResult(
                        rule_id="DHCP-010",
                        title=(
                            "DHCP pool includes a reserved subnet "
                            "address"
                        ),
                        category="DHCP",
                        severity="high",
                        description=(
                            "The pool includes a network or broadcast "
                            "address that should not be assigned to a "
                            "normal IPv4 client."
                        ),
                        evidence=(
                            f"{entry.raw}\n"
                            f"Reserved address: "
                            f"{reserved_addresses[0]}"
                        ),
                        recommendation=(
                            "Remove network and broadcast addresses "
                            "from the DHCP pool."
                        ),
                        line_number=entry.line_number,
                    )
                )

            matching_dhcp_networks = [
                item
                for item in dhcp_networks
                if any(
                    item["network"] == network
                    for network in related_networks
                )
            ]

            if not matching_dhcp_networks:
                findings.append(
                    FindingResult(
                        rule_id="DHCP-012",
                        title=(
                            "DHCP server has no matching network entry"
                        ),
                        category="DHCP",
                        severity="high",
                        description=(
                            "No DHCP network configuration matches "
                            "the subnet configured on the server "
                            "interface."
                        ),
                        evidence=entry.raw,
                        recommendation=(
                            "Create a DHCP network entry for the LAN "
                            "subnet and configure its gateway and "
                            "other client options."
                        ),
                        line_number=entry.line_number,
                    )
                )

            for network_item in matching_dhcp_networks:
                included_gateways = [
                    gateway
                    for gateway in network_item["gateways"]
                    if _address_in_pool(
                        gateway,
                        pool_segments,
                    )
                ]

                if included_gateways:
                    findings.append(
                        FindingResult(
                            rule_id="DHCP-011",
                            title=(
                                "DHCP gateway is inside the client pool"
                            ),
                            category="DHCP",
                            severity="critical",
                            description=(
                                "The pool may assign the gateway "
                                "address to a client, causing an IP "
                                "conflict and loss of connectivity."
                            ),
                            evidence=(
                                f"{entry.raw}\n"
                                f"Network: "
                                f"{network_item['entry'].raw}\n"
                                f"Gateway: "
                                f"{included_gateways[0]}"
                            ),
                            recommendation=(
                                "Exclude the gateway and all reserved "
                                "infrastructure addresses from the "
                                "client pool."
                            ),
                            line_number=entry.line_number,
                        )
                    )

    return findings


def _normalize_reference(value: Any) -> str:
    """Normalize RouterOS object references before comparison."""

    if value in {None, ""}:
        return ""

    reference = str(value).strip()

    while reference.startswith("!"):
        reference = reference[1:].strip()

    return reference


def interface_reference_rules(
    entries: list[ConfigEntry],
    configuration_summary: dict[str, Any],
) -> list[FindingResult]:
    """Validate interface and interface-list references.

    Reference validation is performed only when the uploaded export contains
    enough interface inventory data. This reduces false positives for partial
    RouterOS exports.
    """

    findings: list[FindingResult] = []

    interface_names = {
        str(item.get("name", "")).strip()
        for item in configuration_summary.get("interfaces", [])
        if item.get("name")
    }

    interface_list_names = {
        str(item.get("name", "")).strip()
        for item in configuration_summary.get("interface_lists", [])
        if item.get("name")
    }

    can_validate_interfaces = bool(interface_names)
    can_validate_interface_lists = bool(interface_list_names)

    ignored_references = {
        "",
        "none",
        "all",
        "dynamic",
        "static",
    }

    def check_interface(
        entry: ConfigEntry,
        property_name: str,
        rule_id: str,
        title: str,
        category: str,
        description: str,
        recommendation: str,
    ) -> None:
        if not can_validate_interfaces:
            return

        reference = _normalize_reference(
            prop(entry, property_name)
        )

        if (
            reference.lower() in ignored_references
            or reference in interface_names
        ):
            return

        findings.append(
            FindingResult(
                rule_id=rule_id,
                title=title,
                category=category,
                severity="high",
                description=description,
                evidence=(
                    f"{entry.raw}\n"
                    f"Undefined {property_name}: {reference}"
                ),
                recommendation=recommendation,
                suggested_command="",
                line_number=entry.line_number,
            )
        )

    def check_interface_list(
        entry: ConfigEntry,
        property_name: str,
        rule_id: str,
        title: str,
        category: str,
        description: str,
        recommendation: str,
    ) -> None:
        if not can_validate_interface_lists:
            return

        reference = _normalize_reference(
            prop(entry, property_name)
        )

        if (
            reference.lower() in ignored_references
            or reference in interface_list_names
        ):
            return

        findings.append(
            FindingResult(
                rule_id=rule_id,
                title=title,
                category=category,
                severity="high",
                description=description,
                evidence=(
                    f"{entry.raw}\n"
                    f"Undefined {property_name}: {reference}"
                ),
                recommendation=recommendation,
                suggested_command="",
                line_number=entry.line_number,
            )
        )

    for entry in entries:
        if not is_enabled(entry):
            continue

        if entry.section in {
            "/interface vlan",
            "/interface vrrp",
        }:
            check_interface(
                entry=entry,
                property_name="interface",
                rule_id="IF-001",
                title="Interface object references an undefined parent",
                category="Interfaces",
                description=(
                    "The interface depends on a parent interface that is not "
                    "defined in the uploaded configuration."
                ),
                recommendation=(
                    "Create the parent interface or update this object to "
                    "reference an existing interface."
                ),
            )

        elif entry.section == "/interface list member":
            check_interface(
                entry=entry,
                property_name="interface",
                rule_id="IF-002",
                title="Interface-list member references an undefined interface",
                category="Interfaces",
                description=(
                    "An interface-list membership references an interface "
                    "that is not present in the configuration inventory."
                ),
                recommendation=(
                    "Correct the interface name or create the referenced "
                    "interface before adding it to the list."
                ),
            )

            check_interface_list(
                entry=entry,
                property_name="list",
                rule_id="IF-003",
                title="Interface-list member references an undefined list",
                category="Interfaces",
                description=(
                    "An interface-list membership references a list that "
                    "is not defined in the uploaded configuration."
                ),
                recommendation=(
                    "Create the interface list or update the membership to "
                    "use an existing list."
                ),
            )

        elif entry.section == "/interface bridge port":
            check_interface(
                entry=entry,
                property_name="interface",
                rule_id="IF-004",
                title="Bridge port references an undefined interface",
                category="Interfaces",
                description=(
                    "A bridge port uses an interface that is not present in "
                    "the configuration inventory."
                ),
                recommendation=(
                    "Correct the bridge-port interface name or define the "
                    "referenced interface."
                ),
            )

            check_interface(
                entry=entry,
                property_name="bridge",
                rule_id="IF-005",
                title="Bridge port references an undefined bridge",
                category="Interfaces",
                description=(
                    "A bridge port references a bridge that is not present "
                    "in the configuration inventory."
                ),
                recommendation=(
                    "Create the bridge or update the bridge port to use an "
                    "existing bridge."
                ),
            )

        elif entry.section == "/ip address":
            check_interface(
                entry=entry,
                property_name="interface",
                rule_id="IP-004",
                title="IP address references an undefined interface",
                category="IP addressing",
                description=(
                    "The IP address is assigned to an interface that is not "
                    "defined in the uploaded configuration."
                ),
                recommendation=(
                    "Correct the interface name or create the interface "
                    "before assigning the IP address."
                ),
            )

        elif entry.section == "/ip dhcp-server":
            check_interface(
                entry=entry,
                property_name="interface",
                rule_id="DHCP-005",
                title="DHCP server references an undefined interface",
                category="DHCP",
                description=(
                    "The DHCP server is attached to an interface that is "
                    "not defined in the configuration inventory."
                ),
                recommendation=(
                    "Attach the DHCP server to an existing LAN interface "
                    "or create the missing interface."
                ),
            )

        elif entry.section == "/ip firewall filter":
            check_interface(
                entry=entry,
                property_name="in-interface",
                rule_id="FW-007",
                title="Firewall rule references an undefined interface",
                category="Firewall",
                description=(
                    "A firewall rule uses an incoming interface that is not "
                    "defined in the configuration inventory."
                ),
                recommendation=(
                    "Correct the incoming interface reference or create the "
                    "missing interface."
                ),
            )

            check_interface(
                entry=entry,
                property_name="out-interface",
                rule_id="FW-007",
                title="Firewall rule references an undefined interface",
                category="Firewall",
                description=(
                    "A firewall rule uses an outgoing interface that is not "
                    "defined in the configuration inventory."
                ),
                recommendation=(
                    "Correct the outgoing interface reference or create the "
                    "missing interface."
                ),
            )

            check_interface_list(
                entry=entry,
                property_name="in-interface-list",
                rule_id="FW-008",
                title="Firewall rule references an undefined interface list",
                category="Firewall",
                description=(
                    "A firewall rule uses an incoming interface list that "
                    "is not defined in the configuration."
                ),
                recommendation=(
                    "Create the interface list or update the rule to use an "
                    "existing list."
                ),
            )

            check_interface_list(
                entry=entry,
                property_name="out-interface-list",
                rule_id="FW-008",
                title="Firewall rule references an undefined interface list",
                category="Firewall",
                description=(
                    "A firewall rule uses an outgoing interface list that "
                    "is not defined in the configuration."
                ),
                recommendation=(
                    "Create the interface list or update the rule to use an "
                    "existing list."
                ),
            )

        elif entry.section == "/ip firewall nat":
            check_interface(
                entry=entry,
                property_name="in-interface",
                rule_id="NAT-003",
                title="NAT rule references an undefined interface",
                category="NAT",
                description=(
                    "A NAT rule uses an incoming interface that is not "
                    "defined in the configuration inventory."
                ),
                recommendation=(
                    "Correct the incoming interface reference or create the "
                    "missing interface."
                ),
            )

            check_interface(
                entry=entry,
                property_name="out-interface",
                rule_id="NAT-003",
                title="NAT rule references an undefined interface",
                category="NAT",
                description=(
                    "A NAT rule uses an outgoing interface that is not "
                    "defined in the configuration inventory."
                ),
                recommendation=(
                    "Correct the outgoing interface reference or create the "
                    "missing interface."
                ),
            )

            check_interface_list(
                entry=entry,
                property_name="in-interface-list",
                rule_id="NAT-004",
                title="NAT rule references an undefined interface list",
                category="NAT",
                description=(
                    "A NAT rule uses an incoming interface list that is not "
                    "defined in the configuration."
                ),
                recommendation=(
                    "Create the interface list or update the rule to use an "
                    "existing list."
                ),
            )

            check_interface_list(
                entry=entry,
                property_name="out-interface-list",
                rule_id="NAT-004",
                title="NAT rule references an undefined interface list",
                category="NAT",
                description=(
                    "A NAT rule uses an outgoing interface list that is not "
                    "defined in the configuration."
                ),
                recommendation=(
                    "Create the interface list or update the rule to use an "
                    "existing list."
                ),
            )

    return findings


ROUTE_DISCARD_TYPES = {
    "blackhole",
    "prohibit",
    "unreachable",
}

ROUTE_BROADCAST_INTERFACE_TYPES = {
    "ethernet",
    "bridge",
    "vlan",
    "wireless",
    "wifi",
}


def _route_type(entry: ConfigEntry) -> str:
    """Return a normalized RouterOS route type."""

    explicit_type = str(
        prop(entry, "type", "")
    ).strip().lower()

    if explicit_type in ROUTE_DISCARD_TYPES:
        return explicit_type

    for route_type in ROUTE_DISCARD_TYPES:
        marker = prop(entry, route_type)

        if marker is True or str(marker).lower() == "yes":
            return route_type

    return "unicast"


def _parse_route_gateway(raw_gateway: str) -> dict[str, Any]:
    """Parse IP, interface, IP%interface, and @table gateways."""

    original = str(raw_gateway).strip()

    if not original:
        raise ValueError("Gateway is empty")

    reference = original
    lookup_table = ""

    if "@" in reference:
        reference, lookup_table = reference.rsplit("@", 1)
        reference = reference.strip()
        lookup_table = lookup_table.strip()

    interface_name = ""

    if "%" in reference:
        address_text, interface_name = reference.split("%", 1)

        address_text = address_text.strip()
        interface_name = interface_name.strip()

        if not address_text or not interface_name:
            raise ValueError(
                "Gateway has an invalid IP%interface format"
            )

        address = ip_address(address_text)

        normalized = f"{address}%{interface_name}"

        if lookup_table:
            normalized += f"@{lookup_table}"

        return {
            "raw": original,
            "normalized": normalized,
            "kind": "ip",
            "address": address,
            "interface": interface_name,
            "lookup_table": lookup_table,
        }

    try:
        address = ip_address(reference)
    except ValueError:
        if not reference:
            raise ValueError("Gateway interface is empty")

        normalized = reference

        if lookup_table:
            normalized += f"@{lookup_table}"

        return {
            "raw": original,
            "normalized": normalized,
            "kind": "interface",
            "address": None,
            "interface": reference,
            "lookup_table": lookup_table,
        }

    normalized = str(address)

    if lookup_table:
        normalized += f"@{lookup_table}"

    return {
        "raw": original,
        "normalized": normalized,
        "kind": "ip",
        "address": address,
        "interface": "",
        "lookup_table": lookup_table,
    }


def _split_route_gateways(raw_gateway: Any) -> list[str]:
    """Split RouterOS ECMP gateway values."""

    if raw_gateway in {None, ""}:
        return []

    return [
        item.strip()
        for item in str(raw_gateway).split(",")
        if item.strip()
    ]


def route_rules(
    entries: list[ConfigEntry],
    configuration_summary: dict[str, Any] | None = None,
) -> list[FindingResult]:
    """Validate static IPv4 routes and gateway dependencies."""

    findings: list[FindingResult] = []
    configuration_summary = configuration_summary or {}

    interface_types = {
        str(item.get("name", "")).strip(): str(
            item.get("type", "")
        ).strip().lower()
        for item in configuration_summary.get(
            "interfaces",
            [],
        )
        if item.get("name")
    }

    can_validate_interfaces = bool(interface_types)

    connected_networks = []
    connected_networks_by_interface = {}
    router_addresses = set()

    for entry in entries_for(entries, "/ip address"):
        if not is_enabled(entry):
            continue

        raw_address = prop(entry, "address")
        interface_name = str(
            prop(entry, "interface", "")
        ).strip()

        if not raw_address:
            continue

        try:
            parsed_interface = ip_interface(
                str(raw_address)
            )
        except ValueError:
            continue

        if parsed_interface.version != 4:
            continue

        connected_networks.append(
            parsed_interface.network
        )
        router_addresses.add(parsed_interface.ip)

        if interface_name:
            connected_networks_by_interface.setdefault(
                interface_name,
                [],
            ).append(parsed_interface.network)

    route_records = []
    seen_signatures = {}

    for entry in entries_for(entries, "/ip route"):
        if not is_enabled(entry):
            continue

        if entry.command != "add":
            continue

        raw_destination = prop(
            entry,
            "dst-address",
            "0.0.0.0/0",
        )

        if raw_destination in {None, ""}:
            raw_destination = "0.0.0.0/0"

        try:
            destination = ip_network(
                str(raw_destination),
                strict=False,
            )

            if destination.version != 4:
                raise ValueError(
                    "IPv6 destination found in /ip route"
                )
        except ValueError:
            findings.append(
                FindingResult(
                    rule_id="ROUTE-001",
                    title="Invalid static route destination",
                    category="Routes",
                    severity="high",
                    description=(
                        "The route destination is not a valid IPv4 "
                        "network prefix."
                    ),
                    evidence=entry.raw,
                    recommendation=(
                        "Use a valid IPv4 destination in CIDR format, "
                        "such as 192.168.20.0/24."
                    ),
                    suggested_command="",
                    line_number=entry.line_number,
                )
            )
            continue

        route_type = _route_type(entry)

        raw_distance = prop(entry, "distance", 1)

        try:
            distance = int(raw_distance)

            if not 0 <= distance <= 255:
                raise ValueError
        except (TypeError, ValueError):
            findings.append(
                FindingResult(
                    rule_id="ROUTE-011",
                    title="Invalid route distance",
                    category="Routes",
                    severity="medium",
                    description=(
                        "The route distance must be an integer "
                        "between 0 and 255."
                    ),
                    evidence=entry.raw,
                    recommendation=(
                        "Set a valid administrative distance. "
                        "Static routes commonly use distance 1."
                    ),
                    suggested_command="",
                    line_number=entry.line_number,
                )
            )
            distance = 1

        routing_table = str(
            prop(entry, "routing-table", "main")
        ).strip() or "main"

        gateway_values = _split_route_gateways(
            prop(entry, "gateway")
        )

        if (
            route_type == "unicast"
            and not gateway_values
        ):
            findings.append(
                FindingResult(
                    rule_id="ROUTE-002",
                    title="Static route has no gateway",
                    category="Routes",
                    severity="high",
                    description=(
                        "An enabled unicast static route does not "
                        "define a next hop."
                    ),
                    evidence=entry.raw,
                    recommendation=(
                        "Configure a reachable gateway or use an "
                        "explicit discard route type when intended."
                    ),
                    suggested_command="",
                    line_number=entry.line_number,
                )
            )

        parsed_gateways = []

        for raw_gateway in gateway_values:
            try:
                gateway = _parse_route_gateway(
                    raw_gateway
                )
            except ValueError as exc:
                findings.append(
                    FindingResult(
                        rule_id="ROUTE-003",
                        title="Invalid route gateway",
                        category="Routes",
                        severity="high",
                        description=(
                            f"The gateway cannot be parsed: {exc}."
                        ),
                        evidence=entry.raw,
                        recommendation=(
                            "Use a valid gateway IP address, "
                            "interface, IP%interface, or @table "
                            "reference."
                        ),
                        suggested_command="",
                        line_number=entry.line_number,
                    )
                )
                continue

            referenced_interface = gateway["interface"]

            if (
                referenced_interface
                and can_validate_interfaces
                and referenced_interface
                not in interface_types
            ):
                findings.append(
                    FindingResult(
                        rule_id="ROUTE-003",
                        title=(
                            "Route references an undefined gateway "
                            "interface"
                        ),
                        category="Routes",
                        severity="high",
                        description=(
                            "The route gateway references an "
                            "interface that is not defined in the "
                            "uploaded configuration."
                        ),
                        evidence=(
                            f"{entry.raw}\n"
                            f"Undefined interface: "
                            f"{referenced_interface}"
                        ),
                        recommendation=(
                            "Correct the gateway interface name or "
                            "create the missing interface."
                        ),
                        suggested_command="",
                        line_number=entry.line_number,
                    )
                )

            parsed_gateways.append(gateway)

        gateway_signature = tuple(
            sorted(
                gateway["normalized"]
                for gateway in parsed_gateways
            )
        )

        signature = (
            str(destination),
            gateway_signature,
            distance,
            routing_table,
            route_type,
        )

        if signature in seen_signatures:
            first_entry = seen_signatures[signature]

            findings.append(
                FindingResult(
                    rule_id="ROUTE-005",
                    title="Exact duplicate static route",
                    category="Routes",
                    severity="medium",
                    description=(
                        "The same destination, gateway, distance, "
                        "routing table, and route type are configured "
                        "more than once."
                    ),
                    evidence=(
                        f"First: {first_entry.raw}\n"
                        f"Duplicate: {entry.raw}"
                    ),
                    recommendation=(
                        "Remove the redundant route unless duplicate "
                        "entries are required for a documented reason."
                    ),
                    suggested_command="",
                    line_number=entry.line_number,
                )
            )
        else:
            seen_signatures[signature] = entry

        check_gateway = str(
            prop(entry, "check-gateway", "")
        ).strip().lower()

        for gateway in parsed_gateways:
            if gateway["kind"] == "interface":
                interface_name = gateway["interface"]
                interface_type = interface_types.get(
                    interface_name,
                    "",
                )

                directly_connected_destination = any(
                    destination == network
                    for network in (
                        connected_networks_by_interface.get(
                            interface_name,
                            [],
                        )
                    )
                )

                if (
                    interface_type
                    in ROUTE_BROADCAST_INTERFACE_TYPES
                    and not directly_connected_destination
                ):
                    findings.append(
                        FindingResult(
                            rule_id="ROUTE-008",
                            title=(
                                "Interface-only gateway used on a "
                                "broadcast interface"
                            ),
                            category="Routes",
                            severity="medium",
                            description=(
                                "Using only a broadcast interface as "
                                "the gateway for a remote destination "
                                "can cause unsuccessful address "
                                "resolution."
                            ),
                            evidence=entry.raw,
                            recommendation=(
                                "Use a next-hop IP address, or an "
                                "IP%interface gateway when an explicit "
                                "interface is required."
                            ),
                            suggested_command="",
                            line_number=entry.line_number,
                        )
                    )

                if check_gateway not in {
                    "",
                    "none",
                    "no",
                }:
                    findings.append(
                        FindingResult(
                            rule_id="ROUTE-009",
                            title=(
                                "Gateway checking used with an "
                                "interface-only gateway"
                            ),
                            category="Routes",
                            severity="medium",
                            description=(
                                "Gateway reachability checks require "
                                "a known gateway address and are not "
                                "meaningful for an interface-only "
                                "gateway."
                            ),
                            evidence=entry.raw,
                            recommendation=(
                                "Use an IP next hop or remove the "
                                "check-gateway option."
                            ),
                            suggested_command="",
                            line_number=entry.line_number,
                        )
                    )

                continue

            gateway_address = gateway["address"]

            if gateway_address in router_addresses:
                findings.append(
                    FindingResult(
                        rule_id="ROUTE-006",
                        title=(
                            "Route gateway is the router's own address"
                        ),
                        category="Routes",
                        severity="critical",
                        description=(
                            "The configured next hop belongs to the "
                            "same router and can create invalid "
                            "forwarding behavior."
                        ),
                        evidence=entry.raw,
                        recommendation=(
                            "Use the address of the actual next-hop "
                            "router."
                        ),
                        suggested_command="",
                        line_number=entry.line_number,
                    )
                )

            for network in connected_networks:
                if (
                    network.prefixlen >= 31
                    or gateway_address not in network
                ):
                    continue

                if gateway_address in {
                    network.network_address,
                    network.broadcast_address,
                }:
                    findings.append(
                        FindingResult(
                            rule_id="ROUTE-007",
                            title=(
                                "Route gateway uses a reserved subnet "
                                "address"
                            ),
                            category="Routes",
                            severity="high",
                            description=(
                                "The gateway is the network or "
                                "broadcast address of a connected "
                                "IPv4 subnet."
                            ),
                            evidence=entry.raw,
                            recommendation=(
                                "Use a valid host address for the "
                                "next-hop router."
                            ),
                            suggested_command="",
                            line_number=entry.line_number,
                        )
                    )
                    break

        route_records.append(
            {
                "entry": entry,
                "network": destination,
                "gateways": parsed_gateways,
                "distance": distance,
                "routing_table": routing_table,
                "route_type": route_type,
            }
        )

    resolved_route_indexes = set()

    def gateway_is_directly_reachable(
        gateway: dict[str, Any],
    ) -> bool:
        if gateway["kind"] == "interface":
            return (
                not can_validate_interfaces
                or gateway["interface"] in interface_types
            )

        return any(
            gateway["address"] in network
            for network in connected_networks
        )

    for index, record in enumerate(route_records):
        if record["route_type"] != "unicast":
            continue

        if any(
            gateway_is_directly_reachable(gateway)
            for gateway in record["gateways"]
        ):
            resolved_route_indexes.add(index)

    changed = True

    while changed:
        changed = False

        for index, record in enumerate(route_records):
            if (
                index in resolved_route_indexes
                or record["route_type"] != "unicast"
            ):
                continue

            route_resolved = False

            for gateway in record["gateways"]:
                if gateway["kind"] != "ip":
                    continue

                lookup_table = (
                    gateway["lookup_table"]
                    or record["routing_table"]
                )

                for other_index in resolved_route_indexes:
                    if other_index == index:
                        continue

                    other = route_records[other_index]

                    if (
                        other["route_type"] != "unicast"
                        or other["routing_table"]
                        != lookup_table
                        or other["network"].prefixlen == 0
                    ):
                        continue

                    if gateway["address"] in other["network"]:
                        route_resolved = True
                        break

                if route_resolved:
                    break

            if route_resolved:
                resolved_route_indexes.add(index)
                changed = True

    if connected_networks:
        for index, record in enumerate(route_records):
            if record["route_type"] != "unicast":
                continue

            for gateway in record["gateways"]:
                if gateway["kind"] != "ip":
                    continue

                if gateway_is_directly_reachable(gateway):
                    continue

                lookup_table = (
                    gateway["lookup_table"]
                    or record["routing_table"]
                )

                recursively_resolved = any(
                    other_index != index
                    and other_index in resolved_route_indexes
                    and route_records[other_index][
                        "route_type"
                    ] == "unicast"
                    and route_records[other_index][
                        "routing_table"
                    ] == lookup_table
                    and route_records[other_index][
                        "network"
                    ].prefixlen > 0
                    and gateway["address"]
                    in route_records[other_index]["network"]
                    for other_index in range(
                        len(route_records)
                    )
                )

                if recursively_resolved:
                    continue

                findings.append(
                    FindingResult(
                        rule_id="ROUTE-004",
                        title=(
                            "Route gateway cannot be resolved"
                        ),
                        category="Routes",
                        severity="high",
                        description=(
                            "The uploaded configuration contains no "
                            "connected or recursively resolvable path "
                            "to this gateway."
                        ),
                        evidence=(
                            f"{record['entry'].raw}\n"
                            f"Unresolved gateway: "
                            f"{gateway['normalized']}"
                        ),
                        recommendation=(
                            "Add a connected or recursive route to "
                            "the next hop, or correct the gateway "
                            "address."
                        ),
                        suggested_command="",
                        line_number=(
                            record["entry"].line_number
                        ),
                    )
                )

    route_groups = {}

    for record in route_records:
        group_key = (
            str(record["network"]),
            record["routing_table"],
            record["distance"],
        )

        route_groups.setdefault(
            group_key,
            [],
        ).append(record)

    for grouped_routes in route_groups.values():
        unicast_routes = [
            record
            for record in grouped_routes
            if record["route_type"] == "unicast"
        ]

        discard_routes = [
            record
            for record in grouped_routes
            if record["route_type"]
            in ROUTE_DISCARD_TYPES
        ]

        if not unicast_routes or not discard_routes:
            continue

        findings.append(
            FindingResult(
                rule_id="ROUTE-010",
                title=(
                    "Conflicting unicast and discard routes"
                ),
                category="Routes",
                severity="high",
                description=(
                    "The same destination and distance contain both "
                    "a forwarding route and a discard route."
                ),
                evidence=(
                    f"Unicast: "
                    f"{unicast_routes[0]['entry'].raw}\n"
                    f"Discard: "
                    f"{discard_routes[0]['entry'].raw}"
                ),
                recommendation=(
                    "Use distinct distances or remove the unintended "
                    "route so the forwarding policy is unambiguous."
                ),
                suggested_command="",
                line_number=(
                    discard_routes[0]["entry"].line_number
                ),
            )
        )

    return findings


FIREWALL_TERMINAL_ACTIONS = {
    "accept",
    "drop",
    "reject",
}

FIREWALL_MANAGEMENT_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    80: "WebFig HTTP",
    443: "WebFig HTTPS",
    8291: "WinBox",
    8728: "RouterOS API",
    8729: "RouterOS API-SSL",
}

FIREWALL_NON_MATCH_PROPERTIES = {
    "_positional",
    "action",
    "chain",
    "comment",
    "disabled",
    "log",
    "log-prefix",
    "place-before",
    "copy-from",
}


def _normalized_csv_set(value: Any) -> set[str]:
    """Normalize comma-separated RouterOS values."""

    if value is None or value == "":
        return set()

    return {
        item.strip().lower()
        for item in str(value).split(",")
        if item.strip()
    }


def _parse_firewall_port_ranges(
    value: Any,
) -> list[tuple[int, int]]:
    """Parse RouterOS comma-separated ports and ranges."""

    if value is None or value == "":
        return []

    ranges: list[tuple[int, int]] = []

    for raw_part in str(value).split(","):
        part = raw_part.strip()

        if not part:
            continue

        if "-" in part:
            start_text, end_text = [
                item.strip()
                for item in part.split("-", 1)
            ]

            start = int(start_text)
            end = int(end_text)
        else:
            start = int(part)
            end = start

        if not 1 <= start <= 65535:
            raise ValueError(
                f"Port {start} is outside 1-65535"
            )

        if not 1 <= end <= 65535:
            raise ValueError(
                f"Port {end} is outside 1-65535"
            )

        if start > end:
            raise ValueError(
                f"Port range {start}-{end} is reversed"
            )

        ranges.append((start, end))

    if not ranges:
        raise ValueError("Port expression is empty")

    return ranges


def _port_ranges_cover(
    earlier_value: Any,
    later_value: Any,
) -> bool:
    """Return whether the earlier port match covers the later one."""

    if earlier_value is None or earlier_value == "":
        return True

    if later_value is None or later_value == "":
        return False

    try:
        earlier_ranges = _parse_firewall_port_ranges(
            earlier_value
        )
        later_ranges = _parse_firewall_port_ranges(
            later_value
        )
    except (TypeError, ValueError):
        return str(earlier_value) == str(later_value)

    return all(
        any(
            earlier_start <= later_start
            and earlier_end >= later_end
            for earlier_start, earlier_end in earlier_ranges
        )
        for later_start, later_end in later_ranges
    )


def _address_match_covers(
    earlier_value: Any,
    later_value: Any,
) -> bool:
    """Return whether an earlier direct address match covers a later one."""

    if earlier_value is None or earlier_value == "":
        return True

    if later_value is None or later_value == "":
        return False

    earlier_text = str(earlier_value).strip()
    later_text = str(later_value).strip()

    if earlier_text.startswith("!") or later_text.startswith("!"):
        return earlier_text == later_text

    try:
        earlier_network = ip_network(
            earlier_text,
            strict=False,
        )
        later_network = ip_network(
            later_text,
            strict=False,
        )
    except ValueError:
        return earlier_text == later_text

    return (
        earlier_network.version == later_network.version
        and (
            earlier_network == later_network
            or earlier_network.supernet_of(later_network)
        )
    )


def _firewall_property_covers(
    property_name: str,
    earlier_value: Any,
    later_value: Any,
) -> bool:
    """Compare one firewall matcher for shadow analysis."""

    if earlier_value is None or earlier_value == "":
        return True

    if later_value is None or later_value == "":
        return False

    if property_name in {
        "src-address",
        "dst-address",
    }:
        return _address_match_covers(
            earlier_value,
            later_value,
        )

    if property_name in {
        "src-port",
        "dst-port",
        "port",
    }:
        return _port_ranges_cover(
            earlier_value,
            later_value,
        )

    if property_name in {
        "connection-state",
        "connection-nat-state",
    }:
        earlier_states = _normalized_csv_set(
            earlier_value
        )
        later_states = _normalized_csv_set(
            later_value
        )

        return earlier_states.issuperset(
            later_states
        )

    return (
        str(earlier_value).strip().lower()
        == str(later_value).strip().lower()
    )


def _firewall_rule_covers(
    earlier: ConfigEntry,
    later: ConfigEntry,
) -> bool:
    """Return whether an earlier rule matches every packet of a later rule."""

    if (
        str(prop(earlier, "chain", "")).lower()
        != str(prop(later, "chain", "")).lower()
    ):
        return False

    property_names = (
        set(earlier.properties)
        | set(later.properties)
    ) - FIREWALL_NON_MATCH_PROPERTIES

    for property_name in property_names:
        if not _firewall_property_covers(
            property_name,
            prop(earlier, property_name),
            prop(later, property_name),
        ):
            return False

    return True


def _normalized_firewall_signature(
    entry: ConfigEntry,
) -> tuple:
    """Build a stable signature for exact duplicate detection."""

    normalized_properties = []

    for key, value in entry.properties.items():
        if key in FIREWALL_NON_MATCH_PROPERTIES:
            continue

        if value is None or value == "":
            continue

        if key in {
            "connection-state",
            "connection-nat-state",
        }:
            normalized_value = ",".join(
                sorted(_normalized_csv_set(value))
            )
        elif key in {
            "src-port",
            "dst-port",
            "port",
        }:
            try:
                normalized_value = ",".join(
                    (
                        str(start)
                        if start == end
                        else f"{start}-{end}"
                    )
                    for start, end
                    in _parse_firewall_port_ranges(value)
                )
            except (TypeError, ValueError):
                normalized_value = str(value).strip().lower()
        else:
            normalized_value = str(value).strip().lower()

        normalized_properties.append(
            (key, normalized_value)
        )

    return (
        str(prop(entry, "chain", "")).strip().lower(),
        str(prop(entry, "action", "")).strip().lower(),
        tuple(sorted(normalized_properties)),
    )


def _is_unrestricted_source(entry: ConfigEntry) -> bool:
    """Return whether a rule lacks a trusted-source restriction."""

    source_address = str(
        prop(entry, "src-address", "")
    ).strip()

    source_address_list = str(
        prop(entry, "src-address-list", "")
    ).strip()

    return (
        source_address
        in {
            "",
            "0.0.0.0/0",
            "::/0",
        }
        and not source_address_list
    )


def _management_ports_in_rule(
    entry: ConfigEntry,
) -> list[tuple[int, str]]:
    """Return management ports accepted by a firewall rule."""

    raw_ports = prop(entry, "dst-port")

    if raw_ports is None or raw_ports == "":
        return []

    try:
        port_ranges = _parse_firewall_port_ranges(
            raw_ports
        )
    except (TypeError, ValueError):
        return []

    exposed = []

    for port, service_name in FIREWALL_MANAGEMENT_PORTS.items():
        if any(
            start <= port <= end
            for start, end in port_ranges
        ):
            exposed.append((port, service_name))

    return exposed


def _is_stateful_accept(entry: ConfigEntry) -> bool:
    return (
        str(prop(entry, "action", "")).lower()
        == "accept"
        and {
            "established",
            "related",
        }.issubset(
            _normalized_csv_set(
                prop(entry, "connection-state")
            )
        )
    )


def _is_invalid_drop(entry: ConfigEntry) -> bool:
    return (
        str(prop(entry, "action", "")).lower()
        in {"drop", "reject"}
        and "invalid"
        in _normalized_csv_set(
            prop(entry, "connection-state")
        )
    )


def _is_broad_rule(entry: ConfigEntry) -> bool:
    restriction_keys = {
        "protocol", "src-address", "dst-address", "src-address-list",
        "dst-address-list", "in-interface", "in-interface-list",
        "out-interface", "out-interface-list", "src-port", "dst-port",
        "connection-state", "connection-nat-state", "layer7-protocol",
    }
    return not any(prop(entry, key) not in {None, ""} for key in restriction_keys)


def firewall_rules(
    entries: list[ConfigEntry],
) -> list[FindingResult]:
    findings: list[FindingResult] = []

    all_rules = [
        entry
        for entry in entries_for(
            entries,
            "/ip firewall filter",
        )
        if entry.command == "add"
    ]

    enabled_rules = [
        entry
        for entry in all_rules
        if is_enabled(entry)
    ]

    input_rules = [
        entry
        for entry in enabled_rules
        if str(
            prop(entry, "chain", "")
        ).lower() == "input"
    ]

    forward_rules = [
        entry
        for entry in enabled_rules
        if str(
            prop(entry, "chain", "")
        ).lower() == "forward"
    ]

    if not any(
        str(prop(entry, "action", "")).lower()
        in {"drop", "reject"}
        and _is_broad_rule(entry)
        for entry in input_rules
    ):
        findings.append(
            FindingResult(
                rule_id="FW-001",
                title="No default input-chain drop rule",
                category="Firewall",
                severity="critical",
                description=(
                    "The configuration does not contain an "
                    "unrestricted final drop or reject rule for "
                    "traffic directed to the router."
                ),
                evidence=(
                    "No matching enabled input-chain rule was found."
                ),
                recommendation=(
                    "Apply a deny-by-default input policy after "
                    "required management and service exceptions."
                ),
                suggested_command=(
                    "/ip firewall filter add chain=input "
                    "action=drop comment=\"NetAudit default input drop\""
                ),
            )
        )

    if not any(
        _is_stateful_accept(entry)
        for entry in input_rules
    ):
        findings.append(
            FindingResult(
                rule_id="FW-002",
                title=(
                    "Established and related traffic is not "
                    "explicitly accepted"
                ),
                category="Firewall",
                severity="medium",
                description=(
                    "A stateful input policy normally accepts "
                    "established and related connections near the "
                    "start of the chain."
                ),
                evidence=(
                    "No suitable input-chain rule was found."
                ),
                recommendation=(
                    "Add the stateful accept rule before specific "
                    "service rules."
                ),
                suggested_command=(
                    "/ip firewall filter add chain=input "
                    "action=accept "
                    "connection-state=established,related"
                ),
            )
        )

    if not any(
        _is_invalid_drop(entry)
        for entry in input_rules
    ):
        findings.append(
            FindingResult(
                rule_id="FW-003",
                title="Invalid connections are not dropped",
                category="Firewall",
                severity="medium",
                description=(
                    "Invalid connection-tracking states are not "
                    "explicitly discarded in the input chain."
                ),
                evidence=(
                    "No suitable input-chain rule was found."
                ),
                recommendation=(
                    "Drop invalid traffic near the start of the "
                    "input chain."
                ),
                suggested_command=(
                    "/ip firewall filter add chain=input "
                    "action=drop connection-state=invalid"
                ),
            )
        )

    for entry in input_rules:
        if (
            str(prop(entry, "action", "")).lower()
            == "accept"
            and _is_broad_rule(entry)
        ):
            findings.append(
                FindingResult(
                    rule_id="FW-004",
                    title="Broad input accept rule",
                    category="Firewall",
                    severity="critical",
                    description=(
                        "This rule accepts all traffic directed to "
                        "the router without source, protocol, port, "
                        "or interface restrictions."
                    ),
                    evidence=entry.raw,
                    recommendation=(
                        "Replace it with specific trusted-source and "
                        "required-service rules followed by a "
                        "default drop."
                    ),
                    line_number=entry.line_number,
                )
            )

    for entry in all_rules:
        if is_enabled(entry):
            continue

        action = str(
            prop(entry, "action", "")
        ).lower()

        if (
            action in {"drop", "reject"}
            or "invalid"
            in _normalized_csv_set(
                prop(entry, "connection-state")
            )
        ):
            findings.append(
                FindingResult(
                    rule_id="FW-005",
                    title="Disabled security firewall rule",
                    category="Firewall",
                    severity="low",
                    description=(
                        "A rule that appears intended to block "
                        "unwanted traffic is disabled."
                    ),
                    evidence=entry.raw,
                    recommendation=(
                        "Confirm whether the rule is required. "
                        "Enable or remove it to avoid ambiguity."
                    ),
                    line_number=entry.line_number,
                )
            )

    terminal_rule_by_chain: dict[
        str,
        ConfigEntry,
    ] = {}

    for entry in enabled_rules:
        chain = str(
            prop(entry, "chain", "")
        ).lower()

        if chain in terminal_rule_by_chain:
            previous = terminal_rule_by_chain[chain]

            findings.append(
                FindingResult(
                    rule_id="FW-006",
                    title=(
                        "Potentially unreachable firewall rule"
                    ),
                    category="Firewall",
                    severity="medium",
                    description=(
                        "An earlier unrestricted terminal rule can "
                        "stop processing before this rule."
                    ),
                    evidence=(
                        f"Earlier terminal rule: {previous.raw}\n"
                        f"Potentially unreachable: {entry.raw}"
                    ),
                    recommendation=(
                        "Reorder or narrow the earlier rule so that "
                        "specific rules can be evaluated."
                    ),
                    line_number=entry.line_number,
                )
            )

        action = str(
            prop(entry, "action", "")
        ).lower()

        if (
            action in FIREWALL_TERMINAL_ACTIONS
            and _is_broad_rule(entry)
        ):
            terminal_rule_by_chain[chain] = entry

    seen_signatures: dict[
        tuple,
        ConfigEntry,
    ] = {}

    duplicate_entry_ids = set()

    for entry in enabled_rules:
        signature = _normalized_firewall_signature(
            entry
        )

        if signature in seen_signatures:
            first_entry = seen_signatures[signature]
            duplicate_entry_ids.add(id(entry))

            findings.append(
                FindingResult(
                    rule_id="FW-009",
                    title="Exact duplicate firewall rule",
                    category="Firewall",
                    severity="medium",
                    description=(
                        "The same chain, action, and matching "
                        "conditions appear more than once."
                    ),
                    evidence=(
                        f"First: {first_entry.raw}\n"
                        f"Duplicate: {entry.raw}"
                    ),
                    recommendation=(
                        "Remove the redundant rule unless duplicate "
                        "entries are required for a documented "
                        "operational reason."
                    ),
                    line_number=entry.line_number,
                )
            )
        else:
            seen_signatures[signature] = entry

    rules_by_chain: dict[
        str,
        list[ConfigEntry],
    ] = {}

    for entry in enabled_rules:
        chain = str(
            prop(entry, "chain", "")
        ).lower()

        rules_by_chain.setdefault(
            chain,
            [],
        ).append(entry)

    for chain_rules in rules_by_chain.values():
        for earlier_index, earlier in enumerate(
            chain_rules
        ):
            earlier_action = str(
                prop(earlier, "action", "")
            ).lower()

            if (
                earlier_action
                not in FIREWALL_TERMINAL_ACTIONS
            ):
                continue

            if _is_broad_rule(earlier):
                continue

            for later in chain_rules[
                earlier_index + 1:
            ]:
                if id(later) in duplicate_entry_ids:
                    continue

                if not _firewall_rule_covers(
                    earlier,
                    later,
                ):
                    continue

                later_action = str(
                    prop(later, "action", "")
                ).lower()

                conflicting = (
                    later_action
                    in FIREWALL_TERMINAL_ACTIONS
                    and later_action != earlier_action
                )

                findings.append(
                    FindingResult(
                        rule_id="FW-010",
                        title=(
                            "Conflicting shadowed firewall rule"
                            if conflicting
                            else "Partially shadowed firewall rule"
                        ),
                        category="Firewall",
                        severity=(
                            "high"
                            if conflicting
                            else "medium"
                        ),
                        description=(
                            "An earlier rule covers every packet "
                            "that can match this later rule. The "
                            "later rule may never affect processing."
                        ),
                        evidence=(
                            f"Earlier covering rule: {earlier.raw}\n"
                            f"Shadowed rule: {later.raw}"
                        ),
                        recommendation=(
                            "Reorder the rules or narrow the earlier "
                            "match so the intended rule can execute."
                        ),
                        line_number=later.line_number,
                    )
                )

    if (
        forward_rules
        and not any(
            str(
                prop(entry, "action", "")
            ).lower() in {"drop", "reject"}
            and _is_broad_rule(entry)
            for entry in forward_rules
        )
    ):
        findings.append(
            FindingResult(
                rule_id="FW-011",
                title=(
                    "No default forward-chain drop rule"
                ),
                category="Firewall",
                severity="high",
                description=(
                    "The forward chain contains rules but does not "
                    "end with an unrestricted drop or reject rule."
                ),
                evidence=(
                    "No matching enabled forward-chain rule "
                    "was found."
                ),
                recommendation=(
                    "Add an explicit default-deny rule after all "
                    "required forwarding exceptions."
                ),
                suggested_command=(
                    "/ip firewall filter add chain=forward "
                    "action=drop "
                    "comment=\"NetAudit default forward drop\""
                ),
            )
        )

    for entry in forward_rules:
        if (
            str(prop(entry, "action", "")).lower()
            == "accept"
            and _is_broad_rule(entry)
        ):
            findings.append(
                FindingResult(
                    rule_id="FW-017",
                    title="Broad forward accept rule",
                    category="Firewall",
                    severity="high",
                    description=(
                        "This rule permits unrestricted routed "
                        "traffic through the router."
                    ),
                    evidence=entry.raw,
                    recommendation=(
                        "Restrict forwarding by source, destination, "
                        "interface, connection state, or required "
                        "service."
                    ),
                    line_number=entry.line_number,
                )
            )

    for chain_name, chain_rules in rules_by_chain.items():
        broad_terminal_index = next(
            (
                index
                for index, entry in enumerate(chain_rules)
                if (
                    str(
                        prop(entry, "action", "")
                    ).lower()
                    in FIREWALL_TERMINAL_ACTIONS
                    and _is_broad_rule(entry)
                )
            ),
            None,
        )

        stateful_index = next(
            (
                index
                for index, entry in enumerate(chain_rules)
                if _is_stateful_accept(entry)
            ),
            None,
        )

        invalid_drop_index = next(
            (
                index
                for index, entry in enumerate(chain_rules)
                if _is_invalid_drop(entry)
            ),
            None,
        )

        if (
            broad_terminal_index is not None
            and stateful_index is not None
            and stateful_index > broad_terminal_index
        ):
            findings.append(
                FindingResult(
                    rule_id="FW-012",
                    title=(
                        "Established and related accept rule is "
                        "placed too late"
                    ),
                    category="Firewall",
                    severity="medium",
                    description=(
                        "A broad terminal rule appears before the "
                        "stateful accept rule in the same chain."
                    ),
                    evidence=(
                        f"Chain: {chain_name}\n"
                        f"Earlier terminal rule: "
                        f"{chain_rules[broad_terminal_index].raw}\n"
                        f"Late stateful rule: "
                        f"{chain_rules[stateful_index].raw}"
                    ),
                    recommendation=(
                        "Move the established and related accept "
                        "rule near the beginning of the chain."
                    ),
                    line_number=(
                        chain_rules[
                            stateful_index
                        ].line_number
                    ),
                )
            )

        if (
            broad_terminal_index is not None
            and invalid_drop_index is not None
            and invalid_drop_index > broad_terminal_index
        ):
            findings.append(
                FindingResult(
                    rule_id="FW-013",
                    title=(
                        "Invalid-connection drop rule is placed "
                        "too late"
                    ),
                    category="Firewall",
                    severity="medium",
                    description=(
                        "A broad terminal rule appears before the "
                        "invalid-state drop rule."
                    ),
                    evidence=(
                        f"Chain: {chain_name}\n"
                        f"Earlier terminal rule: "
                        f"{chain_rules[broad_terminal_index].raw}\n"
                        f"Late invalid drop: "
                        f"{chain_rules[invalid_drop_index].raw}"
                    ),
                    recommendation=(
                        "Move the invalid-connection drop rule near "
                        "the beginning of the chain."
                    ),
                    line_number=(
                        chain_rules[
                            invalid_drop_index
                        ].line_number
                    ),
                )
            )

    for index, entry in enumerate(forward_rules):
        if (
            str(prop(entry, "action", "")).lower()
            != "fasttrack-connection"
        ):
            continue

        has_follow_up_accept = any(
            _is_stateful_accept(candidate)
            for candidate in forward_rules[
                index + 1:
            ]
        )

        if not has_follow_up_accept:
            findings.append(
                FindingResult(
                    rule_id="FW-014",
                    title=(
                        "FastTrack rule has no stateful follow-up "
                        "accept rule"
                    ),
                    category="Firewall",
                    severity="medium",
                    description=(
                        "FastTrack normally requires a later accept "
                        "rule for established and related traffic "
                        "that is not FastTracked."
                    ),
                    evidence=entry.raw,
                    recommendation=(
                        "Add an established and related accept rule "
                        "directly after the FastTrack rule."
                    ),
                    suggested_command=(
                        "/ip firewall filter add chain=forward "
                        "action=accept "
                        "connection-state=established,related"
                    ),
                    line_number=entry.line_number,
                )
            )

    for entry in enabled_rules:
        for property_name in {
            "src-port",
            "dst-port",
            "port",
        }:
            value = prop(entry, property_name)

            if value is None or value == "":
                continue

            try:
                _parse_firewall_port_ranges(value)
            except (TypeError, ValueError) as exc:
                findings.append(
                    FindingResult(
                        rule_id="FW-015",
                        title=(
                            "Invalid firewall port expression"
                        ),
                        category="Firewall",
                        severity="high",
                        description=(
                            f"The {property_name} value cannot be "
                            f"validated: {exc}."
                        ),
                        evidence=entry.raw,
                        recommendation=(
                            "Use numeric ports from 1 to 65535 and "
                            "write ranges with the lower port first."
                        ),
                        line_number=entry.line_number,
                    )
                )

        for property_name in {
            "src-address",
            "dst-address",
        }:
            value = prop(entry, property_name)

            if value is None or value == "":
                continue

            address_text = str(value).strip()

            if address_text.startswith("!"):
                address_text = address_text[1:].strip()

            try:
                ip_network(
                    address_text,
                    strict=False,
                )
            except ValueError:
                findings.append(
                    FindingResult(
                        rule_id="FW-015",
                        title=(
                            "Invalid firewall address expression"
                        ),
                        category="Firewall",
                        severity="high",
                        description=(
                            f"The {property_name} value is not a "
                            "valid IP address or network."
                        ),
                        evidence=entry.raw,
                        recommendation=(
                            "Correct the address and use valid CIDR "
                            "notation where a network is required."
                        ),
                        line_number=entry.line_number,
                    )
                )

    for entry in input_rules:
        if (
            str(prop(entry, "action", "")).lower()
            != "accept"
        ):
            continue

        protocol = str(
            prop(entry, "protocol", "")
        ).strip().lower()

        if protocol not in {"", "tcp"}:
            continue

        management_ports = _management_ports_in_rule(
            entry
        )

        if not management_ports:
            continue

        incoming_interface = str(
            prop(entry, "in-interface", "")
        ).strip()

        incoming_list = str(
            prop(entry, "in-interface-list", "")
        ).strip()

        explicitly_from_wan = (
            incoming_list.upper() == "WAN"
            or incoming_interface.lower()
            in {
                "wan",
                "ether1-wan",
            }
        )

        unrestricted_ingress = (
            not incoming_interface
            and not incoming_list
        )

        if not _is_unrestricted_source(entry):
            continue

        if (
            not explicitly_from_wan
            and not unrestricted_ingress
        ):
            continue

        service_description = ", ".join(
            f"{name} ({port})"
            for port, name in management_ports
        )

        findings.append(
            FindingResult(
                rule_id="FW-016",
                title=(
                    "Router management ports are exposed"
                ),
                category="Firewall",
                severity="critical",
                description=(
                    "An input-chain accept rule exposes one or more "
                    "router management services without a trusted "
                    "source restriction."
                ),
                evidence=(
                    f"{entry.raw}\n"
                    f"Exposed services: "
                    f"{service_description}"
                ),
                recommendation=(
                    "Restrict management access to a trusted "
                    "administrator subnet and block access from WAN."
                ),
                line_number=entry.line_number,
            )
        )

    return findings

NAT_NON_MATCH_PROPERTIES = {
    "_positional",
    "action",
    "chain",
    "comment",
    "disabled",
    "log",
    "log-prefix",
    "place-before",
    "copy-from",
    "to-addresses",
    "to-ports",
}


def _normalize_nat_value(value: Any) -> str:
    if value in {None, ""}:
        return ""

    return str(value).strip().lower()


def _normalize_nat_port_value(value: Any) -> str:
    if value in {None, ""}:
        return ""

    try:
        ranges = _parse_firewall_port_ranges(value)
    except (TypeError, ValueError):
        return str(value).strip().lower()

    return ",".join(
        (
            str(start)
            if start == end
            else f"{start}-{end}"
        )
        for start, end in ranges
    )


def _nat_match_signature(entry: ConfigEntry) -> tuple:
    """Build a signature from NAT packet-matching properties."""

    normalized_properties = []

    for key, value in entry.properties.items():
        if key in NAT_NON_MATCH_PROPERTIES:
            continue

        if value in {None, ""}:
            continue

        if key in {
            "src-port",
            "dst-port",
            "port",
        }:
            normalized_value = _normalize_nat_port_value(
                value
            )
        elif key in {
            "connection-state",
            "connection-nat-state",
        }:
            normalized_value = ",".join(
                sorted(_normalized_csv_set(value))
            )
        else:
            normalized_value = _normalize_nat_value(
                value
            )

        normalized_properties.append(
            (key, normalized_value)
        )

    return (
        _normalize_nat_value(
            prop(entry, "chain")
        ),
        tuple(sorted(normalized_properties)),
    )


def _nat_translation_signature(
    entry: ConfigEntry,
) -> tuple:
    """Build a signature for the action and translation target."""

    return (
        _normalize_nat_value(
            prop(entry, "action")
        ),
        _normalize_nat_value(
            prop(entry, "to-addresses")
        ),
        _normalize_nat_port_value(
            prop(entry, "to-ports")
        ),
    )


def _parse_nat_address_range(
    value: Any,
) -> list[tuple[Any, Any]]:
    """Parse comma-separated NAT addresses and address ranges."""

    if value in {None, ""}:
        return []

    ranges = []

    for raw_item in str(value).split(","):
        item = raw_item.strip()

        if not item:
            continue

        if "-" in item:
            start_text, end_text = [
                part.strip()
                for part in item.split("-", 1)
            ]

            start = ip_address(start_text)
            end = ip_address(end_text)

            if start.version != end.version:
                raise ValueError(
                    "Translated address range mixes IP versions"
                )

            if int(start) > int(end):
                raise ValueError(
                    "Translated address range is reversed"
                )
        else:
            start = ip_address(item)
            end = start

        ranges.append((start, end))

    if not ranges:
        raise ValueError(
            "Translated address value is empty"
        )

    return ranges


def _nat_rule_has_unrestricted_ingress(
    entry: ConfigEntry,
) -> bool:
    incoming_interface = str(
        prop(entry, "in-interface", "")
    ).strip()

    incoming_interface_list = str(
        prop(entry, "in-interface-list", "")
    ).strip()

    return (
        not incoming_interface
        and not incoming_interface_list
    )


def _nat_rule_is_wan_facing(
    entry: ConfigEntry,
) -> bool:
    incoming_interface = str(
        prop(entry, "in-interface", "")
    ).strip().lower()

    incoming_interface_list = str(
        prop(entry, "in-interface-list", "")
    ).strip().upper()

    return (
        incoming_interface_list == "WAN"
        or incoming_interface
        in {
            "wan",
            "ether1-wan",
            "pppoe-out1",
        }
    )


def _nat_management_ports(
    entry: ConfigEntry,
) -> list[tuple[int, str]]:
    raw_ports = prop(entry, "dst-port")

    if raw_ports in {None, ""}:
        return []

    try:
        port_ranges = _parse_firewall_port_ranges(
            raw_ports
        )
    except (TypeError, ValueError):
        return []

    results = []

    for port, service_name in (
        FIREWALL_MANAGEMENT_PORTS.items()
    ):
        if any(
            start <= port <= end
            for start, end in port_ranges
        ):
            results.append((port, service_name))

    return results


def _firewall_protects_dstnat(
    nat_entry: ConfigEntry,
    firewall_entry: ConfigEntry,
) -> bool:
    """Check whether a forward rule permits protected dstnat traffic."""

    if not is_enabled(firewall_entry):
        return False

    if (
        str(
            prop(firewall_entry, "chain", "")
        ).lower()
        != "forward"
    ):
        return False

    if (
        str(
            prop(firewall_entry, "action", "")
        ).lower()
        != "accept"
    ):
        return False

    nat_states = _normalized_csv_set(
        prop(
            firewall_entry,
            "connection-nat-state",
        )
    )

    if "dstnat" in nat_states:
        return True

    translated_address = str(
        prop(nat_entry, "to-addresses", "")
    ).strip()

    firewall_destination = str(
        prop(
            firewall_entry,
            "dst-address",
            "",
        )
    ).strip()

    if (
        translated_address
        and firewall_destination
    ):
        try:
            translated_ranges = (
                _parse_nat_address_range(
                    translated_address
                )
            )

            firewall_network = ip_network(
                firewall_destination,
                strict=False,
            )
        except ValueError:
            return False

        address_matches = all(
            start.version == firewall_network.version
            and start in firewall_network
            and end in firewall_network
            for start, end in translated_ranges
        )

        if not address_matches:
            return False

        nat_to_ports = prop(
            nat_entry,
            "to-ports",
        ) or prop(
            nat_entry,
            "dst-port",
        )

        firewall_ports = prop(
            firewall_entry,
            "dst-port",
        )

        return _port_ranges_cover(
            firewall_ports,
            nat_to_ports,
        )

    return False


def nat_rules(
    entries: list[ConfigEntry],
) -> list[FindingResult]:
    findings: list[FindingResult] = []

    nat_entries = [
        entry
        for entry in entries_for(
            entries,
            "/ip firewall nat",
        )
        if entry.command == "add"
        and is_enabled(entry)
    ]

    firewall_entries = [
        entry
        for entry in entries_for(
            entries,
            "/ip firewall filter",
        )
        if entry.command == "add"
        and is_enabled(entry)
    ]

    masquerade_signatures = {}
    destination_match_signatures = {}
    destination_complete_signatures = {}

    for entry in nat_entries:
        chain = str(
            prop(entry, "chain", "")
        ).strip().lower()

        action = str(
            prop(entry, "action", "")
        ).strip().lower()

        if not action:
            findings.append(
                FindingResult(
                    rule_id="NAT-005",
                    title="NAT rule has no action",
                    category="NAT",
                    severity="high",
                    description=(
                        "An enabled NAT rule does not define what "
                        "RouterOS should do when the rule matches."
                    ),
                    evidence=entry.raw,
                    recommendation=(
                        "Set an appropriate NAT action, such as "
                        "masquerade, src-nat, dst-nat, redirect, "
                        "or netmap."
                    ),
                    line_number=entry.line_number,
                )
            )
            continue

        if chain not in {
            "srcnat",
            "dstnat",
        }:
            findings.append(
                FindingResult(
                    rule_id="NAT-005",
                    title="Invalid NAT chain",
                    category="NAT",
                    severity="high",
                    description=(
                        "The enabled NAT rule does not use the "
                        "srcnat or dstnat chain."
                    ),
                    evidence=entry.raw,
                    recommendation=(
                        "Move the rule to the correct RouterOS NAT "
                        "chain."
                    ),
                    line_number=entry.line_number,
                )
            )

        translated_addresses = prop(
            entry,
            "to-addresses",
        )

        translated_ports = prop(
            entry,
            "to-ports",
        )

        actions_requiring_address = {
            "src-nat",
            "dst-nat",
            "netmap",
        }

        if (
            action in actions_requiring_address
            and translated_addresses in {None, ""}
        ):
            findings.append(
                FindingResult(
                    rule_id="NAT-012",
                    title=(
                        "NAT translation target is missing"
                    ),
                    category="NAT",
                    severity="high",
                    description=(
                        "This NAT action requires a translated "
                        "address, but no to-addresses value is "
                        "configured."
                    ),
                    evidence=entry.raw,
                    recommendation=(
                        "Configure a valid translated address or "
                        "change the rule action."
                    ),
                    line_number=entry.line_number,
                )
            )

        if translated_addresses not in {
            None,
            "",
        }:
            try:
                _parse_nat_address_range(
                    translated_addresses
                )
            except ValueError as exc:
                findings.append(
                    FindingResult(
                        rule_id="NAT-006",
                        title=(
                            "Invalid translated NAT address"
                        ),
                        category="NAT",
                        severity="high",
                        description=(
                            f"The to-addresses value cannot be "
                            f"validated: {exc}."
                        ),
                        evidence=entry.raw,
                        recommendation=(
                            "Use a valid IP address or inclusive "
                            "address range."
                        ),
                        line_number=entry.line_number,
                    )
                )

        if translated_ports not in {
            None,
            "",
        }:
            try:
                _parse_firewall_port_ranges(
                    translated_ports
                )
            except (TypeError, ValueError) as exc:
                findings.append(
                    FindingResult(
                        rule_id="NAT-007",
                        title=(
                            "Invalid translated NAT port"
                        ),
                        category="NAT",
                        severity="high",
                        description=(
                            f"The to-ports value cannot be "
                            f"validated: {exc}."
                        ),
                        evidence=entry.raw,
                        recommendation=(
                            "Use numeric ports from 1 to 65535 "
                            "and write ranges with the lower port "
                            "first."
                        ),
                        line_number=entry.line_number,
                    )
                )

        if (
            action in {
                "dst-nat",
                "redirect",
                "netmap",
            }
            and prop(entry, "dst-port")
            not in {
                None,
                "",
            }
        ):
            try:
                _parse_firewall_port_ranges(
                    prop(entry, "dst-port")
                )
            except (TypeError, ValueError) as exc:
                findings.append(
                    FindingResult(
                        rule_id="NAT-007",
                        title=(
                            "Invalid destination NAT port"
                        ),
                        category="NAT",
                        severity="high",
                        description=(
                            f"The dst-port value cannot be "
                            f"validated: {exc}."
                        ),
                        evidence=entry.raw,
                        recommendation=(
                            "Use a valid numeric destination port "
                            "or port range."
                        ),
                        line_number=entry.line_number,
                    )
                )

        if (
            chain == "srcnat"
            and action == "masquerade"
        ):
            masquerade_signature = (
                _normalize_nat_value(
                    prop(entry, "out-interface")
                ),
                _normalize_nat_value(
                    prop(
                        entry,
                        "out-interface-list",
                    )
                ),
                _normalize_nat_value(
                    prop(entry, "src-address")
                ),
                _normalize_nat_value(
                    prop(
                        entry,
                        "src-address-list",
                    )
                ),
            )

            if (
                masquerade_signature
                in masquerade_signatures
            ):
                first_entry = (
                    masquerade_signatures[
                        masquerade_signature
                    ]
                )

                findings.append(
                    FindingResult(
                        rule_id="NAT-001",
                        title=(
                            "Duplicate masquerade rule"
                        ),
                        category="NAT",
                        severity="medium",
                        description=(
                            "The same masquerade match appears "
                            "more than once."
                        ),
                        evidence=(
                            f"First: {first_entry.raw}\n"
                            f"Duplicate: {entry.raw}"
                        ),
                        recommendation=(
                            "Remove the redundant masquerade rule "
                            "unless the duplication is intentional "
                            "and documented."
                        ),
                        line_number=entry.line_number,
                    )
                )
            else:
                masquerade_signatures[
                    masquerade_signature
                ] = entry

        if chain != "dstnat":
            continue

        match_signature = _nat_match_signature(
            entry
        )

        translation_signature = (
            _nat_translation_signature(entry)
        )

        complete_signature = (
            match_signature,
            translation_signature,
        )

        if (
            complete_signature
            in destination_complete_signatures
        ):
            first_entry = (
                destination_complete_signatures[
                    complete_signature
                ]
            )

            findings.append(
                FindingResult(
                    rule_id="NAT-008",
                    title=(
                        "Exact duplicate destination NAT rule"
                    ),
                    category="NAT",
                    severity="medium",
                    description=(
                        "The same port-forward match and "
                        "translation target appear more than once."
                    ),
                    evidence=(
                        f"First: {first_entry.raw}\n"
                        f"Duplicate: {entry.raw}"
                    ),
                    recommendation=(
                        "Remove the duplicate destination NAT rule."
                    ),
                    line_number=entry.line_number,
                )
            )
        else:
            destination_complete_signatures[
                complete_signature
            ] = entry

        if (
            match_signature
            in destination_match_signatures
        ):
            first_entry = (
                destination_match_signatures[
                    match_signature
                ]
            )

            first_translation = (
                _nat_translation_signature(
                    first_entry
                )
            )

            if (
                first_translation
                != translation_signature
            ):
                findings.append(
                    FindingResult(
                        rule_id="NAT-009",
                        title=(
                            "Conflicting destination NAT rules"
                        ),
                        category="NAT",
                        severity="high",
                        description=(
                            "Two destination NAT rules use the same "
                            "matching conditions but send traffic to "
                            "different targets."
                        ),
                        evidence=(
                            f"First: {first_entry.raw}\n"
                            f"Conflict: {entry.raw}"
                        ),
                        recommendation=(
                            "Use unique public ports or matching "
                            "conditions for each translation target."
                        ),
                        line_number=entry.line_number,
                    )
                )
        else:
            destination_match_signatures[
                match_signature
            ] = entry

        broad_destination_rule = (
            not prop(entry, "dst-address")
            and not prop(
                entry,
                "dst-address-list",
            )
            and not prop(entry, "dst-port")
            and not prop(entry, "protocol")
            and _nat_rule_has_unrestricted_ingress(
                entry
            )
        )

        if broad_destination_rule:
            findings.append(
                FindingResult(
                    rule_id="NAT-002",
                    title=(
                        "Broad destination NAT exposure"
                    ),
                    category="NAT",
                    severity="critical",
                    description=(
                        "The destination NAT rule can match a very "
                        "large range of incoming traffic because it "
                        "lacks destination, protocol, port, and "
                        "interface restrictions."
                    ),
                    evidence=entry.raw,
                    recommendation=(
                        "Restrict the rule to a required public "
                        "address, protocol, port, and WAN interface."
                    ),
                    line_number=entry.line_number,
                )
            )

        management_ports = _nat_management_ports(
            entry
        )

        unrestricted_source = (
            _is_unrestricted_source(entry)
        )

        exposed_ingress = (
            _nat_rule_is_wan_facing(entry)
            or _nat_rule_has_unrestricted_ingress(
                entry
            )
        )

        if (
            management_ports
            and unrestricted_source
            and exposed_ingress
        ):
            exposed_services = ", ".join(
                f"{name} ({port})"
                for port, name
                in management_ports
            )

            findings.append(
                FindingResult(
                    rule_id="NAT-010",
                    title=(
                        "Sensitive management port is publicly "
                        "forwarded"
                    ),
                    category="NAT",
                    severity="critical",
                    description=(
                        "The destination NAT rule exposes a common "
                        "management service without a trusted source "
                        "restriction."
                    ),
                    evidence=(
                        f"{entry.raw}\n"
                        f"Exposed services: "
                        f"{exposed_services}"
                    ),
                    recommendation=(
                        "Avoid forwarding router or server "
                        "management ports publicly. Restrict access "
                        "to a trusted source or use a VPN."
                    ),
                    line_number=entry.line_number,
                )
            )

        has_firewall_protection = any(
            _firewall_protects_dstnat(
                entry,
                firewall_entry,
            )
            for firewall_entry
            in firewall_entries
        )

        if not has_firewall_protection:
            findings.append(
                FindingResult(
                    rule_id="NAT-011",
                    title=(
                        "Destination NAT has no matching forward "
                        "protection"
                    ),
                    category="NAT",
                    severity="high",
                    description=(
                        "No enabled forward-chain accept rule was "
                        "found for destination-NAT traffic or the "
                        "translated destination."
                    ),
                    evidence=entry.raw,
                    recommendation=(
                        "Add a restricted forward-chain rule using "
                        "connection-nat-state=dstnat or the exact "
                        "translated destination and service."
                    ),
                    suggested_command=(
                        "/ip firewall filter add chain=forward "
                        "action=accept "
                        "connection-nat-state=dstnat "
                        "comment=\"Allow protected destination NAT\""
                    ),
                    line_number=entry.line_number,
                )
            )

    return findings

BROAD_INTERFACE_LISTS = {
    "all",
    "dynamic",
    "static",
    "!dynamic",
    "wan",
}


def _routeros_boolean(
    value: Any,
    default: bool = False,
) -> bool:
    """Convert common RouterOS boolean values safely."""

    if isinstance(value, bool):
        return value

    if value in {None, ""}:
        return default

    normalized = str(value).strip().lower()

    if normalized in {
        "yes",
        "true",
        "on",
        "enabled",
        "1",
    }:
        return True

    if normalized in {
        "no",
        "false",
        "off",
        "disabled",
        "0",
    }:
        return False

    return default


def _latest_section_entry(
    entries: list[ConfigEntry],
    section: str,
) -> ConfigEntry | None:
    """Return the final enabled setting entry in a singleton section."""

    matching_entries = [
        entry
        for entry in entries_for(entries, section)
        if entry.command in {"set", "add"}
        and is_enabled(entry)
    ]

    if not matching_entries:
        return None

    return matching_entries[-1]


def _interface_list_is_broad(
    value: Any,
) -> bool:
    if value in {None, ""}:
        return True

    normalized = str(value).strip().lower()

    return normalized in BROAD_INTERFACE_LISTS


def _firewall_exposes_dns(
    entries: list[ConfigEntry],
) -> bool:
    """Detect unrestricted WAN or interface-free DNS accept rules."""

    for entry in entries_for(
        entries,
        "/ip firewall filter",
    ):
        if (
            entry.command != "add"
            or not is_enabled(entry)
        ):
            continue

        if (
            str(prop(entry, "chain", "")).lower()
            != "input"
        ):
            continue

        if (
            str(prop(entry, "action", "")).lower()
            != "accept"
        ):
            continue

        protocol = str(
            prop(entry, "protocol", "")
        ).strip().lower()

        if protocol not in {
            "",
            "tcp",
            "udp",
        }:
            continue

        raw_ports = prop(entry, "dst-port")

        if raw_ports in {None, ""}:
            continue

        try:
            port_ranges = _parse_firewall_port_ranges(
                raw_ports
            )
        except (TypeError, ValueError):
            continue

        includes_dns = any(
            start <= 53 <= end
            for start, end in port_ranges
        )

        if not includes_dns:
            continue

        incoming_interface = str(
            prop(entry, "in-interface", "")
        ).strip().lower()

        incoming_interface_list = str(
            prop(
                entry,
                "in-interface-list",
                "",
            )
        ).strip().lower()

        exposed_ingress = (
            not incoming_interface
            and not incoming_interface_list
        ) or (
            incoming_interface_list == "wan"
        ) or (
            incoming_interface
            in {
                "wan",
                "ether1-wan",
                "pppoe-out1",
            }
        )

        if (
            exposed_ingress
            and _is_unrestricted_source(entry)
        ):
            return True

    return False


def additional_security_rules(
    entries: list[ConfigEntry],
) -> list[FindingResult]:
    """Audit optional RouterOS services and Layer-2 management access."""

    findings: list[FindingResult] = []

    dns_entry = _latest_section_entry(
        entries,
        "/ip dns",
    )

    if (
        dns_entry
        and _routeros_boolean(
            prop(
                dns_entry,
                "allow-remote-requests",
            )
        )
        and _firewall_exposes_dns(entries)
    ):
        findings.append(
            FindingResult(
                rule_id="SEC-001",
                title=(
                    "Remote DNS requests are exposed"
                ),
                category="Security services",
                severity="critical",
                description=(
                    "The router accepts remote DNS requests and an "
                    "input firewall rule exposes TCP or UDP port 53 "
                    "without a trusted source restriction."
                ),
                evidence=dns_entry.raw,
                recommendation=(
                    "Allow DNS only from trusted LAN networks and "
                    "block TCP and UDP port 53 from WAN."
                ),
                suggested_command=(
                    "/ip firewall filter add chain=input "
                    "action=drop in-interface-list=WAN "
                    "protocol=udp dst-port=53"
                ),
                line_number=dns_entry.line_number,
            )
        )

    mac_telnet_entry = _latest_section_entry(
        entries,
        "/tool mac-server",
    )

    if mac_telnet_entry:
        allowed_list = prop(
            mac_telnet_entry,
            "allowed-interface-list",
        )

        if _interface_list_is_broad(allowed_list):
            findings.append(
                FindingResult(
                    rule_id="SEC-002",
                    title=(
                        "MAC Telnet is available on broad interfaces"
                    ),
                    category="Layer 2 management",
                    severity="high",
                    description=(
                        "MAC Telnet is not limited to a trusted LAN "
                        "interface list."
                    ),
                    evidence=mac_telnet_entry.raw,
                    recommendation=(
                        "Restrict MAC Telnet to a trusted LAN list "
                        "or disable it."
                    ),
                    suggested_command=(
                        "/tool mac-server set "
                        "allowed-interface-list=none"
                    ),
                    line_number=mac_telnet_entry.line_number,
                )
            )

    mac_winbox_entry = _latest_section_entry(
        entries,
        "/tool mac-server mac-winbox",
    )

    if mac_winbox_entry:
        allowed_list = prop(
            mac_winbox_entry,
            "allowed-interface-list",
        )

        if _interface_list_is_broad(allowed_list):
            findings.append(
                FindingResult(
                    rule_id="SEC-003",
                    title=(
                        "MAC WinBox is available on broad interfaces"
                    ),
                    category="Layer 2 management",
                    severity="high",
                    description=(
                        "MAC WinBox is not limited to a trusted LAN "
                        "interface list."
                    ),
                    evidence=mac_winbox_entry.raw,
                    recommendation=(
                        "Restrict MAC WinBox to a trusted LAN list "
                        "or disable it."
                    ),
                    suggested_command=(
                        "/tool mac-server mac-winbox set "
                        "allowed-interface-list=none"
                    ),
                    line_number=mac_winbox_entry.line_number,
                )
            )

    mac_ping_entry = _latest_section_entry(
        entries,
        "/tool mac-server ping",
    )

    if (
        mac_ping_entry
        and _routeros_boolean(
            prop(mac_ping_entry, "enabled")
        )
    ):
        findings.append(
            FindingResult(
                rule_id="SEC-004",
                title="MAC Ping server is enabled",
                category="Layer 2 management",
                severity="low",
                description=(
                    "Other hosts in the same Layer-2 domain can "
                    "probe the router by MAC address."
                ),
                evidence=mac_ping_entry.raw,
                recommendation=(
                    "Disable MAC Ping when it is not required for "
                    "diagnostics."
                ),
                suggested_command=(
                    "/tool mac-server ping set enabled=no"
                ),
                line_number=mac_ping_entry.line_number,
            )
        )

    discovery_entry = _latest_section_entry(
        entries,
        "/ip neighbor discovery-settings",
    )

    if discovery_entry:
        discovery_list = prop(
            discovery_entry,
            "discover-interface-list",
        )

        if _interface_list_is_broad(
            discovery_list
        ):
            findings.append(
                FindingResult(
                    rule_id="SEC-005",
                    title=(
                        "Neighbor discovery uses a broad interface list"
                    ),
                    category="Layer 2 management",
                    severity="medium",
                    description=(
                        "Router identity, platform, interface, and "
                        "address information may be advertised on "
                        "untrusted interfaces."
                    ),
                    evidence=discovery_entry.raw,
                    recommendation=(
                        "Limit neighbor discovery to a trusted LAN "
                        "interface list."
                    ),
                    suggested_command=(
                        "/ip neighbor discovery-settings set "
                        "discover-interface-list=LAN"
                    ),
                    line_number=discovery_entry.line_number,
                )
            )

    romon_entry = _latest_section_entry(
        entries,
        "/tool romon",
    )

    if (
        romon_entry
        and _routeros_boolean(
            prop(romon_entry, "enabled")
        )
    ):
        romon_ports = [
            entry
            for entry in entries_for(
                entries,
                "/tool romon port",
            )
            if entry.command in {"add", "set"}
            and is_enabled(entry)
        ]

        has_broad_participation = (
            not romon_ports
            or any(
                str(
                    prop(entry, "interface", "all")
                ).strip().lower()
                == "all"
                and not _routeros_boolean(
                    prop(entry, "forbid"),
                    default=False,
                )
                for entry in romon_ports
            )
        )

        if has_broad_participation:
            findings.append(
                FindingResult(
                    rule_id="SEC-006",
                    title=(
                        "RoMON is enabled on broad interfaces"
                    ),
                    category="Layer 2 management",
                    severity="high",
                    description=(
                        "RoMON is enabled and no restrictive port "
                        "policy was found. Its default participation "
                        "can include all interfaces."
                    ),
                    evidence=romon_entry.raw,
                    recommendation=(
                        "Disable RoMON when unused or explicitly "
                        "restrict participating interfaces."
                    ),
                    suggested_command=(
                        "/tool romon set enabled=no"
                    ),
                    line_number=romon_entry.line_number,
                )
            )

    bandwidth_entry = _latest_section_entry(
        entries,
        "/tool bandwidth-server",
    )

    if (
        bandwidth_entry
        and _routeros_boolean(
            prop(
                bandwidth_entry,
                "enabled",
            ),
            default=True,
        )
        and not _routeros_boolean(
            prop(
                bandwidth_entry,
                "authenticate",
            ),
            default=True,
        )
    ):
        findings.append(
            FindingResult(
                rule_id="SEC-007",
                title=(
                    "Bandwidth-test server allows "
                    "unauthenticated clients"
                ),
                category="Security services",
                severity="high",
                description=(
                    "Remote clients can initiate bandwidth tests "
                    "without RouterOS authentication."
                ),
                evidence=bandwidth_entry.raw,
                recommendation=(
                    "Require authentication or disable the "
                    "bandwidth-test server when unused."
                ),
                suggested_command=(
                    "/tool bandwidth-server set "
                    "authenticate=yes"
                ),
                line_number=bandwidth_entry.line_number,
            )
        )

    proxy_entry = _latest_section_entry(
        entries,
        "/ip proxy",
    )

    if (
        proxy_entry
        and _routeros_boolean(
            prop(proxy_entry, "enabled")
        )
    ):
        proxy_access_rules = [
            entry
            for entry in entries_for(
                entries,
                "/ip proxy access",
            )
            if entry.command == "add"
            and is_enabled(entry)
        ]

        has_restrictive_rule = any(
            str(
                prop(entry, "action", "")
            ).strip().lower()
            == "deny"
            for entry in proxy_access_rules
        )

        if not has_restrictive_rule:
            findings.append(
                FindingResult(
                    rule_id="SEC-008",
                    title=(
                        "Web proxy is enabled without an evident "
                        "deny policy"
                    ),
                    category="Security services",
                    severity="high",
                    description=(
                        "The RouterOS web proxy is enabled, but no "
                        "enabled deny rule was found in the exported "
                        "proxy access list."
                    ),
                    evidence=proxy_entry.raw,
                    recommendation=(
                        "Disable the proxy when unused or define a "
                        "restricted source and access policy."
                    ),
                    suggested_command=(
                        "/ip proxy set enabled=no"
                    ),
                    line_number=proxy_entry.line_number,
                )
            )

    socks_entry = _latest_section_entry(
        entries,
        "/ip socks",
    )

    if (
        socks_entry
        and _routeros_boolean(
            prop(socks_entry, "enabled")
        )
    ):
        socks_access_rules = [
            entry
            for entry in entries_for(
                entries,
                "/ip socks access",
            )
            if entry.command == "add"
            and is_enabled(entry)
        ]

        has_restrictive_rule = any(
            str(
                prop(entry, "action", "")
            ).strip().lower()
            == "deny"
            for entry in socks_access_rules
        )

        if not has_restrictive_rule:
            findings.append(
                FindingResult(
                    rule_id="SEC-009",
                    title=(
                        "SOCKS proxy is enabled without an evident "
                        "deny policy"
                    ),
                    category="Security services",
                    severity="critical",
                    description=(
                        "The router can relay TCP application "
                        "traffic, but no enabled deny rule was found "
                        "in the exported SOCKS access list."
                    ),
                    evidence=socks_entry.raw,
                    recommendation=(
                        "Disable SOCKS when unused or restrict it to "
                        "explicit trusted sources and destinations."
                    ),
                    suggested_command=(
                        "/ip socks set enabled=no"
                    ),
                    line_number=socks_entry.line_number,
                )
            )

    snmp_entry = _latest_section_entry(
        entries,
        "/snmp",
    )

    snmp_enabled = bool(
        snmp_entry
        and _routeros_boolean(
            prop(snmp_entry, "enabled")
        )
    )

    if snmp_enabled:
        communities = [
            entry
            for entry in entries_for(
                entries,
                "/snmp community",
            )
            if entry.command in {"add", "set"}
            and is_enabled(entry)
        ]

        for community in communities:
            community_name = str(
                prop(community, "name", "")
            ).strip()

            allowed_address = str(
                prop(
                    community,
                    "address",
                    prop(
                        community,
                        "addresses",
                        "0.0.0.0/0",
                    ),
                )
            ).strip().lower()

            security = str(
                prop(
                    community,
                    "security",
                    "none",
                )
            ).strip().lower()

            write_access = _routeros_boolean(
                prop(
                    community,
                    "write-access",
                )
            )

            unrestricted = allowed_address in {
                "",
                "0.0.0.0/0",
                "::/0",
                "0.0.0.0/0,::/0",
            }

            insecure_name = (
                community_name.lower() == "public"
            )

            if (
                security == "none"
                and (
                    unrestricted
                    or insecure_name
                )
            ):
                findings.append(
                    FindingResult(
                        rule_id="SEC-010",
                        title=(
                            "Insecure SNMP community configuration"
                        ),
                        category="Security services",
                        severity="high",
                        description=(
                            "SNMP is enabled with an unauthenticated "
                            "community that is public, unrestricted, "
                            "or both."
                        ),
                        evidence=community.raw,
                        recommendation=(
                            "Use SNMPv3 security and restrict the "
                            "community to exact monitoring hosts."
                        ),
                        line_number=community.line_number,
                    )
                )

            if write_access:
                findings.append(
                    FindingResult(
                        rule_id="SEC-011",
                        title=(
                            "SNMP community has write access"
                        ),
                        category="Security services",
                        severity="critical",
                        description=(
                            "The community can modify supported "
                            "RouterOS objects through SNMP."
                        ),
                        evidence=community.raw,
                        recommendation=(
                            "Disable SNMP write access unless it is "
                            "strictly required and protected with "
                            "SNMPv3 and source restrictions."
                        ),
                        suggested_command=(
                            "/snmp community set "
                            "[find name=\""
                            f"{community_name}"
                            "\"] write-access=no"
                        ),
                        line_number=community.line_number,
                    )
                )

    return findings


class RuleHelpers:
    """Static utility helpers shared across all domain rule checkers."""

    @staticmethod
    def prop(entry: ConfigEntry, key: str, default=None):
        return entry.properties.get(key, default)

    @staticmethod
    def positional(entry: ConfigEntry, index=0, default=""):
        values = entry.properties.get("_positional", [])
        return values[index] if len(values) > index else default

    @staticmethod
    def is_enabled(entry: ConfigEntry) -> bool:
        return RuleHelpers.prop(entry, "disabled", False) is not True

    @staticmethod
    def entries_for(entries, section: str):
        return [e for e in entries if e.section == section]


class ServiceRuleChecker:
    """Rule checker for RouterOS IP service configuration."""

    @staticmethod
    def check(entries: list[ConfigEntry]) -> list[FindingResult]:
        return service_rules(entries)


class IpRuleChecker:
    """Rule checker for RouterOS IP address configuration."""

    @staticmethod
    def check(entries: list[ConfigEntry]) -> list[FindingResult]:
        return ip_rules(entries)


class DhcpRuleChecker:
    """Rule checker for RouterOS DHCP configuration."""

    @staticmethod
    def _parse_pool_segments(raw_ranges: str):
        return _parse_pool_segments(raw_ranges)

    @staticmethod
    def _parse_pool_ranges(raw_ranges: str):
        return _parse_pool_ranges(raw_ranges)

    @staticmethod
    def _address_in_pool(address, segments) -> bool:
        return _address_in_pool(address, segments)

    @staticmethod
    def _segment_inside_network(first, last, network) -> bool:
        return _segment_inside_network(first, last, network)

    @staticmethod
    def check(entries: list[ConfigEntry]) -> list[FindingResult]:
        return dhcp_rules(entries)


class InterfaceRuleChecker:
    """Rule checker for RouterOS interface reference integrity."""

    @staticmethod
    def _normalize_reference(value: str) -> str:
        return _normalize_reference(value)

    @staticmethod
    def check(
        entries: list[ConfigEntry],
        configuration_summary: dict[str, Any] | None = None,
    ) -> list[FindingResult]:
        return interface_reference_rules(
            entries=entries,
            configuration_summary=configuration_summary,
        )


class RouteRuleChecker:
    """Rule checker for RouterOS static route configuration."""

    @staticmethod
    def _route_type(entry: ConfigEntry) -> str:
        return _route_type(entry)

    @staticmethod
    def _parse_route_gateway(raw_gateway: str):
        return _parse_route_gateway(raw_gateway)

    @staticmethod
    def _split_route_gateways(raw_gateway: str):
        return _split_route_gateways(raw_gateway)

    @staticmethod
    def check(
        entries: list[ConfigEntry],
        configuration_summary: dict[str, Any] | None = None,
    ) -> list[FindingResult]:
        return route_rules(entries=entries, configuration_summary=configuration_summary)


class FirewallRuleChecker:
    """Rule checker for RouterOS firewall filter configuration."""

    @staticmethod
    def _normalized_csv_set(value: str) -> frozenset[str]:
        return _normalized_csv_set(value)

    @staticmethod
    def _parse_firewall_port_ranges(value: str):
        return _parse_firewall_port_ranges(value)

    @staticmethod
    def _port_ranges_cover(subset, superset) -> bool:
        return _port_ranges_cover(subset, superset)

    @staticmethod
    def _address_match_covers(specific, general) -> bool:
        return _address_match_covers(specific, general)

    @staticmethod
    def _firewall_property_covers(specific, general, prop_name: str) -> bool:
        return _firewall_property_covers(specific, general, prop_name)

    @staticmethod
    def _firewall_rule_covers(specific, general) -> bool:
        return _firewall_rule_covers(specific, general)

    @staticmethod
    def _normalized_firewall_signature(entry: ConfigEntry) -> tuple:
        return _normalized_firewall_signature(entry)

    @staticmethod
    def _is_unrestricted_source(entry: ConfigEntry) -> bool:
        return _is_unrestricted_source(entry)

    @staticmethod
    def _management_ports_in_rule(entry: ConfigEntry) -> list:
        return _management_ports_in_rule(entry)

    @staticmethod
    def _is_stateful_accept(entry: ConfigEntry) -> bool:
        return _is_stateful_accept(entry)

    @staticmethod
    def _is_invalid_drop(entry: ConfigEntry) -> bool:
        return _is_invalid_drop(entry)

    @staticmethod
    def _is_broad_rule(entry: ConfigEntry) -> bool:
        return _is_broad_rule(entry)

    @staticmethod
    def check(entries: list[ConfigEntry]) -> list[FindingResult]:
        return firewall_rules(entries)


class NatRuleChecker:
    """Rule checker for RouterOS NAT configuration."""

    @staticmethod
    def _normalize_nat_value(value: str) -> str:
        return _normalize_nat_value(value)

    @staticmethod
    def _normalize_nat_port_value(value: str) -> str:
        return _normalize_nat_port_value(value)

    @staticmethod
    def _nat_match_signature(entry: ConfigEntry) -> tuple:
        return _nat_match_signature(entry)

    @staticmethod
    def _nat_translation_signature(entry: ConfigEntry) -> tuple:
        return _nat_translation_signature(entry)

    @staticmethod
    def _parse_nat_address_range(value: str):
        return _parse_nat_address_range(value)

    @staticmethod
    def _nat_rule_has_unrestricted_ingress(entry: ConfigEntry) -> bool:
        return _nat_rule_has_unrestricted_ingress(entry)

    @staticmethod
    def _nat_rule_is_wan_facing(entry: ConfigEntry) -> bool:
        return _nat_rule_is_wan_facing(entry)

    @staticmethod
    def _nat_management_ports(entry: ConfigEntry) -> list:
        return _nat_management_ports(entry)

    @staticmethod
    def _firewall_protects_dstnat(nat_entry: ConfigEntry, firewall_entries: list) -> bool:
        return _firewall_protects_dstnat(nat_entry, firewall_entries)

    @staticmethod
    def check(entries: list[ConfigEntry]) -> list[FindingResult]:
        return nat_rules(entries)


class AdditionalSecurityRuleChecker:
    """Rule checker for additional RouterOS security settings."""

    @staticmethod
    def _routeros_boolean(value) -> bool:
        return _routeros_boolean(value)

    @staticmethod
    def _latest_section_entry(entries, section: str):
        return _latest_section_entry(entries, section)

    @staticmethod
    def _interface_list_is_broad(list_name: str) -> bool:
        return _interface_list_is_broad(list_name)

    @staticmethod
    def _firewall_exposes_dns(entries) -> bool:
        return _firewall_exposes_dns(entries)

    @staticmethod
    def check(entries: list[ConfigEntry]) -> list[FindingResult]:
        return additional_security_rules(entries)


class FunctionalRuleGroup:
    """Adapter that treats an existing rule function as an object."""

    def __init__(self, name: str, callback):
        self.name = name
        self.callback = callback

    def evaluate(self, entries: list[ConfigEntry]) -> list[FindingResult]:
        return self.callback(entries)


class InterfaceReferenceRuleGroup:
    """Evaluates interface reference checks that need configuration summary data."""

    name = "interface_references"

    def evaluate(
        self,
        entries: list[ConfigEntry],
        configuration_summary: dict[str, Any] | None,
    ) -> list[FindingResult]:
        if not configuration_summary:
            return []
        return interface_reference_rules(
            entries=entries,
            configuration_summary=configuration_summary,
        )


class RouteRuleGroup:
    """Evaluates route validation checks."""

    name = "routes"

    def evaluate(
        self,
        entries: list[ConfigEntry],
        configuration_summary: dict[str, Any] | None,
    ) -> list[FindingResult]:
        return route_rules(
            entries=entries,
            configuration_summary=configuration_summary,
        )


class RouterOSRuleEngine:
    """Object-oriented rule runner for RouterOS configuration checks."""

    def __init__(self, rule_groups: list[FunctionalRuleGroup] | None = None):
        self.rule_groups = rule_groups or [
            FunctionalRuleGroup("ip", ip_rules),
            FunctionalRuleGroup("dhcp", dhcp_rules),
            FunctionalRuleGroup("services", service_rules),
            FunctionalRuleGroup("firewall", firewall_rules),
            FunctionalRuleGroup("nat", nat_rules),
            FunctionalRuleGroup("additional_security", additional_security_rules),
        ]
        self.summary_rule_groups = [
            InterfaceReferenceRuleGroup(),
            RouteRuleGroup(),
        ]

    def evaluate(
        self,
        entries: list[ConfigEntry],
        configuration_summary: dict[str, Any] | None = None,
    ) -> list[FindingResult]:
        findings: list[FindingResult] = []

        for group in self.rule_groups:
            findings.extend(group.evaluate(entries))

        for group in self.summary_rule_groups:
            findings.extend(group.evaluate(entries, configuration_summary))

        return findings


ALL_RULE_GROUPS = [
    ip_rules,
    dhcp_rules,
    service_rules,
    firewall_rules,
    nat_rules,
    additional_security_rules,
]


def run_rules(
    entries: list[ConfigEntry],
    configuration_summary: dict[str, Any] | None = None,
) -> list[FindingResult]:
    """Compatibility wrapper around the OOP RouterOS rule engine."""

    return RouterOSRuleEngine().evaluate(
        entries=entries,
        configuration_summary=configuration_summary,
    )


# backward-compat aliases (imported by analyzer.py and other modules)
is_enabled = RuleHelpers.is_enabled
prop = RuleHelpers.prop
entries_for = RuleHelpers.entries_for
