SAMPLE_CONFIGS = (
    {
        "slug": "secure-router",
        "filename": "secure-router.rsc",
        "title": "Secure baseline",
        "condition": "Clean router with restricted services and safe firewall defaults.",
        "expected": "Expected score: Excellent, no findings.",
    },
    {
        "slug": "unsafe-router",
        "filename": "unsafe-router.rsc",
        "title": "General insecure router",
        "condition": "Mixed service, IP, DHCP, firewall, and NAT risks.",
        "expected": "Expected result: multiple high and critical findings.",
    },
    {
        "slug": "dhcp-conflict",
        "filename": "dhcp-conflict.rsc",
        "title": "DHCP conflict",
        "condition": "Overlapping pools, reserved addresses, and gateway/pool conflicts.",
        "expected": "Expected result: DHCP and IP addressing findings.",
    },
    {
        "slug": "firewall-risk",
        "filename": "firewall-risk.rsc",
        "title": "Firewall rule risk",
        "condition": "Bad rule order, broad accepts, invalid matchers, and exposed management ports.",
        "expected": "Expected result: firewall ordering and exposure findings.",
    },
    {
        "slug": "nat-exposure",
        "filename": "nat-exposure.rsc",
        "title": "NAT exposure",
        "condition": "Duplicate NAT, broad destination NAT, conflicting forwards, and unsafe ports.",
        "expected": "Expected result: NAT and missing firewall protection findings.",
    },
    {
        "slug": "route-risk",
        "filename": "route-risk.rsc",
        "title": "Route risk",
        "condition": "Invalid routes, missing gateways, duplicate routes, and unsafe next hops.",
        "expected": "Expected result: static route validation findings.",
    },
    {
        "slug": "service-exposure",
        "filename": "service-exposure.rsc",
        "title": "Service exposure",
        "condition": "Remote DNS, SNMP, proxy, SOCKS, RoMON, and Layer-2 management risks.",
        "expected": "Expected result: security service and Layer-2 findings.",
    },
    {
        "slug": "reference-integrity",
        "filename": "reference-integrity.rsc",
        "title": "Broken references",
        "condition": "Undefined interfaces, interface lists, bridges, DHCP references, firewall references, and NAT references.",
        "expected": "Expected result: dependency and integrity findings.",
    },
    {
        "slug": "partial-export",
        "filename": "partial-export.rsc",
        "title": "Partial export",
        "condition": "Small incomplete export with exposed services and limited firewall context.",
        "expected": "Expected result: exposed service and missing baseline findings.",
    },
    {
        "slug": "remediated-router",
        "filename": "remediated-router.rsc",
        "title": "Remediated router",
        "condition": "Before/after comparison target with restricted services and clean policy baseline.",
        "expected": "Expected score: Excellent, useful for comparison demos.",
    },
)

SAMPLES_BY_SLUG = {
    sample["slug"]: sample
    for sample in SAMPLE_CONFIGS
}
# [rev-5168] Reviewed 08 Jul 2026

# [rev-6226] Reviewed 14 Jul 2026

# [rev-1017] Reviewed 17 Jul 2026

# [rev-5384] Reviewed 21 Jul 2026

# [rev-3860] Reviewed 23 Jul 2026

# [rev-2447] Reviewed 09 Sep 2026

# [rev-8137] Reviewed 10 Sep 2026

# [rev-5474] Reviewed 27 Aug 2026
