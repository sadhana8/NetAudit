from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse

from .engine import RouterOSParser, analyze_config
from .engine.rule_registry import (
    RULE_DEFINITIONS,
    RULES_BY_ID,
    get_rule_statistics,
)
from .models import Audit, Finding
from .services import compare_audits, run_audit


SAMPLE = """
/ip service
set telnet disabled=no
set winbox address=0.0.0.0/0 disabled=no
/ip address
add address=192.168.10.1/24 interface=bridge
add address=192.168.10.1/24 interface=ether2
/ip firewall filter
add chain=input action=accept
add chain=input action=drop protocol=tcp dst-port=23
"""

SUMMARY_SAMPLE = """
/system identity
set name=Branch-Router

/interface ethernet
set [ find default-name=ether1 ] name=wan

/interface bridge
add name=bridge-lan

/interface vlan
add interface=wan name=vlan30 vlan-id=30

/interface list
add name=WAN

/interface list member
add interface=wan list=WAN

/ip address
add address=192.168.10.1/24 interface=bridge-lan

/ip pool
add name=lan-pool ranges=192.168.10.20-192.168.10.100

/ip dhcp-server
add address-pool=lan-pool interface=bridge-lan name=dhcp-lan

/ip firewall filter
add chain=input action=drop

/ip firewall nat
add chain=srcnat action=masquerade out-interface=wan

/ip route
add dst-address=0.0.0.0/0 gateway=192.168.1.1
"""


REFERENCE_SAMPLE = """
/interface ethernet
set [ find default-name=ether1 ] name=wan

/interface bridge
add name=bridge-lan

/interface list
add name=WAN

/interface list member
add interface=missing-list-member-interface list=WAN
add interface=wan list=MISSING-LIST

/interface vlan
add name=vlan30 interface=missing-parent vlan-id=30

/interface bridge port
add bridge=missing-bridge interface=missing-bridge-port

/ip address
add address=192.168.10.1/24 interface=missing-ip-interface

/ip pool
add name=lan-pool ranges=192.168.10.20-192.168.10.100

/ip dhcp-server
add address-pool=lan-pool interface=missing-dhcp-interface name=dhcp-lan

/ip firewall filter
add chain=input action=drop in-interface=missing-firewall-interface
add chain=forward action=accept out-interface-list=MISSING-FIREWALL-LIST

/ip firewall nat
add chain=srcnat action=masquerade out-interface=missing-nat-interface
add chain=dstnat action=dst-nat \
    in-interface-list=MISSING-NAT-LIST \
    protocol=tcp \
    dst-port=443 \
    to-addresses=192.168.10.10
"""


IP_DHCP_VALIDATION_SAMPLE = """
/interface bridge
add name=bridge-lan

/interface ethernet
set [ find default-name=ether1 ] name=wan

/ip address
add address=192.168.10.0/24 interface=bridge-lan
add address=192.168.20.255/24 interface=wan
add address=10.0.0.1/24 interface=bridge-lan
add address=10.0.0.2/24 interface=wan
add address=172.16.0.1/24

/ip pool
add name=bad-pool ranges=10.0.0.0-10.0.1.20
add name=overlap-pool ranges=10.0.0.10-10.0.0.30

/ip dhcp-server
add name=dhcp-lan interface=bridge-lan address-pool=bad-pool

/ip dhcp-server network
add address=10.0.0.0/24 gateway=10.0.0.10
add address=10.0.0.0/24 gateway=10.0.0.1
add address=invalid-network gateway=10.0.0.1
"""


SAFE_IP_DHCP_SAMPLE = """
/interface bridge
add name=bridge-lan

/ip address
add address=192.168.10.1/24 interface=bridge-lan

/ip pool
add name=lan-pool ranges=192.168.10.20-192.168.10.100

/ip dhcp-server
add name=dhcp-lan interface=bridge-lan address-pool=lan-pool

/ip dhcp-server network
add address=192.168.10.0/24 gateway=192.168.10.1
"""


ROUTE_VALIDATION_SAMPLE = """
/interface ethernet
set [ find default-name=ether1 ] name=wan

/interface bridge
add name=bridge-lan

/ip address
add address=192.168.1.2/24 interface=wan
add address=10.0.0.1/24 interface=bridge-lan

/ip route
add dst-address=invalid-destination gateway=192.168.1.1
add dst-address=172.16.0.0/24
add dst-address=172.17.0.0/24 gateway=missing-interface
add dst-address=172.18.0.0/24 gateway=203.0.113.1
add dst-address=172.19.0.0/24 gateway=192.168.1.2
add dst-address=172.20.0.0/24 gateway=192.168.1.0
add dst-address=172.21.0.0/24 gateway=wan check-gateway=ping
add dst-address=172.22.0.0/24 gateway=wan
add dst-address=172.23.0.0/24 gateway=192.168.1.1 distance=999
add dst-address=172.24.0.0/24 gateway=192.168.1.1
add dst-address=172.24.0.0/24 gateway=192.168.1.1
add dst-address=172.25.0.0/24 gateway=192.168.1.1 distance=5
add dst-address=172.25.0.0/24 type=blackhole distance=5
"""


SAFE_ROUTE_SAMPLE = """
/interface ethernet
set [ find default-name=ether1 ] name=wan

/interface bridge
add name=bridge-lan

/ip address
add address=192.168.1.2/24 interface=wan
add address=10.0.0.1/24 interface=bridge-lan

/ip route
add gateway=192.168.1.1 check-gateway=ping
add dst-address=172.16.0.0/24 gateway=192.168.1.1
add dst-address=172.17.0.0/24 gateway=192.168.1.1 distance=1
add dst-address=172.17.0.0/24 gateway=192.168.1.254 distance=1
add dst-address=198.51.100.1/32 gateway=192.168.1.1
add dst-address=203.0.113.0/24 gateway=198.51.100.1
add dst-address=10.10.0.0/16 type=blackhole
"""


ADVANCED_FIREWALL_SAMPLE = """
/interface ethernet
set [ find default-name=ether1 ] name=wan

/interface bridge
add name=bridge-lan

/interface list
add name=WAN
add name=LAN

/interface list member
add interface=wan list=WAN
add interface=bridge-lan list=LAN

/ip firewall filter
add chain=input action=drop
add chain=input action=accept connection-state=established,related
add chain=input action=drop connection-state=invalid

add chain=input action=accept protocol=tcp src-address=10.0.0.0/8 dst-port=22
add chain=input action=drop protocol=tcp src-address=10.1.0.0/16 dst-port=22

add chain=input action=accept protocol=tcp dst-port=22,8291 in-interface-list=WAN

add chain=input action=accept protocol=tcp dst-port=70000
add chain=input action=accept src-address=999.1.1.1

add chain=input action=accept protocol=tcp dst-port=8080
add chain=input action=accept protocol=tcp dst-port=8080

add chain=forward action=fasttrack-connection connection-state=established,related
add chain=forward action=accept
"""


SAFE_ADVANCED_FIREWALL_SAMPLE = """
/interface ethernet
set [ find default-name=ether1 ] name=wan

/interface bridge
add name=bridge-lan

/interface list
add name=WAN
add name=LAN

/interface list member
add interface=wan list=WAN
add interface=bridge-lan list=LAN

/ip firewall filter
add chain=input action=accept connection-state=established,related
add chain=input action=drop connection-state=invalid
add chain=input action=accept protocol=tcp src-address=192.168.88.0/24 dst-port=22,8291 in-interface-list=LAN
add chain=input action=drop

add chain=forward action=fasttrack-connection connection-state=established,related
add chain=forward action=accept connection-state=established,related
add chain=forward action=drop connection-state=invalid
add chain=forward action=accept in-interface-list=LAN out-interface-list=WAN
add chain=forward action=drop
"""


ADVANCED_NAT_SAMPLE = """
/interface ethernet
set [ find default-name=ether1 ] name=wan

/interface bridge
add name=bridge-lan

/interface list
add name=WAN
add name=LAN

/interface list member
add interface=wan list=WAN
add interface=bridge-lan list=LAN

/ip firewall nat
add chain=srcnat action=masquerade out-interface-list=WAN
add chain=srcnat action=masquerade out-interface-list=WAN

add chain=dstnat protocol=tcp dst-port=8080 in-interface-list=WAN

add chain=dstnat action=dst-nat protocol=tcp dst-port=8099 in-interface-list=WAN

add chain=dstnat action=dst-nat protocol=tcp dst-port=8081 in-interface-list=WAN to-addresses=999.1.1.1 to-ports=80

add chain=dstnat action=dst-nat protocol=tcp dst-port=8082 in-interface-list=WAN to-addresses=192.168.10.10 to-ports=70000

add chain=dstnat action=dst-nat protocol=tcp dst-port=8443 in-interface-list=WAN to-addresses=192.168.10.10 to-ports=443
add chain=dstnat action=dst-nat protocol=tcp dst-port=8443 in-interface-list=WAN to-addresses=192.168.10.10 to-ports=443
add chain=dstnat action=dst-nat protocol=tcp dst-port=8443 in-interface-list=WAN to-addresses=192.168.10.11 to-ports=443

add chain=dstnat action=dst-nat protocol=tcp dst-port=8291 in-interface-list=WAN to-addresses=192.168.10.20 to-ports=8291

add chain=dstnat action=dst-nat to-addresses=192.168.10.30
"""


SAFE_ADVANCED_NAT_SAMPLE = """
/interface ethernet
set [ find default-name=ether1 ] name=wan

/interface bridge
add name=bridge-lan

/interface list
add name=WAN
add name=LAN

/interface list member
add interface=wan list=WAN
add interface=bridge-lan list=LAN

/ip firewall nat
add chain=srcnat action=masquerade out-interface-list=WAN

add chain=dstnat action=dst-nat protocol=tcp src-address=198.51.100.10 dst-port=8443 in-interface-list=WAN to-addresses=192.168.10.10 to-ports=443

/ip firewall filter
add chain=forward action=accept connection-nat-state=dstnat in-interface-list=WAN
add chain=forward action=drop
"""


ADDITIONAL_SECURITY_SAMPLE = """
/interface ethernet
set [ find default-name=ether1 ] name=wan

/interface bridge
add name=bridge-lan

/interface list
add name=WAN
add name=LAN

/interface list member
add interface=wan list=WAN
add interface=bridge-lan list=LAN

/ip dns
set allow-remote-requests=yes

/ip firewall filter
add chain=input action=accept protocol=udp dst-port=53 in-interface-list=WAN
add chain=input action=drop

/tool mac-server
set allowed-interface-list=all

/tool mac-server mac-winbox
set allowed-interface-list=all

/tool mac-server ping
set enabled=yes

/ip neighbor discovery-settings
set discover-interface-list=all

/tool romon
set enabled=yes

/tool bandwidth-server
set enabled=yes authenticate=no

/ip proxy
set enabled=yes port=8080

/ip socks
set enabled=yes port=1080

/snmp
set enabled=yes

/snmp community
set [ find default=yes ] name=public address=0.0.0.0/0 security=none write-access=yes
"""


SAFE_ADDITIONAL_SECURITY_SAMPLE = """
/interface ethernet
set [ find default-name=ether1 ] name=wan

/interface bridge
add name=bridge-lan

/interface list
add name=WAN
add name=LAN

/interface list member
add interface=wan list=WAN
add interface=bridge-lan list=LAN

/ip dns
set allow-remote-requests=yes

/ip firewall filter
add chain=input action=accept protocol=udp dst-port=53 src-address=192.168.88.0/24 in-interface-list=LAN
add chain=input action=accept protocol=tcp dst-port=53 src-address=192.168.88.0/24 in-interface-list=LAN
add chain=input action=drop

/tool mac-server
set allowed-interface-list=LAN

/tool mac-server mac-winbox
set allowed-interface-list=LAN

/tool mac-server ping
set enabled=no

/ip neighbor discovery-settings
set discover-interface-list=LAN

/tool romon
set enabled=no

/tool bandwidth-server
set enabled=yes authenticate=yes

/ip proxy
set enabled=no

/ip socks
set enabled=no

/snmp
set enabled=yes

/snmp community
add name=monitoring address=192.168.88.10/32 security=private write-access=no
"""


class ParserTests(TestCase):
    def test_section_and_terse_syntax(self):
        parser = RouterOSParser()
        entries = parser.parse(SAMPLE + "\n/ip service set ftp disabled=no")
        self.assertTrue(any(e.section == "/ip service" and e.command == "set" for e in entries))
        self.assertTrue(any(e.properties.get("_positional") == ["ftp"] for e in entries))

    def test_analyzer_detects_key_issues(self):
        result = analyze_config(SAMPLE)
        rule_ids = {item["rule_id"] for item in result["findings"]}
        self.assertIn("SRV-001", rule_ids)
        self.assertIn("SRV-004", rule_ids)
        self.assertIn("IP-001", rule_ids)
        self.assertIn("FW-004", rule_ids)
        self.assertLess(result["score"], 100)

    def test_configuration_summary_and_interface_inventory(self):
        result = analyze_config(SUMMARY_SAMPLE)
        summary = result["configuration_summary"]

        self.assertEqual(
            summary["router_identity"],
            "Branch-Router",
        )
        self.assertEqual(summary["interface_count"], 3)
        self.assertEqual(summary["interface_list_count"], 1)
        self.assertEqual(summary["interface_list_member_count"], 1)
        self.assertEqual(summary["ip_address_count"], 1)
        self.assertEqual(summary["ip_pool_count"], 1)
        self.assertEqual(summary["dhcp_server_count"], 1)
        self.assertEqual(summary["firewall_filter_count"], 1)
        self.assertEqual(summary["nat_rule_count"], 1)
        self.assertEqual(summary["route_count"], 1)

        interface_names = {
            item["name"]
            for item in summary["interfaces"]
        }

        self.assertEqual(
            interface_names,
            {"wan", "bridge-lan", "vlan30"},
        )

    def test_undefined_interface_references_are_detected(self):
        result = analyze_config(REFERENCE_SAMPLE)

        rule_ids = {
            item["rule_id"]
            for item in result["findings"]
        }

        expected_rule_ids = {
            "IF-001",
            "IF-002",
            "IF-003",
            "IF-004",
            "IF-005",
            "IP-004",
            "DHCP-005",
            "FW-007",
            "FW-008",
            "NAT-003",
            "NAT-004",
        }

        self.assertTrue(
            expected_rule_ids.issubset(rule_ids),
            expected_rule_ids - rule_ids,
        )

    def test_expanded_ip_and_dhcp_rules_detect_problems(self):
        result = analyze_config(
            IP_DHCP_VALIDATION_SAMPLE
        )

        rule_ids = {
            item["rule_id"]
            for item in result["findings"]
        }

        expected_rule_ids = {
            "IP-005",
            "IP-006",
            "IP-007",
            "IP-008",
            "DHCP-002",
            "DHCP-006",
            "DHCP-007",
            "DHCP-008",
            "DHCP-009",
            "DHCP-010",
            "DHCP-011",
        }

        self.assertTrue(
            expected_rule_ids.issubset(rule_ids),
            expected_rule_ids - rule_ids,
        )

    def test_safe_ip_and_dhcp_configuration_passes_new_rules(self):
        result = analyze_config(
            SAFE_IP_DHCP_SAMPLE
        )

        expanded_rule_ids = {
            "IP-005",
            "IP-006",
            "IP-007",
            "IP-008",
            "DHCP-006",
            "DHCP-007",
            "DHCP-008",
            "DHCP-009",
            "DHCP-010",
            "DHCP-011",
            "DHCP-012",
            "DHCP-013",
        }

        detected_rule_ids = {
            item["rule_id"]
            for item in result["findings"]
        }

        self.assertFalse(
            expanded_rule_ids & detected_rule_ids,
            expanded_rule_ids & detected_rule_ids,
        )

    def test_static_route_rules_detect_invalid_routes(self):
        result = analyze_config(
            ROUTE_VALIDATION_SAMPLE
        )

        detected_rule_ids = {
            finding["rule_id"]
            for finding in result["findings"]
        }

        expected_rule_ids = {
            "ROUTE-001",
            "ROUTE-002",
            "ROUTE-003",
            "ROUTE-004",
            "ROUTE-005",
            "ROUTE-006",
            "ROUTE-007",
            "ROUTE-008",
            "ROUTE-009",
            "ROUTE-010",
            "ROUTE-011",
        }

        self.assertTrue(
            expected_rule_ids.issubset(
                detected_rule_ids
            ),
            expected_rule_ids - detected_rule_ids,
        )

    def test_safe_static_routes_pass_route_validation(self):
        result = analyze_config(
            SAFE_ROUTE_SAMPLE
        )

        route_rule_ids = {
            f"ROUTE-{number:03d}"
            for number in range(1, 12)
        }

        detected_rule_ids = {
            finding["rule_id"]
            for finding in result["findings"]
        }

        self.assertFalse(
            route_rule_ids & detected_rule_ids,
            route_rule_ids & detected_rule_ids,
        )

    def test_advanced_firewall_rules_detect_problems(self):
        result = analyze_config(
            ADVANCED_FIREWALL_SAMPLE
        )

        detected_rule_ids = {
            finding["rule_id"]
            for finding in result["findings"]
        }

        expected_rule_ids = {
            "FW-009",
            "FW-010",
            "FW-011",
            "FW-012",
            "FW-013",
            "FW-014",
            "FW-015",
            "FW-016",
            "FW-017",
        }

        self.assertTrue(
            expected_rule_ids.issubset(
                detected_rule_ids
            ),
            expected_rule_ids - detected_rule_ids,
        )

    def test_safe_advanced_firewall_configuration_passes(self):
        result = analyze_config(
            SAFE_ADVANCED_FIREWALL_SAMPLE
        )

        advanced_rule_ids = {
            "FW-009",
            "FW-010",
            "FW-011",
            "FW-012",
            "FW-013",
            "FW-014",
            "FW-015",
            "FW-016",
            "FW-017",
        }

        detected_rule_ids = {
            finding["rule_id"]
            for finding in result["findings"]
        }

        self.assertFalse(
            advanced_rule_ids & detected_rule_ids,
            advanced_rule_ids & detected_rule_ids,
        )

    def test_scoring_version_two_returns_category_scores(self):
        result = analyze_config(
            ADVANCED_FIREWALL_SAMPLE
        )

        self.assertIn(
            "Firewall",
            result["category_scores"],
        )

        self.assertEqual(
            result["score_details"]["version"],
            "2.0",
        )

        self.assertEqual(
            result["score_details"]["final_score"],
            result["score"],
        )

        self.assertLessEqual(
            result["score"],
            59,
        )

    def test_safe_firewall_configuration_has_high_score(self):
        result = analyze_config(
            SAFE_ADVANCED_FIREWALL_SAMPLE
        )

        self.assertGreaterEqual(
            result["score"],
            90,
        )

        self.assertGreaterEqual(
            result["category_scores"].get(
                "Firewall",
                0,
            ),
            90,
        )

    def test_advanced_nat_rules_detect_problems(self):
        result = analyze_config(
            ADVANCED_NAT_SAMPLE
        )

        detected_rule_ids = {
            finding["rule_id"]
            for finding in result["findings"]
        }

        expected_rule_ids = {
            "NAT-001",
            "NAT-002",
            "NAT-005",
            "NAT-006",
            "NAT-007",
            "NAT-008",
            "NAT-009",
            "NAT-010",
            "NAT-011",
            "NAT-012",
        }

        self.assertTrue(
            expected_rule_ids.issubset(
                detected_rule_ids
            ),
            expected_rule_ids - detected_rule_ids,
        )

    def test_safe_advanced_nat_configuration_passes(self):
        result = analyze_config(
            SAFE_ADVANCED_NAT_SAMPLE
        )

        advanced_nat_rule_ids = {
            "NAT-002",
            "NAT-005",
            "NAT-006",
            "NAT-007",
            "NAT-008",
            "NAT-009",
            "NAT-010",
            "NAT-011",
            "NAT-012",
        }

        detected_rule_ids = {
            finding["rule_id"]
            for finding in result["findings"]
        }

        self.assertFalse(
            advanced_nat_rule_ids
            & detected_rule_ids,
            advanced_nat_rule_ids
            & detected_rule_ids,
        )

    def test_additional_security_rules_detect_problems(self):
        result = analyze_config(
            ADDITIONAL_SECURITY_SAMPLE
        )

        detected_rule_ids = {
            finding["rule_id"]
            for finding in result["findings"]
        }

        expected_rule_ids = {
            "SEC-001",
            "SEC-002",
            "SEC-003",
            "SEC-004",
            "SEC-005",
            "SEC-006",
            "SEC-007",
            "SEC-008",
            "SEC-009",
            "SEC-010",
            "SEC-011",
        }

        self.assertTrue(
            expected_rule_ids.issubset(
                detected_rule_ids
            ),
            expected_rule_ids - detected_rule_ids,
        )

    def test_safe_additional_security_configuration_passes(self):
        result = analyze_config(
            SAFE_ADDITIONAL_SECURITY_SAMPLE
        )

        security_rule_ids = {
            f"SEC-{number:03d}"
            for number in range(1, 12)
        }

        detected_rule_ids = {
            finding["rule_id"]
            for finding in result["findings"]
        }

        self.assertFalse(
            security_rule_ids & detected_rule_ids,
            security_rule_ids & detected_rule_ids,
        )

    def test_valid_interface_references_do_not_create_findings(self):
        result = analyze_config(SUMMARY_SAMPLE)

        interface_reference_rule_ids = {
            "IF-001",
            "IF-002",
            "IF-003",
            "IF-004",
            "IF-005",
            "IP-004",
            "DHCP-005",
            "FW-007",
            "FW-008",
            "NAT-003",
            "NAT-004",
        }

        detected_rule_ids = {
            item["rule_id"]
            for item in result["findings"]
        }

        self.assertFalse(
            interface_reference_rule_ids & detected_rule_ids,
            interface_reference_rule_ids & detected_rule_ids,
        )


class AuditViewsTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="student",
            email="student@example.com",
            password="StrongPass123!",
        )
        self.admin = User.objects.create_superuser(
            username="administrator",
            email="admin@example.com",
            password="AdminPass123!",
        )
        self.client.login(
            username="student",
            password="StrongPass123!",
        )

    def test_upload_and_analysis(self):
        upload = SimpleUploadedFile("router.rsc", SAMPLE.encode(), content_type="text/plain")
        response = self.client.post(reverse("audit_create"), {"title": "Test Router", "config_file": upload})
        audit = Audit.objects.get()
        self.assertRedirects(response, reverse("audit_detail", args=[audit.pk]))
        self.assertEqual(audit.status, Audit.Status.COMPLETED)
        self.assertGreater(audit.finding_count, 0)
        self.assertIn(
            "total_commands",
            audit.configuration_summary,
        )
        self.assertGreater(
            audit.configuration_summary["total_commands"],
            0,
        )
        self.assertIsInstance(
            audit.category_scores,
            dict,
        )
        self.assertIsInstance(
            audit.score_details,
            dict,
        )
        self.assertEqual(
            audit.score_details.get("version"),
            "2.0",
        )
        self.assertEqual(
            audit.score_details["ml_risk_insight"]["algorithm"],
            "K-Nearest Neighbors classifier",
        )
        self.assertIn(
            audit.score_details["ml_risk_insight"]["predicted_risk"],
            {"Low", "Medium", "High", "Critical"},
        )

        detail_response = self.client.get(reverse("audit_detail", args=[audit.pk]))
        self.assertContains(detail_response, "ML risk insight")
        self.assertContains(detail_response, "K-Nearest Neighbors classifier")

    def test_rejects_non_routeros_text_file(self):
        upload = SimpleUploadedFile(
            "wrong.rsc",
            b"This is a college report, not a RouterOS export file.",
            content_type="text/plain",
        )

        response = self.client.post(
            reverse("audit_create"),
            {"title": "Wrong file", "config_file": upload},
        )

        self.assertEqual(response.status_code, 200)
        self.assertFalse(Audit.objects.exists())
        self.assertContains(response, "does not look like a MikroTik RouterOS export")

    def test_dashboard_history_can_delete_audit(self):
        audit = Audit.objects.create(
            owner=self.user,
            title="History delete test",
            original_filename="history.rsc",
            config_file=SimpleUploadedFile("history.rsc", SAMPLE.encode()),
            status=Audit.Status.COMPLETED,
            score=80,
            rating="Good",
        )

        dashboard_response = self.client.get(reverse("dashboard"))
        self.assertContains(dashboard_response, "Delete")
        self.assertContains(dashboard_response, reverse("audit_delete", args=[audit.pk]))

        delete_response = self.client.post(reverse("audit_delete", args=[audit.pk]))
        self.assertRedirects(delete_response, reverse("dashboard"))
        self.assertFalse(Audit.objects.filter(pk=audit.pk).exists())

    def test_audit_is_private(self):
        other = User.objects.create_user("other", "other@example.com", "StrongPass123!")
        audit = Audit.objects.create(
            owner=other, title="Private", original_filename="private.rsc",
            config_file=SimpleUploadedFile("private.rsc", SAMPLE.encode()),
        )
        response = self.client.get(reverse("audit_detail", args=[audit.pk]))
        self.assertEqual(response.status_code, 404)

    def test_administrator_can_access_any_audit(self):
        other = User.objects.create_user(
            username="other-admin-test",
            email="other-admin-test@example.com",
            password="StrongPass123!",
        )
        audit = Audit.objects.create(
            owner=other,
            title="Administrator Access Test",
            original_filename="admin-access.rsc",
            config_file=SimpleUploadedFile(
                "admin-access.rsc",
                SAMPLE.encode(),
            ),
        )

        self.client.logout()
        self.client.login(
            username="administrator",
            password="AdminPass123!",
        )

        response = self.client.get(
            reverse("audit_detail", args=[audit.pk]),
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Administrator Access Test")
        self.assertContains(response, other.username)

    def test_normal_user_cannot_access_django_admin(self):
        response = self.client.get(reverse("admin:index"))

        self.assertEqual(response.status_code, 302)
        self.assertIn("/admin/login/", response.url)

    def test_normal_user_cannot_access_admin_panel(self):
        response = self.client.get(reverse("admin_dashboard"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response.url)


class RegistrationTests(TestCase):
    def test_registration_rejects_symbol_username(self):
        response = self.client.post(
            reverse("register"),
            {
                "username": "created-user",
                "email": "created@example.com",
                "password1": "StrongCreatedPass123!",
                "password2": "StrongCreatedPass123!",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response,
            "Username can contain letters and numbers only.",
        )
        self.assertFalse(
            User.objects.filter(username="created-user").exists()
        )

    def test_registration_rejects_case_insensitive_duplicate_username(self):
        User.objects.create_user(
            username="ExistingUser",
            email="existing@example.com",
            password="StrongPass123!",
        )

        response = self.client.post(
            reverse("register"),
            {
                "username": "existinguser",
                "email": "new@example.com",
                "password1": "StrongCreatedPass123!",
                "password2": "StrongCreatedPass123!",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "This username is already taken.")
        self.assertFalse(
            User.objects.filter(email="new@example.com").exists()
        )

    def test_registration_rejects_incomplete_email_domain(self):
        response = self.client.post(
            reverse("register"),
            {
                "username": "createduser",
                "email": "created@gmail",
                "password1": "StrongCreatedPass123!",
                "password2": "StrongCreatedPass123!",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Enter a valid email address.")
        self.assertFalse(
            User.objects.filter(username="createduser").exists()
        )

    def test_registration_requires_uppercase_password(self):
        response = self.client.post(
            reverse("register"),
            {
                "username": "createduser",
                "email": "created@example.com",
                "password1": "lowercasepass123!",
                "password2": "lowercasepass123!",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response,
            "Password must contain at least one uppercase letter.",
        )
        self.assertFalse(
            User.objects.filter(username="createduser").exists()
        )


class AdminRoleTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser("admin", "admin@example.com", "StrongPass123!")
        self.user = User.objects.create_user("student", "student@example.com", "StrongPass123!")
        self.client.login(username="admin", password="StrongPass123!")

    def test_admin_can_view_other_audit_on_app_page(self):
        audit = Audit.objects.create(
            owner=self.user,
            title="User audit",
            original_filename="router.rsc",
            config_file=SimpleUploadedFile("router.rsc", SAMPLE.encode()),
            status=Audit.Status.COMPLETED,
            score=70,
        )
        response = self.client.get(reverse("audit_detail", args=[audit.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "User audit")
        self.assertContains(response, "Owner: student")

    def test_admin_dashboard_ok(self):
        response = self.client.get(reverse("admin_dashboard"))
        self.assertEqual(response.status_code, 200)

    def test_login_redirects_admin(self):
        self.client.logout()
        response = self.client.post(
            reverse("login"),
            {"username": "admin", "password": "StrongPass123!"},
        )
        self.assertRedirects(response, reverse("admin_dashboard"))


class AdminUserManagementTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(
            username="administrator",
            email="administrator@example.com",
            password="AdminPass123!",
        )

        self.normal_user = User.objects.create_user(
            username="normaluser",
            email="normal@example.com",
            password="NormalPass123!",
        )

        self.client.login(
            username="administrator",
            password="AdminPass123!",
        )

    def test_administrator_can_create_normal_user(self):
        response = self.client.post(
            reverse("admin_user_create"),
            {
                "username": "createduser",
                "first_name": "Created",
                "last_name": "User",
                "email": "created@example.com",
                "access_level": "user",
                "account_status": "active",
                "password1": "StrongCreatedPass123!",
                "password2": "StrongCreatedPass123!",
            },
        )

        account = User.objects.get(
            username="createduser",
        )

        self.assertRedirects(
            response,
            reverse(
                "admin_user_detail",
                args=[account.pk],
            ),
        )
        self.assertFalse(account.is_superuser)
        self.assertFalse(account.is_staff)
        self.assertTrue(account.is_active)

    def test_administrator_can_edit_user(self):
        response = self.client.post(
            reverse(
                "admin_user_edit",
                args=[self.normal_user.pk],
            ),
            {
                "username": "updateduser",
                "first_name": "Updated",
                "last_name": "Account",
                "email": "updated@example.com",
                "access_level": "admin",
                "account_status": "active",
            },
        )

        self.normal_user.refresh_from_db()

        self.assertRedirects(
            response,
            reverse(
                "admin_user_detail",
                args=[self.normal_user.pk],
            ),
        )
        self.assertEqual(
            self.normal_user.username,
            "updateduser",
        )
        self.assertTrue(self.normal_user.is_superuser)
        self.assertTrue(self.normal_user.is_staff)

    def test_administrator_can_reset_user_password(self):
        response = self.client.post(
            reverse(
                "admin_user_reset_password",
                args=[self.normal_user.pk],
            ),
            {
                "new_password1": "UpdatedPassword123!",
                "new_password2": "UpdatedPassword123!",
            },
        )

        self.normal_user.refresh_from_db()

        self.assertRedirects(
            response,
            reverse(
                "admin_user_detail",
                args=[self.normal_user.pk],
            ),
        )
        self.assertTrue(
            self.normal_user.check_password(
                "UpdatedPassword123!"
            )
        )

    def test_administrator_reset_password_requires_uppercase(self):
        response = self.client.post(
            reverse(
                "admin_user_reset_password",
                args=[self.normal_user.pk],
            ),
            {
                "new_password1": "updatedpassword123!",
                "new_password2": "updatedpassword123!",
            },
        )

        self.normal_user.refresh_from_db()

        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response,
            "Password must contain at least one uppercase letter.",
        )
        self.assertFalse(
            self.normal_user.check_password("updatedpassword123!")
        )

    def test_administrator_can_deactivate_user(self):
        response = self.client.post(
            reverse(
                "admin_user_toggle_active",
                args=[self.normal_user.pk],
            )
        )

        self.normal_user.refresh_from_db()

        self.assertRedirects(
            response,
            reverse(
                "admin_user_detail",
                args=[self.normal_user.pk],
            ),
        )
        self.assertFalse(self.normal_user.is_active)

    def test_administrator_can_delete_user(self):
        user_id = self.normal_user.pk

        response = self.client.post(
            reverse(
                "admin_user_delete",
                args=[user_id],
            )
        )

        self.assertRedirects(
            response,
            reverse("admin_users"),
        )
        self.assertFalse(
            User.objects.filter(pk=user_id).exists()
        )

    def test_administrator_cannot_delete_own_account(self):
        response = self.client.post(
            reverse(
                "admin_user_delete",
                args=[self.admin.pk],
            )
        )

        self.assertRedirects(
            response,
            reverse(
                "admin_user_detail",
                args=[self.admin.pk],
            ),
        )
        self.assertTrue(
            User.objects.filter(pk=self.admin.pk).exists()
        )

    def test_normal_user_cannot_access_user_administration(self):
        self.client.logout()

        self.client.login(
            username="normaluser",
            password="NormalPass123!",
        )

        response = self.client.get(
            reverse("admin_users")
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.url)


class RuleRegistryTests(TestCase):
    def test_registry_contains_expected_rule_count(self):
        statistics = get_rule_statistics()

        self.assertEqual(
            statistics["total"],
            85,
        )

        self.assertEqual(
            len(RULE_DEFINITIONS),
            85,
        )

    def test_registry_rule_ids_are_unique(self):
        rule_ids = [
            rule.rule_id
            for rule in RULE_DEFINITIONS
        ]

        self.assertEqual(
            len(rule_ids),
            len(set(rule_ids)),
        )

        self.assertEqual(
            len(RULES_BY_ID),
            len(RULE_DEFINITIONS),
        )

    def test_generated_findings_use_registered_rule_ids(self):
        samples = (
            SAMPLE,
            REFERENCE_SAMPLE,
            IP_DHCP_VALIDATION_SAMPLE,
            ROUTE_VALIDATION_SAMPLE,
            ADVANCED_FIREWALL_SAMPLE,
            ADVANCED_NAT_SAMPLE,
            ADDITIONAL_SECURITY_SAMPLE,
        )

        unregistered_rule_ids = set()

        for sample in samples:
            result = analyze_config(sample)

            for finding in result["findings"]:
                rule_id = finding["rule_id"]

                if rule_id not in RULES_BY_ID:
                    unregistered_rule_ids.add(
                        rule_id
                    )

        self.assertFalse(
            unregistered_rule_ids,
            unregistered_rule_ids,
        )

    def test_supported_rules_page_is_available(self):
        response = self.client.get(
            reverse("supported_rules")
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            "Supported validation rules",
        )

        self.assertContains(
            response,
            "FW-001",
        )

    def test_supported_rules_page_can_filter_by_category(self):
        response = self.client.get(
            reverse("supported_rules"),
            {
                "category": "NAT",
            },
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            "NAT-001",
        )

        self.assertNotContains(
            response,
            "ROUTE-001",
        )


class AdminRulesTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(
            username="rules-admin",
            email="rules-admin@example.com",
            password="AdminPass123!",
        )

        self.normal_user = User.objects.create_user(
            username="rules-user",
            email="rules-user@example.com",
            password="UserPass123!",
        )

    def test_administrator_can_view_rule_management_page(self):
        self.client.login(
            username="rules-admin",
            password="AdminPass123!",
        )

        response = self.client.get(
            reverse("admin_rules")
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            "Validation rules",
        )

        self.assertContains(
            response,
            "IF-001",
        )

    def test_administrator_can_filter_rules(self):
        self.client.login(
            username="rules-admin",
            password="AdminPass123!",
        )

        response = self.client.get(
            reverse("admin_rules"),
            {
                "category": "NAT",
                "severity": "critical",
            },
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            "NAT-002",
        )

        self.assertNotContains(
            response,
            "ROUTE-001",
        )

    def test_normal_user_cannot_access_rule_management(self):
        self.client.login(
            username="rules-user",
            password="UserPass123!",
        )

        response = self.client.get(
            reverse("admin_rules")
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        self.assertIn(
            "login",
            response.url,
        )


class AuditComparisonTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="comparison-user",
            email="comparison@example.com",
            password="StrongPass123!",
        )

        self.other_user = User.objects.create_user(
            username="comparison-other",
            email="comparison-other@example.com",
            password="StrongPass123!",
        )

        self.baseline = Audit.objects.create(
            owner=self.user,
            title="Baseline Router",
            original_filename="baseline.rsc",
            config_file=SimpleUploadedFile(
                "baseline.rsc",
                b"/system identity set name=baseline",
            ),
            status=Audit.Status.COMPLETED,
            score=50,
            rating="Poor",
            finding_count=2,
            critical_count=1,
            high_count=1,
            category_scores={
                "Firewall": 40,
                "NAT": 60,
            },
        )

        self.current = Audit.objects.create(
            owner=self.user,
            title="Current Router",
            original_filename="current.rsc",
            config_file=SimpleUploadedFile(
                "current.rsc",
                b"/system identity set name=current",
            ),
            status=Audit.Status.COMPLETED,
            score=80,
            rating="Good",
            finding_count=2,
            high_count=1,
            medium_count=1,
            category_scores={
                "Firewall": 75,
                "NAT": 85,
            },
        )

        Finding.objects.create(
            audit=self.baseline,
            rule_id="FW-001",
            title="Missing input drop",
            category="Firewall",
            severity="critical",
            description="Input protection is missing.",
            evidence="No input drop rule found.",
            recommendation="Add a default drop rule.",
        )

        Finding.objects.create(
            audit=self.baseline,
            rule_id="NAT-002",
            title="Broad destination NAT",
            category="NAT",
            severity="high",
            description="Destination NAT is broad.",
            evidence="Broad destination NAT rule.",
            recommendation="Restrict the NAT rule.",
        )

        Finding.objects.create(
            audit=self.current,
            rule_id="FW-001",
            title="Missing input drop",
            category="Firewall",
            severity="high",
            description="Input protection is missing.",
            evidence="No input drop rule found.",
            recommendation="Add a default drop rule.",
        )

        Finding.objects.create(
            audit=self.current,
            rule_id="DHCP-008",
            title="Pool outside interface subnet",
            category="DHCP",
            severity="medium",
            description="The pool is outside the subnet.",
            evidence="Pool 192.168.20.10-192.168.20.50.",
            recommendation="Move the pool into the subnet.",
        )

    def test_comparison_detects_resolved_new_and_unchanged(self):
        result = compare_audits(
            baseline=self.baseline,
            current=self.current,
        )

        self.assertEqual(
            result["score_delta"],
            30,
        )

        self.assertEqual(
            result["outcome"],
            "Improved",
        )

        self.assertEqual(
            result["resolved_count"],
            1,
        )

        self.assertEqual(
            result["new_count"],
            1,
        )

        self.assertEqual(
            result["unchanged_count"],
            1,
        )

        self.assertEqual(
            result["resolved_findings"][0][
                "rule_id"
            ],
            "NAT-002",
        )

        self.assertEqual(
            result["new_findings"][0][
                "rule_id"
            ],
            "DHCP-008",
        )

        self.assertEqual(
            result["unchanged_findings"][0][
                "rule_id"
            ],
            "FW-001",
        )

    def test_comparison_rejects_different_owners(self):
        foreign_audit = Audit.objects.create(
            owner=self.other_user,
            title="Foreign Audit",
            original_filename="foreign.rsc",
            config_file=SimpleUploadedFile(
                "foreign.rsc",
                b"/system identity set name=foreign",
            ),
            status=Audit.Status.COMPLETED,
            score=100,
            rating="Excellent",
        )

        with self.assertRaises(ValueError):
            compare_audits(
                baseline=foreign_audit,
                current=self.current,
            )

    def test_user_can_open_comparison_page(self):
        self.client.login(
            username="comparison-user",
            password="StrongPass123!",
        )

        response = self.client.get(
            reverse(
                "audit_compare",
                args=[self.current.pk],
            ),
            {
                "baseline": self.baseline.pk,
            },
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            "Compare audit results",
        )

        self.assertContains(
            response,
            "Resolved findings",
        )

        self.assertContains(
            response,
            "NAT-002",
        )

    def test_user_cannot_use_another_users_baseline(self):
        foreign_audit = Audit.objects.create(
            owner=self.other_user,
            title="Foreign Baseline",
            original_filename="foreign-baseline.rsc",
            config_file=SimpleUploadedFile(
                "foreign-baseline.rsc",
                b"/system identity set name=foreign",
            ),
            status=Audit.Status.COMPLETED,
            score=90,
            rating="Excellent",
        )

        self.client.login(
            username="comparison-user",
            password="StrongPass123!",
        )

        response = self.client.get(
            reverse(
                "audit_compare",
                args=[self.current.pk],
            ),
            {
                "baseline": foreign_audit.pk,
            },
        )

        self.assertEqual(
            response.status_code,
            404,
        )


class FeaturesPageTests(TestCase):
    def test_features_page_is_publicly_available(self):
        response = self.client.get(
            reverse("features")
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            "NetAudit modules",
        )

        self.assertContains(
            response,
            "Core audit modules",
        )

        self.assertContains(
            response,
            "Before-and-after comparison",
        )

    def test_authenticated_navigation_contains_features(self):
        user = User.objects.create_user(
            username="features-user",
            email="features@example.com",
            password="StrongPass123!",
        )

        self.client.login(
            username="features-user",
            password="StrongPass123!",
        )

        response = self.client.get(
            reverse("features")
        )

        self.assertContains(
            response,
            'href="/features/"',
            html=False,
        )

        self.assertNotContains(
            response,
            ">New audit<",
            html=False,
        )

        self.assertContains(
            response,
            'href="/features/network-map/"',
            html=False,
        )

        self.assertContains(
            response,
            'href="/features/hardening-script/"',
            html=False,
        )


class FeatureShortcutRedirectTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="shortcut-user",
            email="shortcut@example.com",
            password="StrongPass123!",
        )

        self.client.login(
            username="shortcut-user",
            password="StrongPass123!",
        )

    def test_feature_shortcuts_show_source_selection_instead_of_auto_redirect(self):
        audit = Audit.objects.create(
            owner=self.user,
            title="Shortcut Router",
            original_filename="shortcut.rsc",
            config_file=SimpleUploadedFile(
                "shortcut.rsc",
                b"/system identity set name=shortcut",
            ),
            status=Audit.Status.COMPLETED,
            score=82,
            rating="Good",
        )

        shortcuts = {
            "feature_audit_result": "audit_detail",
            "feature_network_map": "audit_topology",
            "feature_attack_surface": "audit_attack_surface",
            "feature_hardening_script": "audit_hardening",
            "feature_before_after": "audit_compare",
        }

        for shortcut_name, target_name in shortcuts.items():
            with self.subTest(shortcut_name=shortcut_name):
                response = self.client.get(reverse(shortcut_name))

                self.assertEqual(response.status_code, 200)
                self.assertContains(response, "Choose source file")
                self.assertContains(response, "This feature will not automatically use an old audit")
                self.assertContains(response, "Shortcut Router")
                self.assertContains(response, reverse(target_name, args=[audit.pk]))

    def test_feature_shortcut_without_completed_audit_still_shows_upload_choice(self):
        response = self.client.get(reverse("feature_network_map"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Network map")
        self.assertContains(response, "No completed audits yet")
        self.assertContains(response, 'name="config_file"')
class ProfileTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="profile-user",
            email="profile@example.com",
            password="OriginalPass123!",
        )

        self.client.login(
            username="profile-user",
            password="OriginalPass123!",
        )

    def test_profile_page_is_available(self):
        response = self.client.get(
            reverse("profile")
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            "Profile details",
        )

        self.assertContains(
            response,
            "Change password",
        )

    def test_user_can_update_profile(self):
        response = self.client.post(
            reverse("profile"),
            {
                "action": "update_profile",
                "profile-first_name": "Network",
                "profile-last_name": "Student",
                "profile-email": "updated-profile@example.com",
            },
        )

        self.user.refresh_from_db()

        self.assertRedirects(
            response,
            reverse("profile"),
        )

        self.assertEqual(
            self.user.first_name,
            "Network",
        )

        self.assertEqual(
            self.user.email,
            "updated-profile@example.com",
        )

    def test_user_can_change_password(self):
        response = self.client.post(
            reverse("profile"),
            {
                "action": "change_password",
                "password-old_password": "OriginalPass123!",
                "password-new_password1": "UpdatedPass123!",
                "password-new_password2": "UpdatedPass123!",
            },
        )

        self.user.refresh_from_db()

        self.assertRedirects(
            response,
            reverse("profile"),
        )

        self.assertTrue(
            self.user.check_password(
                "UpdatedPass123!"
            )
        )

        profile_response = self.client.get(
            reverse("profile")
        )

        self.assertEqual(
            profile_response.status_code,
            200,
        )

    def test_user_password_change_requires_uppercase(self):
        response = self.client.post(
            reverse("profile"),
            {
                "action": "change_password",
                "password-old_password": "OriginalPass123!",
                "password-new_password1": "updatedpass123!",
                "password-new_password2": "updatedpass123!",
            },
        )

        self.user.refresh_from_db()

        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response,
            "Password must contain at least one uppercase letter.",
        )
        self.assertFalse(
            self.user.check_password("updatedpass123!")
        )


class AuditSystemModulePagesTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="module-user",
            email="module@example.com",
            password="StrongPass123!",
        )

        self.audit = Audit.objects.create(
            owner=self.user,
            title="Module Demo Router",
            original_filename="module-demo.rsc",
            config_file=SimpleUploadedFile(
                "module-demo.rsc",
                b"/system identity set name=module-demo",
            ),
            status=Audit.Status.COMPLETED,
            score=55,
            rating="Poor",
            finding_count=1,
            high_count=1,
            configuration_summary={
                "router_identity": "Module-Demo",
                "interfaces": [
                    {"name": "wan", "type": "ethernet", "line_number": 1},
                    {"name": "bridge-lan", "type": "bridge", "line_number": 2},
                ],
                "interface_list_members": [
                    {"interface": "wan", "list": "WAN"},
                    {"interface": "bridge-lan", "list": "LAN"},
                ],
                "ip_addresses": [
                    {"address": "198.51.100.2/24", "interface": "wan"},
                    {"address": "192.168.88.1/24", "interface": "bridge-lan"},
                ],
                "dhcp_pools": [
                    {"name": "lan-pool", "ranges": "192.168.88.20-192.168.88.100"},
                ],
                "dhcp_servers": [
                    {"name": "dhcp-lan", "interface": "bridge-lan", "address_pool": "lan-pool"},
                ],
                "services": [
                    {"name": "winbox", "address": "0.0.0.0/0", "line_number": 5},
                ],
                "firewall_rules": [
                    {"chain": "input", "action": "accept", "in_interface_list": "WAN", "protocol": "tcp", "dst_port": "8291"},
                ],
                "nat_rules": [
                    {"chain": "dstnat", "action": "dst-nat", "dst_port": "8291", "to_addresses": "192.168.88.10"},
                ],
                "routes": [
                    {"destination": "0.0.0.0/0", "gateway": "198.51.100.1", "distance": "1", "type": "unicast"},
                ],
            },
        )

        Finding.objects.create(
            audit=self.audit,
            rule_id="SRV-004",
            title="WinBox management access is unrestricted",
            category="Services",
            severity="high",
            description="WinBox accepts connections without a trusted source restriction.",
            evidence="set winbox address=0.0.0.0/0 disabled=no",
            recommendation="Restrict WinBox to a trusted administrator subnet.",
            suggested_command="/ip service set winbox address=192.168.88.0/24",
        )

        self.client.login(
            username="module-user",
            password="StrongPass123!",
        )

    def test_network_map_page_is_available(self):
        response = self.client.get(
            reverse("audit_topology", args=[self.audit.pk])
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Network map")
        self.assertContains(response, "Module-Demo")
        self.assertContains(response, "Network layout")
        self.assertContains(response, "Router connection layout")
        self.assertContains(response, "Analyze another file")
        self.assertContains(response, 'name="config_file"')
        self.assertContains(response, reverse("audit_create"))

    def test_attack_surface_page_is_available(self):
        response = self.client.get(
            reverse("audit_attack_surface", args=[self.audit.pk])
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Attack surface")
        self.assertContains(response, "winbox")
        self.assertContains(response, "Exposure summary")
        self.assertContains(response, "public entry points")

    def test_hardening_script_page_and_download_are_available(self):
        response = self.client.get(
            reverse("audit_hardening", args=[self.audit.pk])
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Hardening script")
        self.assertContains(response, "/ip service set winbox")
        self.assertContains(response, "Review generated script")
        self.assertContains(response, "administrator decision")

        download_response = self.client.get(
            reverse("hardening_download", args=[self.audit.pk])
        )

        self.assertEqual(download_response.status_code, 200)
        self.assertIn(
            b"/ip service set winbox",
            download_response.content,
        )






# [rev-5384] Reviewed 21 Jul 2026

# [rev-4868] Reviewed 24 Aug 2026

# [rev-8227] Reviewed 26 Aug 2026
