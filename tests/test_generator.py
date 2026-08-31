"""pcap_generator.generator 的单元测试。"""

import os
import tempfile
import unittest

from scapy.all import rdpcap
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from pcap_generator import PcapGenerator


class PcapGeneratorTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.gen = PcapGenerator()

    def test_add_tcp_packet(self) -> None:
        pkt = self.gen.add_tcp_packet(
            "192.168.1.1", "192.168.1.2", 12345, 80, payload=b"hello"
        )
        self.assertEqual(len(self.gen.packets), 1)
        self.assertTrue(pkt.haslayer(TCP))
        self.assertEqual(pkt[IP].src, "192.168.1.1")
        self.assertEqual(pkt[IP].dst, "192.168.1.2")
        self.assertEqual(pkt[TCP].sport, 12345)
        self.assertEqual(pkt[TCP].dport, 80)
        self.assertEqual(bytes(pkt[Raw].load), b"hello")

    def test_add_udp_packet(self) -> None:
        pkt = self.gen.add_udp_packet(
            "10.0.0.1", "10.0.0.2", 5000, 53, payload=b"query"
        )
        self.assertTrue(pkt.haslayer(UDP))
        self.assertEqual(pkt[UDP].sport, 5000)
        self.assertEqual(pkt[UDP].dport, 53)
        self.assertEqual(bytes(pkt[Raw].load), b"query")

    def test_add_icmp_packet(self) -> None:
        pkt = self.gen.add_icmp_packet("172.16.0.1", "172.16.0.2")
        self.assertTrue(pkt.haslayer(ICMP))
        self.assertEqual(pkt[IP].src, "172.16.0.1")
        self.assertEqual(pkt[IP].dst, "172.16.0.2")

    def test_add_arp_packet(self) -> None:
        pkt = self.gen.add_arp_packet(
            "192.168.1.1", "192.168.1.2", "00:11:22:33:44:55"
        )
        self.assertTrue(pkt.haslayer(ARP))
        self.assertEqual(pkt[ARP].psrc, "192.168.1.1")
        self.assertEqual(pkt[ARP].pdst, "192.168.1.2")
        self.assertEqual(pkt[Ether].src, "00:11:22:33:44:55")

    def test_add_raw_packet(self) -> None:
        pkt = self.gen.add_raw_packet(b"\xde\xad\xbe\xef")
        self.assertTrue(pkt.haslayer(Ether))
        self.assertEqual(bytes(pkt[Raw].load), b"\xde\xad\xbe\xef")

    def test_add_http_request(self) -> None:
        pkt = self.gen.add_http_request(
            "192.168.1.10",
            "93.184.216.34",
            method="GET",
            host="example.com",
            path="/index.html",
        )
        payload = bytes(pkt[Raw].load)
        self.assertIn(b"GET /index.html HTTP/1.1", payload)
        self.assertIn(b"Host: example.com", payload)

    def test_add_http_request_with_body(self) -> None:
        body = b'{"user": "admin"}'
        pkt = self.gen.add_http_request(
            "192.168.1.10",
            "93.184.216.34",
            method="POST",
            host="example.com",
            path="/api/login",
            body=body,
        )
        payload = bytes(pkt[Raw].load)
        self.assertIn(b"POST /api/login HTTP/1.1", payload)
        self.assertTrue(payload.endswith(body))
        self.assertIn(f"Content-Length: {len(body)}".encode(), payload)

    def test_add_http_response(self) -> None:
        body = b"<html>Hello</html>"
        pkt = self.gen.add_http_response(
            "93.184.216.34",
            "192.168.1.10",
            status_code=200,
            status_text="OK",
            body=body,
        )
        payload = bytes(pkt[Raw].load)
        self.assertIn(b"HTTP/1.1 200 OK", payload)
        self.assertTrue(payload.endswith(body))

    def test_clear(self) -> None:
        self.gen.add_icmp_packet("10.0.0.1", "10.0.0.2")
        self.assertEqual(len(self.gen.packets), 1)
        self.gen.clear()
        self.assertEqual(len(self.gen.packets), 0)

    def test_write_empty_raises(self) -> None:
        with self.assertRaises(ValueError):
            self.gen.write("should_not_be_created.pcap")

    def test_write(self) -> None:
        self.gen.add_tcp_packet("10.0.0.1", "10.0.0.2", 1234, 80, payload=b"abc")
        self.gen.add_udp_packet("10.0.0.1", "10.0.0.2", 1234, 53, payload=b"def")

        with tempfile.TemporaryDirectory() as tmpdir:
            filename = os.path.join(tmpdir, "test.pcap")
            self.gen.write(filename)
            self.assertTrue(os.path.exists(filename))

            packets = rdpcap(filename)
            self.assertEqual(len(packets), 2)


if __name__ == "__main__":
    unittest.main()
