"""核心 PCAP 生成器模块。

提供 :class:`PcapGenerator` 类，用于构造常见协议（TCP、UDP、ICMP、ARP）
的数据包、自定义原始字节包，以及 HTTP 请求/响应包，并将其写入 PCAP 文件。
"""

from __future__ import annotations

from typing import Dict, List, Optional

from scapy.data import DLT_EN10MB
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw
from scapy.utils import PcapWriter


class PcapGenerator:
    """PCAP 数据包生成器。

    用于构建各种协议的数据包并写入 PCAP 文件，也可以作为 Python API
    在其他程序中调用。
    """

    def __init__(self) -> None:
        self.packets: List[Packet] = []

    def add_tcp_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        payload: bytes = b"",
        flags: str = "S",
        seq: int = 1000,
        ack: int = 0,
    ) -> Packet:
        """添加一个 TCP 数据包。"""
        pkt = (
            Ether()
            / IP(src=src_ip, dst=dst_ip)
            / TCP(sport=src_port, dport=dst_port, flags=flags, seq=seq, ack=ack)
        )
        if payload:
            pkt = pkt / Raw(load=payload)
        self.packets.append(pkt)
        return pkt

    def add_udp_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        payload: bytes = b"",
    ) -> Packet:
        """添加一个 UDP 数据包。"""
        pkt = Ether() / IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port)
        if payload:
            pkt = pkt / Raw(load=payload)
        self.packets.append(pkt)
        return pkt

    def add_icmp_packet(self, src_ip: str, dst_ip: str) -> Packet:
        """添加一个 ICMP (echo request) 数据包。"""
        pkt = Ether() / IP(src=src_ip, dst=dst_ip) / ICMP()
        self.packets.append(pkt)
        return pkt

    def add_arp_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_mac: str,
        dst_mac: str = "ff:ff:ff:ff:ff:ff",
    ) -> Packet:
        """添加一个 ARP 数据包（默认为 who-has 请求）。"""
        pkt = Ether(src=src_mac, dst=dst_mac) / ARP(
            hwsrc=src_mac,
            psrc=src_ip,
            hwdst=dst_mac if dst_mac != "ff:ff:ff:ff:ff:ff" else "00:00:00:00:00:00",
            pdst=dst_ip,
        )
        self.packets.append(pkt)
        return pkt

    def add_raw_packet(self, raw_bytes: bytes) -> Packet:
        """添加一个自定义原始字节数据包。

        ``raw_bytes`` 会被当作以太网帧的载荷写入（即数据包内容为
        ``Ether() / Raw(load=raw_bytes)``），这样可以与其他协议数据包
        一起写入同一个 PCAP 文件，而不会产生 link-type 不一致的问题。
        """
        pkt = Ether() / Raw(load=raw_bytes)
        self.packets.append(pkt)
        return pkt

    def add_http_request(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int = 12345,
        dst_port: int = 80,
        method: str = "GET",
        host: str = "example.com",
        path: str = "/",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
    ) -> Packet:
        """添加一个 HTTP 请求数据包。"""
        header_lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
        merged_headers = dict(headers or {})
        merged_headers.setdefault("User-Agent", "pcap-generator")
        merged_headers.setdefault("Accept", "*/*")
        if body:
            merged_headers.setdefault("Content-Length", str(len(body)))
        for key, value in merged_headers.items():
            header_lines.append(f"{key}: {value}")
        header_lines.append("Connection: close")

        request_text = "\r\n".join(header_lines) + "\r\n\r\n"
        payload = request_text.encode("utf-8")
        if body:
            payload += body

        return self.add_tcp_packet(
            src_ip, dst_ip, src_port, dst_port, payload=payload, flags="PA"
        )

    def add_http_response(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int = 80,
        dst_port: int = 12345,
        status_code: int = 200,
        status_text: str = "OK",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
    ) -> Packet:
        """添加一个 HTTP 响应数据包。"""
        body_bytes = body if body is not None else b""
        header_lines = [f"HTTP/1.1 {status_code} {status_text}"]
        merged_headers = dict(headers or {})
        merged_headers.setdefault("Server", "pcap-generator")
        merged_headers.setdefault("Content-Type", "text/html; charset=utf-8")
        merged_headers.setdefault("Content-Length", str(len(body_bytes)))
        for key, value in merged_headers.items():
            header_lines.append(f"{key}: {value}")
        header_lines.append("Connection: close")

        response_text = "\r\n".join(header_lines) + "\r\n\r\n"
        payload = response_text.encode("utf-8") + body_bytes

        return self.add_tcp_packet(
            src_ip, dst_ip, src_port, dst_port, payload=payload, flags="PA"
        )

    def clear(self) -> None:
        """清空已添加的所有数据包。"""
        self.packets = []

    def write(self, filename: str) -> None:
        """将所有已添加的数据包写入 PCAP 文件。

        :raises ValueError: 当没有任何数据包被添加时抛出。
        """
        if not self.packets:
            raise ValueError("没有可写入的数据包，请先添加至少一个数据包")

        # 显式指定以太网 linktype，并将每个数据包序列化为原始字节后再写入。
        # 这样即使混合了不同协议层次的数据包，scapy 也不会因无法为其自动
        # 推断 linktype 而报错。
        writer = PcapWriter(filename, linktype=DLT_EN10MB)
        try:
            for pkt in self.packets:
                writer.write(bytes(pkt))
        finally:
            writer.close()
