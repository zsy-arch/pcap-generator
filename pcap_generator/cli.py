"""命令行接口模块，提供 ``pcap-gen`` 命令。"""

from __future__ import annotations

import argparse
import sys
from typing import Dict, List, Optional

from .generator import PcapGenerator


def _parse_headers(header_args: Optional[List[str]]) -> Dict[str, str]:
    """将 ``Key: Value`` 或 ``Key=Value`` 形式的字符串列表解析为字典。"""
    headers: Dict[str, str] = {}
    for item in header_args or []:
        if ":" in item:
            key, value = item.split(":", 1)
        elif "=" in item:
            key, value = item.split("=", 1)
        else:
            raise ValueError(f"无效的 header 格式: {item!r}，应为 'Key: Value'")
        headers[key.strip()] = value.strip()
    return headers


def _parse_payload(payload: Optional[str], payload_hex: Optional[str]) -> bytes:
    if payload_hex:
        return bytes.fromhex(payload_hex.replace(" ", ""))
    if payload is not None:
        return payload.encode("utf-8")
    return b""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pcap-gen", description="生成 PCAP 文件的命令行工具"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_output_arg(sp: argparse.ArgumentParser) -> None:
        sp.add_argument(
            "-o", "--output", default="output.pcap", help="输出的 PCAP 文件名"
        )

    # tcp
    tcp_parser = subparsers.add_parser("tcp", help="生成 TCP 数据包")
    tcp_parser.add_argument("--src-ip", required=True, help="源 IP 地址")
    tcp_parser.add_argument("--dst-ip", required=True, help="目的 IP 地址")
    tcp_parser.add_argument("--src-port", type=int, required=True, help="源端口")
    tcp_parser.add_argument("--dst-port", type=int, required=True, help="目的端口")
    tcp_parser.add_argument("--payload", default="", help="载荷内容（文本）")
    tcp_parser.add_argument("--payload-hex", default=None, help="载荷内容（十六进制字符串）")
    add_output_arg(tcp_parser)

    # udp
    udp_parser = subparsers.add_parser("udp", help="生成 UDP 数据包")
    udp_parser.add_argument("--src-ip", required=True, help="源 IP 地址")
    udp_parser.add_argument("--dst-ip", required=True, help="目的 IP 地址")
    udp_parser.add_argument("--src-port", type=int, required=True, help="源端口")
    udp_parser.add_argument("--dst-port", type=int, required=True, help="目的端口")
    udp_parser.add_argument("--payload", default="", help="载荷内容（文本）")
    udp_parser.add_argument("--payload-hex", default=None, help="载荷内容（十六进制字符串）")
    add_output_arg(udp_parser)

    # icmp
    icmp_parser = subparsers.add_parser("icmp", help="生成 ICMP 数据包")
    icmp_parser.add_argument("--src-ip", required=True, help="源 IP 地址")
    icmp_parser.add_argument("--dst-ip", required=True, help="目的 IP 地址")
    add_output_arg(icmp_parser)

    # arp
    arp_parser = subparsers.add_parser("arp", help="生成 ARP 数据包")
    arp_parser.add_argument("--src-ip", required=True, help="源 IP 地址")
    arp_parser.add_argument("--dst-ip", required=True, help="目的 IP 地址")
    arp_parser.add_argument("--src-mac", required=True, help="源 MAC 地址")
    arp_parser.add_argument(
        "--dst-mac", default="ff:ff:ff:ff:ff:ff", help="目的 MAC 地址"
    )
    add_output_arg(arp_parser)

    # raw
    raw_parser = subparsers.add_parser("raw", help="生成自定义原始字节数据包")
    group = raw_parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--payload", help="原始载荷内容（文本）")
    group.add_argument("--payload-hex", help="原始载荷内容（十六进制字符串）")
    add_output_arg(raw_parser)

    # http-request
    req_parser = subparsers.add_parser("http-request", help="生成 HTTP 请求数据包")
    req_parser.add_argument("--src-ip", required=True, help="源 IP 地址")
    req_parser.add_argument("--dst-ip", required=True, help="目的 IP 地址")
    req_parser.add_argument("--src-port", type=int, default=12345, help="源端口")
    req_parser.add_argument("--dst-port", type=int, default=80, help="目的端口")
    req_parser.add_argument("--method", default="GET", help="HTTP 方法")
    req_parser.add_argument("--host", default="example.com", help="Host 头")
    req_parser.add_argument("--path", default="/", help="请求路径")
    req_parser.add_argument(
        "--header", action="append", help="自定义请求头，格式 'Key: Value'，可多次指定"
    )
    req_parser.add_argument("--body", default=None, help="请求体内容（文本）")
    add_output_arg(req_parser)

    # http-response
    resp_parser = subparsers.add_parser("http-response", help="生成 HTTP 响应数据包")
    resp_parser.add_argument("--src-ip", required=True, help="源 IP 地址")
    resp_parser.add_argument("--dst-ip", required=True, help="目的 IP 地址")
    resp_parser.add_argument("--src-port", type=int, default=80, help="源端口")
    resp_parser.add_argument("--dst-port", type=int, default=12345, help="目的端口")
    resp_parser.add_argument("--status-code", type=int, default=200, help="HTTP 状态码")
    resp_parser.add_argument("--status-text", default="OK", help="HTTP 状态描述")
    resp_parser.add_argument(
        "--header", action="append", help="自定义响应头，格式 'Key: Value'，可多次指定"
    )
    resp_parser.add_argument("--body", default=None, help="响应体内容（文本）")
    add_output_arg(resp_parser)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    generator = PcapGenerator()

    try:
        headers = _parse_headers(getattr(args, "header", None))
    except ValueError as exc:
        parser.error(str(exc))
        return 2

    if args.command == "tcp":
        generator.add_tcp_packet(
            args.src_ip,
            args.dst_ip,
            args.src_port,
            args.dst_port,
            payload=_parse_payload(args.payload, args.payload_hex),
        )
    elif args.command == "udp":
        generator.add_udp_packet(
            args.src_ip,
            args.dst_ip,
            args.src_port,
            args.dst_port,
            payload=_parse_payload(args.payload, args.payload_hex),
        )
    elif args.command == "icmp":
        generator.add_icmp_packet(args.src_ip, args.dst_ip)
    elif args.command == "arp":
        generator.add_arp_packet(
            args.src_ip, args.dst_ip, args.src_mac, args.dst_mac
        )
    elif args.command == "raw":
        generator.add_raw_packet(_parse_payload(args.payload, args.payload_hex))
    elif args.command == "http-request":
        body = args.body.encode("utf-8") if args.body is not None else None
        generator.add_http_request(
            args.src_ip,
            args.dst_ip,
            src_port=args.src_port,
            dst_port=args.dst_port,
            method=args.method,
            host=args.host,
            path=args.path,
            headers=headers,
            body=body,
        )
    elif args.command == "http-response":
        body = args.body.encode("utf-8") if args.body is not None else None
        generator.add_http_response(
            args.src_ip,
            args.dst_ip,
            src_port=args.src_port,
            dst_port=args.dst_port,
            status_code=args.status_code,
            status_text=args.status_text,
            headers=headers,
            body=body,
        )
    else:  # pragma: no cover - argparse 保证 command 有效
        parser.error(f"未知命令: {args.command}")
        return 2

    generator.write(args.output)
    print(f"已生成 PCAP 文件: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
