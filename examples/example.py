"""pcap_generator 使用示例脚本。

运行方式：
    python examples/example.py
"""

from pcap_generator import PcapGenerator


def main() -> None:
    gen = PcapGenerator()

    # TCP 数据包
    gen.add_tcp_packet(
        "192.168.1.1", "192.168.1.2", 12345, 80, payload=b"hello tcp"
    )

    # UDP 数据包
    gen.add_udp_packet(
        "192.168.1.1", "192.168.1.2", 12345, 53, payload=b"hello udp"
    )

    # ICMP 数据包
    gen.add_icmp_packet("192.168.1.1", "192.168.1.2")

    # ARP 数据包
    gen.add_arp_packet("192.168.1.1", "192.168.1.2", "00:11:22:33:44:55")

    # 自定义原始字节数据包
    gen.add_raw_packet(b"\xde\xad\xbe\xef")

    # HTTP 请求包
    gen.add_http_request(
        "192.168.1.10",
        "93.184.216.34",
        method="GET",
        host="example.com",
        path="/index.html",
    )

    # HTTP POST 请求包（带请求体）
    gen.add_http_request(
        "192.168.1.10",
        "93.184.216.34",
        method="POST",
        host="example.com",
        path="/api/login",
        headers={"Content-Type": "application/json"},
        body=b'{"user": "admin", "pass": "123456"}',
    )

    # HTTP 响应包
    gen.add_http_response(
        "93.184.216.34",
        "192.168.1.10",
        status_code=200,
        status_text="OK",
        body=b"<html><body>Hello</body></html>",
    )

    output_file = "example_output.pcap"
    gen.write(output_file)
    print(f"已生成示例 PCAP 文件: {output_file}，共 {len(gen.packets)} 个数据包")


if __name__ == "__main__":
    main()
