# pcap-generator

使用 Python 编写的 PCAP 文件生成工具，基于 [scapy](https://scapy.net/) 构造数据包。

## 功能特性

- 支持生成 TCP、UDP、ICMP、ARP 等常见协议的数据包
- 支持自定义原始字节作为 payload 写入数据包
- 支持生成 HTTP 请求（GET/POST 等）和 HTTP 响应包
- 提供命令行工具 `pcap-gen`
- 提供 Python API，方便在其他程序中调用

## 安装

```bash
pip install -r requirements.txt
pip install -e .
```

安装完成后即可使用 `pcap-gen` 命令行工具。

## CLI 用法示例

生成 TCP 数据包：

```bash
pcap-gen tcp --src-ip 192.168.1.1 --dst-ip 192.168.1.2 \
    --src-port 12345 --dst-port 80 --payload "hello" -o tcp.pcap
```

生成 UDP 数据包：

```bash
pcap-gen udp --src-ip 192.168.1.1 --dst-ip 192.168.1.2 \
    --src-port 12345 --dst-port 53 --payload "hello" -o udp.pcap
```

生成 ICMP 数据包：

```bash
pcap-gen icmp --src-ip 192.168.1.1 --dst-ip 192.168.1.2 -o icmp.pcap
```

生成 ARP 数据包：

```bash
pcap-gen arp --src-ip 192.168.1.1 --dst-ip 192.168.1.2 \
    --src-mac 00:11:22:33:44:55 -o arp.pcap
```

生成自定义原始字节数据包：

```bash
pcap-gen raw --payload-hex "deadbeef" -o raw.pcap
```

生成 HTTP 请求包：

```bash
pcap-gen http-request --src-ip 192.168.1.10 --dst-ip 93.184.216.34 \
    --method GET --host example.com --path /index.html -o http_req.pcap
```

生成 HTTP 响应包：

```bash
pcap-gen http-response --src-ip 93.184.216.34 --dst-ip 192.168.1.10 \
    --status-code 200 --status-text OK --body "<html>Hello</html>" -o http_resp.pcap
```

## Python API 用法示例

```python
from pcap_generator import PcapGenerator

gen = PcapGenerator()

# TCP 包
gen.add_tcp_packet("192.168.1.1", "192.168.1.2", 12345, 80, payload=b"hello")

# UDP 包
gen.add_udp_packet("192.168.1.1", "192.168.1.2", 12345, 53, payload=b"query")

# ICMP 包
gen.add_icmp_packet("192.168.1.1", "192.168.1.2")

# ARP 包
gen.add_arp_packet("192.168.1.1", "192.168.1.2", "00:11:22:33:44:55")

# 自定义原始字节包
gen.add_raw_packet(b"\xde\xad\xbe\xef")

# HTTP 请求包
gen.add_http_request(
    "192.168.1.10", "93.184.216.34",
    method="GET", host="example.com", path="/index.html",
)

# HTTP 响应包
gen.add_http_response(
    "93.184.216.34", "192.168.1.10",
    status_code=200, status_text="OK", body=b"<html>Hello</html>",
)

# 写入 pcap 文件
gen.write("output.pcap")

# 清空已添加的数据包
gen.clear()
```

更多示例可参考 [`examples/example.py`](examples/example.py)。

## 运行测试

```bash
pip install -r requirements.txt
python -m unittest discover tests
```

## 许可证

本项目使用 [MIT License](LICENSE)。
