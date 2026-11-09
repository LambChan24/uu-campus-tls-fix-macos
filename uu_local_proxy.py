"""Local-only UU TLS record adapter. End-to-end TLS is never terminated.

No upstream proxy, DNS server, certificate installation, or system settings.
"""
import asyncio
import contextlib
import datetime
import ipaddress
import signal

HOST = "127.0.0.1"
PORT = 17899
LIMIT = asyncio.Semaphore(48)
UU_SUFFIX = ".nrd.nie.163.com"
# Exact additional hosts observed in the UU client's own proxy requests.
UU_EXTRA_HOSTS = {"uuyc.webapp.163.com", "fp.ps.netease.com"}
# Project-supplied endpoints, independently tested with hostname verification.
# These mappings affect only this adapter; system DNS and hosts are unchanged.
ENDPOINTS = {
    "api.nrd.nie.163.com": "112.13.123.98",
    "api-ipv4.nrd.nie.163.com": "112.13.123.98",
    "sig-3303-d.nrd.nie.163.com": "34.95.122.33",
    "sig-3303-g.nrd.nie.163.com": "34.95.122.33",
    "relay-mg-3303-g.nrd.nie.163.com": "117.147.201.40",
}


def log(message):
    print(datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
          message, flush=True)


def is_uu(host):
    return host.lower().endswith(UU_SUFFIX) or host.lower() in UU_EXTRA_HOSTS


def client_hello_sni(record):
    """Read SNI structurally; do not infer a hostname from arbitrary TLS bytes."""
    try:
        if record[0] != 22 or record[5] != 1:
            return None
        hello_size = int.from_bytes(record[6:9], "big")
        body = record[9:9 + hello_size]
        if len(body) != hello_size:
            return None
        pos = 34
        pos += 1 + body[pos]
        size = int.from_bytes(body[pos:pos + 2], "big")
        pos += 2 + size
        pos += 1 + body[pos]
        end = pos + 2 + int.from_bytes(body[pos:pos + 2], "big")
        pos += 2
        if end > len(body):
            return None
        while pos + 4 <= end:
            kind = int.from_bytes(body[pos:pos + 2], "big")
            size = int.from_bytes(body[pos + 2:pos + 4], "big")
            pos += 4
            if pos + size > end:
                return None
            extension = body[pos:pos + size]
            pos += size
            if kind == 0:
                if len(extension) < 5:
                    return None
                if int.from_bytes(extension[:2], "big") != len(extension) - 2:
                    return None
                name_size = int.from_bytes(extension[3:5], "big")
                if extension[2] != 0 or name_size + 5 != len(extension):
                    return None
                return extension[5:].decode("ascii").lower()
    except (IndexError, UnicodeDecodeError):
        return None
    return None


def fragment(record, host):
    if len(record) < 6 or record[0] != 22 or record[5] != 1:
        return record, False
    payload = record[5:]
    marker = host.lower().encode("ascii")
    index = payload.lower().find(marker)
    if index < 0:
        marker = b"nrd.nie.163.com"
        index = payload.lower().find(marker)
    if index < 0:
        return record, False
    cut = index + len(marker) // 2
    return (record[:3] + cut.to_bytes(2, "big") + payload[:cut]
            + record[:3] + (len(payload) - cut).to_bytes(2, "big")
            + payload[cut:]), True


async def exact(reader, count):
    return await asyncio.wait_for(reader.readexactly(count), 10)


async def pump(reader, writer):
    while chunk := await reader.read(65536):
        writer.write(chunk)
        await writer.drain()


async def serve(reader, writer):
    remote = None
    target = "unparsed"
    try:
        async with LIMIT:
            first = await exact(reader, 1)
            protocol = "http"
            if first == b"\x05":
                protocol = "socks5"
                count = (await exact(reader, 1))[0]
                methods = await exact(reader, count)
                if 0 not in methods:
                    writer.write(b"\x05\xff")
                    await writer.drain()
                    return
                writer.write(b"\x05\x00")
                await writer.drain()
                header = await exact(reader, 4)
                if header[:3] != b"\x05\x01\x00":
                    raise ValueError("Only SOCKS5 CONNECT is supported")
                if header[3] == 1:
                    target = str(ipaddress.ip_address(await exact(reader, 4)))
                elif header[3] == 4:
                    target = str(ipaddress.ip_address(await exact(reader, 16)))
                elif header[3] == 3:
                    n = (await exact(reader, 1))[0]
                    target = (await exact(reader, n)).decode("ascii")
                else:
                    raise ValueError("Invalid SOCKS address type")
                port = int.from_bytes(await exact(reader, 2), "big")
            else:
                header = first + await asyncio.wait_for(
                    reader.readuntil(b"\r\n\r\n"), 10
                )
                if len(header) > 16384:
                    raise ValueError("Oversized CONNECT header")
                request = header.split(b"\r\n", 1)[0].decode("ascii")
                method, authority, _ = request.split(" ", 2)
                if method != "CONNECT":
                    writer.write(b"HTTP/1.1 405 Method Not Allowed\r\n"
                                 b"Connection: close\r\nContent-Length: 0\r\n\r\n")
                    await writer.drain()
                    return
                target, port_text = authority.rsplit(":", 1)
                target, port = target.strip("[]"), int(port_text)
            try:
                ipaddress.ip_address(target)
                target_is_ip = True
            except ValueError:
                target_is_ip = False
            if port != 443 or (not target_is_ip and not is_uu(target)):
                if protocol == "socks5":
                    writer.write(b"\x05\x02\x00\x01" + b"\x00" * 6)
                else:
                    writer.write(b"HTTP/1.1 403 Forbidden\r\n"
                                 b"Connection: close\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                log(f"REJECT non-UU target={target}:{port}")
                return
            # For IP-form CONNECT, acknowledge locally to receive ClientHello,
            # then require an approved SNI BEFORE making any upstream connection.
            if protocol == "socks5":
                writer.write(b"\x05\x00\x00\x01" + b"\x00" * 6)
            else:
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            record_header = await exact(reader, 5)
            size = int.from_bytes(record_header[3:5], "big")
            if size > 18432:
                raise ValueError("Oversized TLS record")
            record = record_header + await exact(reader, size)
            sni = client_hello_sni(record)
            if target_is_ip:
                if not sni or not is_uu(sni):
                    log(f"REJECT IP target={target}:443 without approved UU SNI")
                    return
                log(f"IP-SNI {target} -> {sni}")
                target = sni
            remote_reader, remote = await asyncio.wait_for(
                asyncio.open_connection(ENDPOINTS.get(target.lower(), target),
                                        port, family=2), 6
            )
            data, changed = fragment(record, target)
            remote.write(data)
            await remote.drain()
            log(f"CONNECT {protocol} {target} fragmented={changed}")
            tasks = [asyncio.create_task(pump(reader, remote)),
                     asyncio.create_task(pump(remote_reader, writer))]
            try:
                done, pending = await asyncio.wait(
                    tasks, return_when=asyncio.FIRST_COMPLETED
                )
                for task in done:
                    task.result()
            finally:
                for task in tasks:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
    except Exception as error:
        log(f"ERROR {target} {type(error).__name__}")
    finally:
        for stream in (remote, writer):
            if stream:
                stream.close()
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(stream.wait_closed(), 2)


async def main():
    server = await asyncio.start_server(serve, HOST, PORT, limit=32768)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    log(f"LISTEN {HOST}:{PORT}; UU allowlist only; no TLS termination")
    async with server:
        await stop.wait()


if __name__ == "__main__":
    asyncio.run(main())
