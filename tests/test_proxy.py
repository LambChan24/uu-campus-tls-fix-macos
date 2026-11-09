"""Offline tests: no campus network, public endpoint, or UU account required."""
import asyncio
import contextlib
import ipaddress
import random
import ssl
import unittest
from unittest import mock

import uu_local_proxy as proxy


def hello(host="api.nrd.nie.163.com"):
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ssl.create_default_context().wrap_bio(
        incoming, outgoing, server_side=False, server_hostname=host
    )
    with contextlib.suppress(ssl.SSLWantReadError):
        tls.do_handshake()
    return outgoing.read()


def payloads(records):
    result = b""
    while records:
        if len(records) < 5:
            raise ValueError("Truncated TLS record")
        size = int.from_bytes(records[3:5], "big")
        if len(records) < size + 5:
            raise ValueError("Truncated TLS payload")
        result += records[5:5 + size]
        records = records[5 + size:]
    return result


class PureTests(unittest.TestCase):
    def test_allowlist_boundaries(self):
        for host in [
            "api.nrd.nie.163.com", "SIG-3303-G.NRD.NIE.163.COM",
            "uuyc.webapp.163.com", "fp.ps.netease.com",
        ]:
            self.assertTrue(proxy.is_uu(host))
        for host in [
            "example.com", "nrd.nie.163.com.attacker.invalid",
            "uuyc.webapp.163.com.attacker.invalid", "127.0.0.1",
        ]:
            self.assertFalse(proxy.is_uu(host))

    def test_sni_and_fragment_payload_preservation(self):
        for host in [
            "api.nrd.nie.163.com", "uuyc.webapp.163.com",
            "fp.ps.netease.com", "sig-3303-g.nrd.nie.163.com",
        ]:
            with self.subTest(host=host):
                record = hello(host)
                self.assertEqual(proxy.client_hello_sni(record), host)
                split, changed = proxy.fragment(record, host)
                self.assertTrue(changed)
                self.assertNotEqual(split, record)
                self.assertEqual(payloads(split), payloads(record))

    def test_truncated_hello_has_no_sni(self):
        record = hello()
        for end in range(len(record)):
            self.assertIsNone(proxy.client_hello_sni(record[:end]))

    def test_non_tls_and_missing_sni_not_fragmented(self):
        for record in [b"", b"short", b"\x17\x03\x03\x00\x01x", hello("example.com")]:
            self.assertEqual(proxy.fragment(record, "api.nrd.nie.163.com"), (record, False))

    def test_no_sni_for_ip_client_hello(self):
        self.assertIsNone(proxy.client_hello_sni(hello("127.0.0.1")))

    def test_malformed_inputs_do_not_raise(self):
        rng = random.Random(42)
        for size in range(400):
            record = bytes(rng.randrange(256) for _ in range(size))
            self.assertIsNone(proxy.client_hello_sni(record))


class ProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.calls = []
        self.received = []
        self.logs = []
        self.clients = []
        self.handlers = set()
        proxy.LIMIT = asyncio.Semaphore(48)
        self.real_open = asyncio.open_connection

        async def upstream(reader, writer):
            try:
                data = await reader.read(32768)
                self.received.append(data)
                writer.write(b"fixture-upstream")
                await writer.drain()
            finally:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()

        self.upstream = await asyncio.start_server(upstream, "127.0.0.1", 0)
        self.upstream_port = self.upstream.sockets[0].getsockname()[1]

        async def fake_open(host, port, **kwargs):
            self.calls.append((host, port, kwargs))
            return await self.real_open("127.0.0.1", self.upstream_port)

        async def handler(reader, writer):
            task = asyncio.current_task()
            self.handlers.add(task)
            try:
                await proxy.serve(reader, writer)
            finally:
                self.handlers.discard(task)

        self.open_patch = mock.patch.object(proxy.asyncio, "open_connection", fake_open)
        self.log_patch = mock.patch.object(proxy, "log", self.logs.append)
        self.open_patch.start()
        self.log_patch.start()
        self.server = await asyncio.start_server(handler, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        for writer in self.clients:
            writer.close()
        self.server.close()
        await self.server.wait_closed()
        for task in list(self.handlers):
            task.cancel()
        await asyncio.gather(*self.handlers, return_exceptions=True)
        self.upstream.close()
        await self.upstream.wait_closed()
        self.open_patch.stop()
        self.log_patch.stop()

    async def client(self):
        reader, writer = await self.real_open("127.0.0.1", self.port)
        self.clients.append(writer)
        return reader, writer

    async def socks(self, host, port=443, ip=False):
        reader, writer = await self.client()
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        self.assertEqual(await reader.readexactly(2), b"\x05\x00")
        if ip:
            addr = ipaddress.ip_address(host)
            address = bytes([1 if addr.version == 4 else 4]) + addr.packed
        else:
            name = host.encode("ascii")
            address = b"\x03" + bytes([len(name)]) + name
        writer.write(b"\x05\x01\x00" + address + port.to_bytes(2, "big"))
        await writer.drain()
        response = await asyncio.wait_for(reader.readexactly(10), 2)
        return reader, writer, response

    async def test_socks_allowed_tls_relay(self):
        reader, writer, response = await self.socks("api.nrd.nie.163.com")
        self.assertEqual(response[1], 0)
        record = hello()
        writer.write(record)
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(64), 2), b"fixture-upstream")
        self.assertEqual(self.calls[0][0], proxy.ENDPOINTS["api.nrd.nie.163.com"])
        self.assertEqual(payloads(self.received[0]), payloads(record))

    async def test_socks_unknown_domain_rejected_without_upstream(self):
        _, _, response = await self.socks("example.com")
        self.assertEqual(response[1], 2)
        self.assertEqual(self.calls, [])

    async def test_unsupported_port_rejected(self):
        _, _, response = await self.socks("api.nrd.nie.163.com", 53)
        self.assertEqual(response[1], 2)
        self.assertEqual(self.calls, [])

    async def test_socks_requires_supported_auth(self):
        reader, writer = await self.client()
        writer.write(b"\x05\x01\x02")
        await writer.drain()
        self.assertEqual(await reader.readexactly(2), b"\x05\xff")
        self.assertEqual(self.calls, [])

    async def test_ipv4_connect_uses_approved_sni_not_requested_ip(self):
        reader, writer, response = await self.socks("192.0.2.25", ip=True)
        self.assertEqual(response[1], 0)
        self.assertEqual(self.calls, [])
        writer.write(hello("sig-3303-g.nrd.nie.163.com"))
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(64), 2), b"fixture-upstream")
        self.assertEqual(self.calls[0][0], proxy.ENDPOINTS["sig-3303-g.nrd.nie.163.com"])

    async def test_ip_with_unapproved_sni_rejected_without_upstream(self):
        reader, writer, _ = await self.socks("192.0.2.25", ip=True)
        writer.write(hello("example.com"))
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(64), 2), b"")
        self.assertEqual(self.calls, [])

    async def test_ipv6_connect_without_sni_rejected_without_upstream(self):
        reader, writer, _ = await self.socks("2001:db8::25", ip=True)
        writer.write(hello("127.0.0.1"))
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(64), 2), b"")
        self.assertEqual(self.calls, [])

    async def test_oversized_tls_record_rejected_without_upstream(self):
        reader, writer, _ = await self.socks("api.nrd.nie.163.com")
        writer.write(b"\x16\x03\x03\xff\xff")
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(64), 2), b"")
        self.assertEqual(self.calls, [])

    async def test_http_connect_allowed(self):
        reader, writer = await self.client()
        writer.write(b"CONNECT uuyc.webapp.163.com:443 HTTP/1.1\r\n\r\n")
        await writer.drain()
        response = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
        self.assertIn(b"200 Connection Established", response)
        writer.write(hello("uuyc.webapp.163.com"))
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(64), 2), b"fixture-upstream")

    async def test_http_connect_unknown_domain_rejected(self):
        reader, writer = await self.client()
        writer.write(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
        await writer.drain()
        self.assertIn(b"403 Forbidden", await asyncio.wait_for(reader.read(512), 2))
        self.assertEqual(self.calls, [])

    async def test_http_non_connect_rejected(self):
        reader, writer = await self.client()
        writer.write(b"GET / HTTP/1.1\r\n\r\n")
        await writer.drain()
        self.assertIn(b"405 Method Not Allowed", await asyncio.wait_for(reader.read(512), 2))
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
