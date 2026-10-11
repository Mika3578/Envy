#!/usr/bin/env python3
"""Loopback-only HTTP fixtures for manual Envy metadata/THEX validation."""

# SPDX-License-Identifier: AGPL-3.0-or-later

import argparse
import base64
import hashlib
import socket
import struct
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


FILE = bytes(range(256)) * 256
TIGER_FILE = b"A" * 1024
# THEX specification Appendix A: Tiger root of 1024 'A' bytes.
TIGER_ROOT = "L66Q4YVNAFWVS23X2HJIRA5ZJ7WXR3F26RSASFA"
TREE_TYPE = b"http://open-content.net/spec/thex/breadthfirst"
TREE_ID = b"uuid:envy-peer-xml-fixture"


def dime(flags, kind, record_id, record_type, body):
    def padded(value):
        return value + b"\0" * (-len(value) % 4)

    header = struct.pack(
        "!BBHHHI", 0x08 | flags, kind, 0, len(record_id), len(record_type), len(body)
    )
    return header + padded(record_id) + padded(record_type) + padded(body)


def thex_records():
    xml = (
        b'<?xml version="1.0"?><hashtree><file size="1024" segmentsize="1024"/>'
        b'<digest algorithm="http://open-content.net/spec/digest/tiger" outputsize="24"/>'
        b'<serializedtree depth="1" type="' + TREE_TYPE + b'" uri="' + TREE_ID
        + b'"/><!--' + b"x" * 20000 + b"--></hashtree>"
    )
    return (
        dime(4, 0x10, b"", b"text/xml", xml),
        dime(2, 0x20, TREE_ID, TREE_TYPE, base64.b32decode(TIGER_ROOT + "=")),
    )


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path.startswith("/thex-"):
            descriptor, tree = thex_records()
            body = descriptor + tree
            self.send_response(200)
            self.send_header("Content-Type", "application/dime")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if path == "/thex-split":
                self.wfile.write(descriptor + tree[:13])
                self.wfile.flush()
                # Force a partial tree record after the complete descriptor.
                time.sleep(0.25)
                self.wfile.write(tree[13:])
            elif path == "/thex-short":
                self.wfile.write(body[:-1])
            else:
                self.wfile.write(body)
        elif path.startswith("/metadata-"):
            body = b'<?xml version="1.0"?><audio title="Peer XML fixture"/>'
            if path == "/metadata-deep":
                body = b'<?xml version="1.0"?>' + b"<a>" * 33 + b"</a>" * 33
            elif path == "/metadata-large":
                body = b'<?xml version="1.0"?><a>' + b"x" * (256 * 1024) + b"</a>"
            self.send_response(200)
            self.send_header("Content-Type", "text/xml")
            if path != "/metadata-close":
                self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        elif path.startswith("/file-"):
            tiger = path.startswith("/file-thex-")
            body = TIGER_FILE if tiger else FILE
            if path == "/file-empty.bin":
                body = b""
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            if path != "/file-close.bin":
                self.send_header("Content-Length", str(len(body)))
            if tiger:
                case = path.removeprefix("/file-thex-").removesuffix(".bin")
                self.send_header("X-Content-URN", "urn:tree:tiger/:" + TIGER_ROOT)
                self.send_header("X-Thex-URI", "/thex-" + case)
            elif path.startswith("/file-metadata-"):
                case = path.removeprefix("/file-metadata-").removesuffix(".bin")
                self.send_header("X-Metadata-Path", "/metadata-" + case)
            keep_alive = tiger or path.startswith("/file-metadata-")
            self.send_header("Connection", "keep-alive" if keep_alive else "close")
            self.end_headers()
            self.wfile.write(body)
            if keep_alive:
                self.wfile.flush()
                self.close_connection = False
                return
        else:
            self.send_error(404)
        self.wfile.flush()
        self.close_connection = True
        self.connection.shutdown(socket.SHUT_WR)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=18793)
    args = parser.parse_args()
    with ThreadingHTTPServer(("127.0.0.1", args.port), Handler) as server:
        print(f"Fixture: http://127.0.0.1:{args.port}/file-close.bin", flush=True)
        print(f"Normal file: 65536 bytes; SHA256 {hashlib.sha256(FILE).hexdigest()}", flush=True)
        print(f"THEX file: 1024 bytes; SHA256 {hashlib.sha256(TIGER_FILE).hexdigest()}", flush=True)
        print("Stop with Ctrl+C. This server accepts loopback connections only.", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
