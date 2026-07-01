# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0.  If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

import os
import struct
import subprocess
import sys

try:
    import google.protobuf  # noqa: F401
    import hypothesis
    import hypothesis.strategies as strategies
    import u16bitmap_server_pb2 as proto
except ModuleNotFoundError as e:
    print(f"skipping u16bitmap hypothesis test: {e}", file=sys.stderr)
    sys.exit(77)

given = hypothesis.given
settings = hypothesis.settings


@strategies.composite
def bitmap_operations(draw):
    command = draw(
        strategies.sampled_from(
            ["SET", "UNSET", "ISSET", "NEXT", "POPCOUNT", "GET", "RESET"]
        )
    )
    if command in {"SET", "UNSET", "ISSET"}:
        return command, draw(strategies.integers(min_value=0, max_value=65535))
    if command == "NEXT":
        return command, draw(strategies.integers(min_value=-1, max_value=2147483647))
    return command, None


class U16BitmapServer:
    def __init__(self, path):
        self.proc = subprocess.Popen(
            [path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def close(self):
        if self.proc.stdin is not None:
            self.proc.stdin.close()
        returncode = self.proc.wait(timeout=5)
        stderr = self.proc.stderr.read().decode()
        assert returncode == 0, stderr

    def command(self, command):
        assert self.proc.stdin is not None
        assert self.proc.stdout is not None

        request = command.SerializeToString()
        self.proc.stdin.write(struct.pack("!I", len(request)))
        self.proc.stdin.write(request)
        self.proc.stdin.flush()

        length_wire = self.proc.stdout.read(4)
        assert len(length_wire) == 4
        (length,) = struct.unpack("!I", length_wire)
        response_wire = self.proc.stdout.read(length)
        assert len(response_wire) == length

        response = proto.Response()
        response.ParseFromString(response_wire)
        return response


def make_command(command, value=None):
    request = proto.Command()
    if command == "SET":
        request.set.value = value
    elif command == "UNSET":
        request.unset.value = value
    elif command == "ISSET":
        request.isset.value = value
    elif command == "NEXT":
        request.next.value = value
    elif command == "POPCOUNT":
        request.popcount.SetInParent()
    elif command == "GET":
        request.get.SetInParent()
    elif command == "RESET":
        request.reset.SetInParent()
    else:
        raise ValueError(command)
    return request


def assert_ok(response):
    assert response.WhichOneof("response") == "ok"


def assert_count(response, expected):
    assert response.WhichOneof("response") == "count"
    assert response.count.count == expected


def assert_values(response, expected):
    assert response.WhichOneof("response") == "values"
    assert response.values.count == len(expected)
    assert list(response.values.values) == expected


def assert_next(response, model, value):
    assert response.WhichOneof("response") == "next"
    expected = next((item for item in sorted(model) if item > value), 2147483647)
    assert response.next.value == expected


@given(strategies.lists(bitmap_operations(), min_size=1, max_size=500))
@settings(deadline=None)
def test_u16bitmap_matches_python_set(operations):
    server_path = os.environ["U16BITMAP_SERVER"]
    server = U16BitmapServer(server_path)
    model = set()

    try:
        for command, value in operations:
            if command == "SET":
                assert_ok(server.command(make_command("SET", value)))
                model.add(value)
            elif command == "UNSET":
                assert_ok(server.command(make_command("UNSET", value)))
                model.discard(value)
            elif command == "ISSET":
                response = server.command(make_command("ISSET", value))
                assert response.WhichOneof("response") == "value"
                assert response.value.present == (value in model)
            elif command == "NEXT":
                assert_next(server.command(make_command("NEXT", value)), model, value)
            elif command == "POPCOUNT":
                assert_count(server.command(make_command("POPCOUNT")), len(model))
            elif command == "GET":
                assert_values(server.command(make_command("GET")), sorted(model))
            elif command == "RESET":
                assert_ok(server.command(make_command("RESET")))
                model.clear()

            assert_count(server.command(make_command("POPCOUNT")), len(model))
            assert_values(server.command(make_command("GET")), sorted(model))
            assert_next(server.command(make_command("NEXT", -1)), model, -1)
            for item in sorted(model):
                assert_next(server.command(make_command("NEXT", item)), model, item)
            assert_next(
                server.command(make_command("NEXT", 2147483647)),
                model,
                2147483647,
            )
    finally:
        server.close()


if __name__ == "__main__":
    test_u16bitmap_matches_python_set()
