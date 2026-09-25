# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
# SPDX-License-Identifier: MPL-2.0

import os
import select
import struct
import subprocess
import tempfile


class ProtobufServer:
    def __init__(self, path, response_type, *, restart_on_crash=False):
        self.path = path
        self.response_type = response_type
        self.restart_on_crash = restart_on_crash

    def __enter__(self):
        self.errors = tempfile.TemporaryFile()
        try:
            self.proc = subprocess.Popen(
                [self.path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=self.errors,
            )
        except BaseException:
            self.errors.close()
            raise
        return self

    def diagnostic(self):
        self.errors.seek(0)
        return self.errors.read().decode(errors="replace")

    def read(self, size):
        data = bytearray()
        while len(data) < size:
            ready, _, _ = select.select([self.proc.stdout], [], [], 10)
            if not ready:
                self.proc.kill()
                self.proc.wait()
                raise AssertionError(f"{self.path}: timed out")
            chunk = os.read(self.proc.stdout.fileno(), size - len(data))
            if not chunk:
                self.proc.wait(timeout=10)
                raise AssertionError(f"{self.path}: EOF\n{self.diagnostic()}")
            data.extend(chunk)
        return bytes(data)

    def command(self, request):
        if self.proc.poll() is not None:
            if not self.restart_on_crash:
                raise AssertionError(f"{self.path}: exited\n{self.diagnostic()}")
            self.proc.stdin.close()
            self.proc.stdout.close()
            self.errors.close()
            self.__enter__()
        data = request.SerializeToString()
        try:
            self.proc.stdin.write(struct.pack("!I", len(data)) + data)
            self.proc.stdin.flush()
        except BrokenPipeError:
            self.proc.wait(timeout=10)
            raise AssertionError(
                f"{self.path}: broken pipe\n{self.diagnostic()}"
            ) from None
        length = struct.unpack("!I", self.read(4))[0]
        assert length <= 4 * 1024 * 1024
        return self.response_type.FromString(self.read(length))

    def __exit__(self, kind, value, traceback):
        try:
            self.proc.stdin.close()
            code = self.proc.wait(timeout=10)
            if kind is None:
                assert code == 0, self.diagnostic()
        finally:
            if self.proc.poll() is None:
                self.proc.kill()
                self.proc.wait()
            self.proc.stdout.close()
            self.errors.close()
