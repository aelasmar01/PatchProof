"""A private, append-only directory of immutable records (projects and plans; PP-009).

The same discipline as the accepted approval and authorization stores: the store directory is
created once with mode 0700 inside an existing private parent owned by the user, never
followed through a symlink and never repaired; each record is written once, exclusively, with
mode 0400 and fsynced; reads are bounded and refuse anything that is not a regular file owned
by the user.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Final

_NAME_RE: Final = re.compile(r"[a-z]{3,5}-[0-9a-f]{16,64}\.json")


class StoreError(Exception):
    """The store or a record in it is unusable. Nothing was written."""


class PrivateStore:
    def __init__(self, root: Path, *, max_record_bytes: int) -> None:
        self.root = root
        self.max_record_bytes = max_record_bytes

    def _check_parent(self) -> int:
        parent = self.root.parent
        if not os.path.isabs(str(self.root)) or os.path.realpath(str(parent)) != str(parent):
            raise StoreError("the store's parent must be an absolute canonical directory")
        try:
            fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError as exc:
            raise StoreError("the store's parent is missing, not a directory, or a symlink") from exc
        st = os.fstat(fd)
        if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077:
            os.close(fd)
            raise StoreError("the store's parent must be a private directory owned by you")
        return fd

    def _open(self, *, create: bool) -> int:
        parent_fd = self._check_parent()
        try:
            if create:
                try:
                    os.mkdir(self.root.name, 0o700, dir_fd=parent_fd)
                except FileExistsError:
                    pass
            try:
                fd = os.open(self.root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            except FileNotFoundError:
                raise
            except OSError as exc:
                raise StoreError("the store is not a directory, or is a symlink") from exc
        finally:
            os.close(parent_fd)
        st = os.fstat(fd)
        if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700:
            os.close(fd)
            raise StoreError("the store must be a directory owned by you with mode 0700")
        return fd

    def names(self) -> list[str]:
        try:
            fd = self._open(create=False)
        except FileNotFoundError:
            return []
        try:
            names = sorted(os.listdir(fd))
        finally:
            os.close(fd)
        stray = [n for n in names if not _NAME_RE.fullmatch(n)]
        if stray:
            raise StoreError(f"unexpected entries in the store: {len(stray)}")
        return names

    def read(self, name: str) -> bytes | None:
        """The record's bytes, or None if it does not exist."""
        if not _NAME_RE.fullmatch(name):
            raise StoreError("invalid record name")
        try:
            dir_fd = self._open(create=False)
        except FileNotFoundError:
            return None
        try:
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
            except FileNotFoundError:
                return None
            except OSError as exc:
                raise StoreError(f"{name} cannot be opened safely") from exc
            with os.fdopen(fd, "rb") as handle:
                st = os.fstat(handle.fileno())
                if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_nlink != 1:
                    raise StoreError(f"{name} is not a regular single-link file owned by you")
                if stat.S_IMODE(st.st_mode) != 0o400:
                    raise StoreError(f"{name} is not read-only (0400)")
                data = handle.read(self.max_record_bytes + 1)
        finally:
            os.close(dir_fd)
        if len(data) > self.max_record_bytes:
            raise StoreError(f"{name} exceeds the record size limit")
        return data

    def write_once(self, name: str, data: bytes) -> Path:
        """Write a new record. Refuses an existing name; never overwrites."""
        if not _NAME_RE.fullmatch(name):
            raise StoreError("invalid record name")
        if len(data) > self.max_record_bytes:
            raise StoreError("the record exceeds the size limit")
        dir_fd = self._open(create=True)
        try:
            try:
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=dir_fd)
            except FileExistsError:
                raise StoreError(f"{name} already exists; records are never overwritten") from None
            try:
                view = memoryview(data)
                while view:
                    written = os.write(fd, view)
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        return self.root / name
