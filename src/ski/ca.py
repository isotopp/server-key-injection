"""Protected, atomic file operations for the persistent user CA."""

from __future__ import annotations

import os
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

import asyncssh

from ski.secure_files import SecureFileError, validate_secure_file
from ski.state import CAKeyRecord, StateDatabase, StateError


class CAFileError(RuntimeError):
    """Raised when CA material cannot be created or validated safely."""


KeyGenerator = Callable[[], asyncssh.SSHKey]
Rename = Callable[[str | os.PathLike[str], str | os.PathLike[str]], None]
CommandRunner = Callable[..., subprocess.CompletedProcess[bytes]]


@dataclass(frozen=True, slots=True)
class GeneratedCAMaterial:
    """Generated CA key material retained only for initialization."""

    private_key: asyncssh.SSHKey
    private_bytes: bytes
    public_bytes: bytes
    fingerprint: str


@dataclass(frozen=True, slots=True)
class ValidatedActiveCA:
    """A configured CA whose files and persisted public record agree."""

    record: CAKeyRecord
    private_key: asyncssh.SSHKey
    public_key: asyncssh.SSHKey


def load_validated_active_ca(
    database: StateDatabase,
    *,
    private_path: Path,
    public_path: Path,
) -> ValidatedActiveCA:
    """Load and cross-check the configured private/public CA and state record."""
    try:
        validate_secure_file(
            private_path,
            owner_uid=os.geteuid(),
            group_gid=os.getegid(),
        )
        validate_secure_file(
            public_path,
            owner_uid=os.geteuid(),
            group_gid=os.getegid(),
        )
        private_key = asyncssh.import_private_key(private_path.read_bytes())
        public_key = asyncssh.import_public_key(public_path.read_bytes())
    except SecureFileError as exc:
        raise StateError("active CA material is unsafe") from exc
    except (OSError, asyncssh.KeyImportError) as exc:
        raise StateError("active CA material is unavailable") from exc
    except Exception as exc:
        raise StateError("active CA material is invalid") from exc

    if (
        private_key.get_algorithm() != "ssh-ed25519"
        or public_key.get_algorithm() != "ssh-ed25519"
        or private_key.export_public_key() != public_key.export_public_key()
    ):
        raise StateError("active CA material does not match")
    record = database.get_active_ca()
    if record is None:
        raise StateError("active CA record is unavailable")
    if (
        record.algorithm != "ssh-ed25519"
        or record.public_key != public_key.export_public_key()
        or record.fingerprint != private_key.get_fingerprint()
        or record.private_key_path != private_path
    ):
        raise StateError("active CA record does not match configured material")
    return ValidatedActiveCA(
        record=record,
        private_key=private_key,
        public_key=public_key,
    )


def _run_ssh_keygen(
    *args: str,
    stdin: int | None = None,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        args,
        check=False,
        stdin=stdin,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


class CAFileWriter:
    """Stage and atomically install one fresh CA keypair and empty KRL."""

    def __init__(
        self,
        *,
        key_generator: KeyGenerator | None = None,
        rename: Rename = os.replace,
        command_runner: CommandRunner = _run_ssh_keygen,
    ) -> None:
        if key_generator is None:
            self._key_generator: KeyGenerator = lambda: asyncssh.generate_private_key(
                "ssh-ed25519",
            )
        else:
            self._key_generator = key_generator
        self._rename = rename
        self._command_runner = command_runner

    def install(
        self,
        *,
        private_path: Path,
        public_path: Path,
        krl_path: Path,
    ) -> GeneratedCAMaterial:
        """Create all three files, refusing existing targets and cleaning failures."""
        paths = (private_path, public_path, krl_path)
        self._validate_targets(paths)
        material = self._generate()
        temporary: list[Path] = []
        installed: list[Path] = []
        try:
            private_temp = self._write_temp(
                private_path,
                material.private_bytes,
                mode=0o600,
            )
            temporary.append(private_temp)
            public_temp = self._write_temp(
                public_path,
                material.public_bytes,
                mode=0o644,
            )
            temporary.append(public_temp)
            krl_temp = self._write_empty_krl(krl_path)
            temporary.append(krl_temp)

            for temporary_path, target in zip(
                (private_temp, public_temp, krl_temp),
                paths,
                strict=True,
            ):
                self._rename(temporary_path, target)
                installed.append(target)
                temporary.remove(temporary_path)
                self._validate_installed(target)
        except Exception as exc:
            for path in temporary:
                path.unlink(missing_ok=True)
            for path in installed:
                path.unlink(missing_ok=True)
            if isinstance(exc, CAFileError):
                raise
            raise CAFileError("CA material could not be installed") from exc
        return material

    @staticmethod
    def _validate_installed(path: Path) -> None:
        """Validate one atomically installed CA file before success."""
        try:
            validate_secure_file(
                path,
                owner_uid=os.geteuid(),
                group_gid=os.getegid(),
            )
        except SecureFileError as exc:
            raise CAFileError("installed CA material is unsafe") from exc

    @staticmethod
    def _validate_targets(paths: Sequence[Path]) -> None:
        resolved: set[Path] = set()
        for path in paths:
            path = Path(path).expanduser()
            if path.name in {"", ".", ".."} or not path.parent.is_dir():
                raise CAFileError("CA output path is unavailable")
            if not os.access(path.parent, os.W_OK):
                raise CAFileError("CA output directory is not writable")
            try:
                resolved_path = path.resolve()
            except OSError as exc:
                raise CAFileError("CA output path is unavailable") from exc
            if resolved_path in resolved:
                raise CAFileError("CA output paths must be distinct")
            resolved.add(resolved_path)
            if path.is_symlink() or path.exists():
                raise CAFileError("CA output already exists")

    def _generate(self) -> GeneratedCAMaterial:
        try:
            key = self._key_generator()
            if key.get_algorithm() != "ssh-ed25519":
                raise CAFileError("CA algorithm is unsupported")
            private_bytes = key.export_private_key()
            public_bytes = key.export_public_key()
        except CAFileError:
            raise
        except Exception as exc:
            raise CAFileError("CA key generation failed") from exc
        return GeneratedCAMaterial(
            private_key=key,
            private_bytes=private_bytes,
            public_bytes=public_bytes,
            fingerprint=key.get_fingerprint(),
        )

    @staticmethod
    def _write_temp(target: Path, payload: bytes, *, mode: int) -> Path:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{target.name}.",
            dir=target.parent,
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, mode)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            try:
                os.close(descriptor)
            except OSError:
                pass
            temporary.unlink(missing_ok=True)
            raise
        return temporary

    def _write_empty_krl(self, target: Path) -> Path:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{target.name}.",
            dir=target.parent,
        )
        temporary = Path(temporary_name)
        os.close(descriptor)
        temporary.unlink(missing_ok=True)
        try:
            result = self._command_runner(
                "ssh-keygen",
                "-k",
                "-f",
                str(temporary),
                stdin=subprocess.DEVNULL,
            )
        except OSError as exc:
            raise CAFileError("empty KRL capability is unavailable") from exc
        if result.returncode != 0 or not temporary.is_file():
            temporary.unlink(missing_ok=True)
            raise CAFileError("empty KRL creation failed")
        temporary.chmod(0o644)
        return temporary
