# -*- coding: UTF-8 -*-
from .__common__ import hashtype, logger, API, ServiceUnavailable


__all__ = ["Sorel20M"]

# most likely values first: i386 (PE32) or AMD64 (PE32+), then GUI or console subsystem
_MACHINES = {0x10b: [0x14c, 0x1c0, 0x1c2, 0x1c4, 0x1a2, 0x1a6, 0x166, 0x1f0], 0x20b: [0x8664, 0xaa64, 0x200]}
_SUBSYSTEMS = [2, 3] + [s for s in range(17) if s not in (2, 3)]


class Sorel20M(API):
    doc = "https://github.com/sophos/SOREL-20M"
    url = "https://sorel-20m.s3.amazonaws.com/09-DEC-2020/binaries"
    # public bucket, hence no API key and no key to reject
    _requires_key = False
    _invalid_key = lambda s, r: False

    def _rearm(self, hash):
        """ Restore the PE header fields zeroed by SOREL-20M (FileHeader.Machine and OptionalHeader.Subsystem) by
             trying the possible values until the content matches the hash again. """
        import hashlib
        import struct
        c = bytearray(self.content)
        if hashlib.sha256(c).hexdigest() == hash:
            return True
        try:
            if c[:2] != b"MZ" or c[(pe := struct.unpack("<I", c[0x3c:0x40])[0]):pe+4] != b"PE\0\0":
                return False
            # the Subsystem field is at the same offset in PE32 and PE32+ optional headers
            machine, magic, subsystem = pe + 4, pe + 24, pe + 92
            if c[machine:machine+2] != b"\0\0" or c[subsystem:subsystem+2] != b"\0\0":
                return False
            for m in _MACHINES.get(struct.unpack("<H", c[magic:magic+2])[0], []):
                c[machine:machine+2] = struct.pack("<H", m)
                for s in _SUBSYSTEMS:
                    c[subsystem:subsystem+2] = struct.pack("<H", s)
                    if hashlib.sha256(c).hexdigest() == hash:
                        self.content = bytes(c)
                        return True
        except struct.error:
            pass
        return False

    @hashtype("sha256")
    def get_file_by_hash(self, hash):
        import zlib
        # static dataset of Windows PE files, stored zlib-compressed and disarmed
        vars(self).pop("content", None)
        self._get(hash)
        if not isinstance(getattr(self, "content", None), bytes):
            raise ServiceUnavailable(self.__class__.__name__, "no content")
        try:
            self.content = zlib.decompress(self.content)
        except zlib.error:
            raise ServiceUnavailable(self.__class__.__name__, "unexpected content")
        if self._rearm(hash):
            self._save()
            return
        # still useful for static analysis, hence saved anyway
        logger.warning(f"{self.name}: could not restore the headers of {hash}, hence saved disarmed")
        postcheck, self._postcheck = self._postcheck, False
        try:
            self._save()
        finally:
            self._postcheck = postcheck
