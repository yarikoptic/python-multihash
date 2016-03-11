"""Exceptions used by multihash."""


class UnknownCode(ValueError):

    """Unknown/unsupported multihash code."""

    pass


class TooShort(ValueError):

    """Supplied multihash is too short."""

    pass


class TooLong(ValueError):

    """Supplied multihash is too long."""

    pass


class LenNotSupported(Exception):

    """Multihash length is not supported."""

    pass


class InconsistentLen(Exception):

    """Encoded multihash length is not consistent with what was expected."""

    pass
