"""Record instance stored and searchable by BaseStorage implementation."""

import logging
from collections import namedtuple
from typing import Optional

from uuid_utils import uuid4

LOGGER = logging.getLogger(__name__)


class StorageRecord(namedtuple("StorageRecord", "type value tags id")):
    """Storage record class."""

    __slots__ = ()

    def __new__(cls, type, value, tags: Optional[dict] = None, id: Optional[str] = None):
        """Initialize some defaults on record."""
        if not id:
            id = uuid4().hex
            LOGGER.debug("Creating storage record %s", id)
        else:
            LOGGER.debug("Handling storage record with id %s", id)
        if not tags:
            tags = {}
        LOGGER.debug("Creating storage record %s", id)
        return super(cls, StorageRecord).__new__(cls, type, value, tags, id)
