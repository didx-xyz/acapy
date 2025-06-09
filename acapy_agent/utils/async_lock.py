"""Async Redis lock for concurrent operations."""

import asyncio
import logging
import os
import time

import valkey.asyncio as valkey
from uuid_utils import uuid4

LOGGER = logging.getLogger(__name__)


class AsyncRedisLock:
    """Class to manage Redis locks for concurrent revocation operations."""

    VALKEY_URL = os.getenv("VALKEY_URL", "redis://valkey-primary:6379")

    def __init__(self, lock_key: str):
        """Initialize the AsyncRedisLock instance.

        Args:
            lock_key (str): The key to use for the Redis lock.
        """
        self.lock_key = lock_key
        self.lock_value = None
        self._valkey = None
        self.acquired_at = None

    async def _get_redis(self):
        if self._valkey is None:
            self._valkey = valkey.from_url(self.VALKEY_URL, decode_responses=True)
        return self._valkey

    async def __aenter__(self):
        """Acquire the Redis lock."""
        redis_client = await self._get_redis()
        self.lock_value = str(uuid4())
        attempt_count = 0
        start_time = time.time()

        LOGGER.debug(
            "Attempting to acquire lock '%s' with value '%s'",
            self.lock_key,
            self.lock_value,
        )
        while True:
            attempt_count += 1
            acquired = await redis_client.set(
                self.lock_key, self.lock_value, nx=True, ex=30
            )
            if acquired:
                self.acquired_at = time.time()
                # NEW: Success logging with metrics
                LOGGER.debug(
                    "Lock '%s' acquired successfully by '%s' after %d attempts in %.2f "
                    "seconds",
                    self.lock_key,
                    self.lock_value,
                    attempt_count,
                    self.acquired_at - start_time,
                )
                break

            elapsed = time.time() - start_time
            timeout = 25
            if elapsed > timeout:  # 25 seconds = 5s buffer before Redis expires lock
                LOGGER.error(
                    "Failed to acquire lock '%s' after %.2f seconds and %d attempts "
                    "- timeout exceeded",
                    self.lock_key,
                    elapsed,
                    attempt_count,
                )
                raise TimeoutError(
                    f"Timeout waiting for lock '{self.lock_key}' after {timeout} seconds"
                )

            if attempt_count % 10 == 0:  # Log every 5 seconds
                LOGGER.info(
                    "Still waiting for lock '%s' after %d attempts (%.2f seconds)",
                    self.lock_key,
                    attempt_count,
                    elapsed,
                )

            await asyncio.sleep(0.5)

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Release the Redis lock."""
        if self.lock_value and self._valkey:
            lua_script = """
            if redis.call("GET", KEYS[1]) == ARGV[1] then
                return redis.call("DEL", KEYS[1])
            else
                return 0
            end
            """
            try:
                result = await self._valkey.eval(
                    lua_script, 1, self.lock_key, self.lock_value
                )
                held_duration = time.time() - self.acquired_at if self.acquired_at else 0

                # NEW: Release logging with duration tracking
                if result == 1:
                    LOGGER.info(
                        "Lock '%s' released successfully by '%s' after being held for "
                        "%.2f seconds",
                        self.lock_key,
                        self.lock_value,
                        held_duration,
                    )
                else:
                    # NEW: Warning for expired locks
                    LOGGER.warning(
                        "Lock '%s' was already expired or released. Expected value '%s', "
                        "held for %.2f seconds",
                        self.lock_key,
                        self.lock_value,
                        held_duration,
                    )
            except Exception as e:
                # NEW: Error handling for release failures
                LOGGER.error(
                    "Error releasing lock '%s' with value '%s': %s",
                    self.lock_key,
                    self.lock_value,
                    str(e),
                )
            finally:
                try:
                    await self._valkey.close()
                    LOGGER.info("Redis connection closed for lock '%s'", self.lock_key)
                except Exception as e:
                    LOGGER.error("Error closing Redis connection: %s", str(e))
