"""Revocation through ledger agnostic AnonCreds interface."""

import asyncio
import hashlib
import http
import logging
import os
import time
from pathlib import Path
from typing import List, Mapping, NamedTuple, Optional, Sequence, Tuple, Union
from urllib.parse import urlparse

import base58
from anoncreds import (
    AnoncredsError,
    Credential,
    CredentialRevocationConfig,
    RevocationRegistryDefinition,
    RevocationRegistryDefinitionPrivate,
    RevocationStatusList,
    W3cCredential,
)
from aries_askar import AskarErrorCode, Entry
from aries_askar.error import AskarError
from requests import RequestException, Session
from uuid_utils import uuid4

from ..askar.profile_anon import AskarAnonCredsProfile, AskarAnonCredsProfileSession
from ..core.error import BaseError
from ..core.event_bus import Event, EventBus
from ..core.profile import Profile, ProfileSession
from ..tails.anoncreds_tails_server import AnonCredsTailsServer
from .error_messages import ANONCREDS_PROFILE_REQUIRED_MSG
from .events import (
    FIRST_REGISTRY_TAG,
    RevListCreateRequestedEvent,
    RevListCreateResponseEvent,
    RevListFinishedEvent,
    RevListStoreRequestedEvent,
    RevListStoreResponseEvent,
    RevRegActivationRequestedEvent,
    RevRegActivationResponseEvent,
    RevRegDefCreateRequestedEvent,
    RevRegDefCreateResponseEvent,
    RevRegDefFinishedEvent,
    RevRegDefStoreRequestedEvent,
    RevRegDefStoreResponseEvent,
    RevRegFullDetectedEvent,
    RevRegFullHandlingResponseEvent,
    TailsUploadRequestedEvent,
    TailsUploadResponseEvent,
)
from .issuer import (
    CATEGORY_CRED_DEF,
    CATEGORY_CRED_DEF_PRIVATE,
    STATE_FINISHED,
    AnonCredsIssuer,
)
from .models.credential_definition import CredDef
from .models.revocation import (
    RevList,
    RevListResult,
    RevListState,
    RevRegDef,
    RevRegDefResult,
    RevRegDefState,
)
from .registry import AnonCredsRegistry
from .util import indy_client_dir

LOGGER = logging.getLogger(__name__)

CATEGORY_REV_LIST = "revocation_list"
CATEGORY_REV_REG_DEF = "revocation_reg_def"
CATEGORY_REV_REG_DEF_PRIVATE = "revocation_reg_def_private"
CATEGORY_REV_REG_ISSUER = "revocation_reg_def_issuer"
STATE_REVOCATION_POSTED = "posted"
STATE_REVOCATION_PENDING = "pending"
REV_REG_DEF_STATE_ACTIVE = "active"


class AnonCredsRevocationError(BaseError):
    """Generic revocation error."""


class AnonCredsRevocationRegistryFullError(AnonCredsRevocationError):
    """Revocation registry is full when issuing a new credential."""


class RevokeResult(NamedTuple):
    """RevokeResult."""

    prev: RevList
    curr: Optional[RevList] = None
    revoked: Optional[Sequence[int]] = None
    failed: Optional[Sequence[str]] = None


class AnonCredsRevocation:
    """Revocation registry operations manager."""

    def __init__(self, profile: Profile):
        """Initialize an AnonCredsRevocation instance.

        Args:
            profile: The active profile instance

        """
        self._profile = profile

    @property
    def profile(self) -> AskarAnonCredsProfile:
        """Accessor for the profile instance."""
        if not isinstance(self._profile, AskarAnonCredsProfile):
            LOGGER.error("Profile is not AskarAnonCredsProfile type")
            raise ValueError(ANONCREDS_PROFILE_REQUIRED_MSG)

        return self._profile

    async def notify(self, event: Event) -> None:
        """Emit an event on the event bus."""
        LOGGER.debug("Emitting event %s on event bus", type(event).__name__)
        event_bus = self.profile.inject(EventBus)
        await event_bus.notify(self.profile, event)
        LOGGER.debug("Event %s emitted successfully", type(event).__name__)

    async def _finish_registration(
        self,
        txn: AskarAnonCredsProfileSession,
        category: str,
        job_id: str,
        registered_id: str,
        *,
        state: Optional[str] = None,
    ):
        LOGGER.debug(
            "Finishing registration for category=%s, job_id=%s, "
            "registered_id=%s, state=%s",
            category,
            job_id,
            registered_id,
            state,
        )
        entry = await txn.handle.fetch(
            category,
            job_id,
            for_update=True,
        )
        if not entry:
            LOGGER.error(
                "Entry not found for category=%s, job_id=%s during registration finish",
                category,
                job_id,
            )
            raise AnonCredsRevocationError(
                f"{category} with job id {job_id} could not be found"
            )

        if state:
            tags = entry.tags
            tags["state"] = state
            LOGGER.debug("Updated entry state to %s", state)
        else:
            tags = entry.tags

        await txn.handle.insert(
            category,
            registered_id,
            value=entry.value,
            tags=tags,
        )
        LOGGER.debug("Inserted entry with registered_id=%s", registered_id)

        await txn.handle.remove(category, job_id)
        LOGGER.debug("Removed entry with job_id=%s", job_id)

        return entry

    ### ------------- REFACTOR START ------------- ###

    async def emit_create_revocation_registry_definition_event(  # ✅
        self,
        issuer_id: str,
        cred_def_id: str,
        registry_type: str,
        tag: str,
        max_cred_num: int,
        options: Optional[dict] = None,
    ) -> None:
        """Emit event to request creation and registration of a new revocation registry.

        Args:
            issuer_id (str): issuer identifier
            cred_def_id (str): credential definition identifier
            registry_type (str): revocation registry type
            tag (str): revocation registry tag
            max_cred_num (int): maximum number of credentials supported
            options (dict): revocation registry options

        """
        LOGGER.debug(
            "Emitting create revocation registry definition event for issuer: %s, "
            "cred_def_id: %s, registry_type: %s, tag: %s, max_cred_num: %s",
            issuer_id,
            cred_def_id,
            registry_type,
            tag,
            max_cred_num,
        )
        event = RevRegDefCreateRequestedEvent.with_payload(
            issuer_id=issuer_id,
            cred_def_id=cred_def_id,
            registry_type=registry_type,
            tag=tag,
            max_cred_num=max_cred_num,
            options=options,
        )
        await self.notify(event)

    async def create_and_register_revocation_registry_definition(  # ✅
        self,
        issuer_id: str,
        cred_def_id: str,
        registry_type: str,
        tag: str,
        max_cred_num: int,
        options: Optional[dict] = None,
    ) -> RevRegDefResult:
        """Create a new revocation registry and register on network.

        This method picks up the RevRegDefCreateRequestedEvent, performing the registry
        creation and registration, emitting success or failure events based on the result.

        Args:
            issuer_id (str): issuer identifier
            cred_def_id (str): credential definition identifier
            registry_type (str): revocation registry type
            tag (str): revocation registry tag
            max_cred_num (int): maximum number of credentials supported
            options (dict): revocation registry options

        """
        LOGGER.debug(
            "Creating and registering revocation registry definition for issuer: %s, "
            "cred_def_id: %s, registry_type: %s, tag: %s, max_cred_num: %s",
            issuer_id,
            cred_def_id,
            registry_type,
            tag,
            max_cred_num,
        )
        options = options or {}
        retry_count = options.pop("retry_count", 0)

        try:
            # Validate credential definition exists
            async with self.profile.session() as session:
                LOGGER.debug("Fetching credential definition %s", cred_def_id)
                cred_def = await session.handle.fetch(CATEGORY_CRED_DEF, cred_def_id)

            if not cred_def:
                raise AskarError(
                    AskarErrorCode.NOT_FOUND,
                    f"Credential definition {cred_def_id} not found for "
                    f"creating revocation registry {tag}",
                )

            # Create a directory for the tails file in the indy-client directory
            tails_dir = indy_client_dir("tails", create=True)

            # Method to create the revocation registry definition and private key
            def create_rev_reg_def() -> Tuple[
                RevocationRegistryDefinition, RevocationRegistryDefinitionPrivate
            ]:
                return RevocationRegistryDefinition.create(
                    cred_def_id,
                    cred_def.raw_value,
                    issuer_id,
                    tag,
                    registry_type,
                    max_cred_num,
                    tails_dir_path=tails_dir,
                )

            # Run the creation of the revocation registry definition in a thread pool
            # to avoid blocking the event loop
            (
                rev_reg_def,
                rev_reg_def_private,
            ) = await asyncio.get_event_loop().run_in_executor(None, create_rev_reg_def)

            rev_reg_def = RevRegDef.from_native(rev_reg_def)

            # Generate and set the public tails URI
            public_tails_uri = self.generate_public_tails_uri(rev_reg_def)
            rev_reg_def.value.tails_location = public_tails_uri

            # Register on network
            anoncreds_registry = self.profile.inject(AnonCredsRegistry)
            result = await anoncreds_registry.register_revocation_registry_definition(
                self.profile, rev_reg_def, options
            )

            # Emit success event, which passes info needed to trigger the store request
            LOGGER.debug(
                "Emitting successful create rev reg def response event for issuer: "
                "%s, cred_def_id: %s, registry_type: %s, tag: %s, max_cred_num: %s",
                issuer_id,
                cred_def_id,
                registry_type,
                tag,
                max_cred_num,
            )
            event = RevRegDefCreateResponseEvent.with_payload(
                rev_reg_def_result=result,
                rev_reg_def=rev_reg_def,
                rev_reg_def_private=rev_reg_def_private,
                options=options,
            )
            await self.notify(event)

            return result
        except Exception as err:
            # Emit failure event with appropriate error message based on exception type
            should_retry = True
            if isinstance(err, AskarError):
                error_msg = f"Error retrieving credential definition: {str(err)}"
                if err.code == AskarErrorCode.NOT_FOUND:
                    should_retry = False
            elif isinstance(err, AnoncredsError):
                error_msg = f"Error creating revocation registry: {str(err)}"
            else:
                error_msg = f"Registry creation failed: {str(err)}"

            LOGGER.warning(f"{error_msg}. Emitting failure event.")

            event = RevRegDefCreateResponseEvent.with_failure(
                error_msg=error_msg,
                should_retry=should_retry,
                retry_count=retry_count,
                issuer_id=issuer_id,
                cred_def_id=cred_def_id,
                registry_type=registry_type,
                tag=tag,
                max_cred_num=max_cred_num,
                options=options,
            )
            await self.notify(event)

    async def emit_store_revocation_registry_definition_event(  # ✅
        self,
        *,
        rev_reg_def: RevRegDef,
        rev_reg_def_result: RevRegDefResult,
        rev_reg_def_private: RevocationRegistryDefinitionPrivate,
        options: Optional[dict] = None,
    ) -> None:
        """Emit event to request storing revocation registry definition locally.

        Args:
            rev_reg_def_result (RevRegDefResult): revocation registry definition result
            rev_reg_def (RevRegDef): revocation registry definition
            rev_reg_def_private (RevocationRegistryDefinitionPrivate): private key
            options (dict): storage options

        """
        LOGGER.debug(
            "Emitting store revocation registry definition event for rev_reg_def_id: %s, "
            "tag: %s",
            rev_reg_def_result.rev_reg_def_id,
            rev_reg_def.tag,
        )
        options = options or {}

        event = RevRegDefStoreRequestedEvent.with_payload(
            rev_reg_def=rev_reg_def,
            rev_reg_def_result=rev_reg_def_result,
            rev_reg_def_private=rev_reg_def_private,
            options=options,
        )
        await self.notify(event)

    async def handle_store_revocation_registry_definition_request(  # ✅
        self,
        rev_reg_def_result: RevRegDefResult,
        rev_reg_def_private: RevocationRegistryDefinitionPrivate,
        options: Optional[dict] = None,
    ) -> None:
        """Handle storing revocation registry definition locally.

        If the tag is the first registry, then successful storage will trigger the
        creation of a backup registry.

        Args:
            rev_reg_def_result (RevRegDefResult): revocation registry definition result
            rev_reg_def_private (RevocationRegistryDefinitionPrivate): private key
            options (dict): storage options

        """
        options = options or {}
        retry_count = options.pop("retry_count", 0)
        rev_reg_def_state = rev_reg_def_result.revocation_registry_definition_state
        rev_reg_def = rev_reg_def_state.revocation_registry_definition
        tag = rev_reg_def.tag
        rev_reg_def_id = rev_reg_def_result.rev_reg_def_id

        LOGGER.debug(
            "Handling registry store request for rev_reg_def_id: %s, tag: %s",
            rev_reg_def_id,
            tag,
        )

        try:
            # Store locally
            await self.store_revocation_registry_definition(
                rev_reg_def_result, rev_reg_def_private, options
            )

            # Emit success event
            LOGGER.debug("Emitting store response event")
            event = RevRegDefStoreResponseEvent.with_payload(
                rev_reg_def_id=rev_reg_def_id,
                rev_reg_def=rev_reg_def,
                rev_reg_def_result=rev_reg_def_result,
                tag=tag,
                options=options,
            )
            await self.notify(event)

        except Exception as err:
            # Emit failure event
            should_retry = True
            if isinstance(err, AnonCredsRevocationError):
                error_msg = str(err)
                if "Revocation registry definition id or job id not found" in error_msg:
                    should_retry = False
            else:
                error_msg = f"Store operation failed: {str(err)}"

            LOGGER.warning(error_msg)
            event = RevRegDefStoreResponseEvent.with_failure(
                rev_reg_def=rev_reg_def,
                tag=tag,
                error_msg=error_msg,
                should_retry=should_retry,
                retry_count=retry_count,
                rev_reg_def_private=rev_reg_def_private,
                options=options,
            )
            await self.notify(event)

    async def store_revocation_registry_definition(  # ✅
        self,
        result: RevRegDefResult,
        rev_reg_def_private: RevocationRegistryDefinitionPrivate,
        options: Optional[dict] = None,
    ) -> None:
        """Store a revocation registry definition.

        Emits a RevRegDefFinishedEvent if the revocation registry definition is finished.

        Args:
            result (RevRegDefResult): revocation registry definition result
            rev_reg_def_private (RevocationRegistryDefinitionPrivate): private key
            options (dict): storage options

        """
        options = options or {}
        identifier = result.job_id or result.rev_reg_def_id
        if not identifier:
            LOGGER.error(
                "No identifier found in result for revocation registry definition"
            )
            raise AnonCredsRevocationError(
                "Revocation registry definition id or job id not found"
            )
        LOGGER.debug(
            "Storing revocation registry definition for rev_reg_def_id: %s, tag: %s",
            result.rev_reg_def_id,
            result.revocation_registry_definition_state.revocation_registry_definition.tag,
        )

        rev_reg_def = (
            result.revocation_registry_definition_state.revocation_registry_definition
        )
        rev_reg_def_state = result.revocation_registry_definition_state.state

        try:
            async with self.profile.transaction() as txn:
                LOGGER.debug(
                    "Inserting revocation registry definition with identifier=%s",
                    identifier,
                )
                await txn.handle.insert(
                    CATEGORY_REV_REG_DEF,
                    identifier,
                    rev_reg_def.to_json(),
                    tags={
                        "cred_def_id": rev_reg_def.cred_def_id,
                        "state": rev_reg_def_state,
                        "active": "false",
                    },
                )
                LOGGER.debug("Inserting revocation registry definition private data")
                await txn.handle.insert(
                    CATEGORY_REV_REG_DEF_PRIVATE,
                    identifier,
                    rev_reg_def_private.to_json_buffer(),
                )
                await txn.commit()
            LOGGER.debug("Revocation registry definition storage transaction committed")
        except AskarError as err:
            LOGGER.error("Failed to store revocation registry definition: %s", err)
            raise AnonCredsRevocationError(
                "Error saving new revocation registry"
            ) from err

    async def finish_revocation_registry_definition(
        self, job_id: str, rev_reg_def_id: str, options: Optional[dict] = None
    ) -> None:
        """Mark a rev reg def as finished."""
        LOGGER.debug(
            "Finishing revocation registry definition job_id=%s, rev_reg_def_id=%s",
            job_id,
            rev_reg_def_id,
        )
        options = options or {}
        async with self.profile.transaction() as txn:
            entry = await self._finish_registration(
                txn, CATEGORY_REV_REG_DEF, job_id, rev_reg_def_id, state=STATE_FINISHED
            )
            rev_reg_def = RevRegDef.from_json(entry.value)
            await self._finish_registration(
                txn,
                CATEGORY_REV_REG_DEF_PRIVATE,
                job_id,
                rev_reg_def_id,
            )
            await txn.commit()

        await self.emit_rev_reg_def_finished_event(rev_reg_def_id, rev_reg_def, options)

    async def emit_rev_reg_def_finished_event(  # ✅
        self,
        rev_reg_def_id: str,
        rev_reg_def: RevRegDef,
        options: Optional[dict] = None,
    ) -> None:
        """Emit event to indicate revocation registry definition is finished."""
        LOGGER.debug("Emitting rev reg def finished event")
        await self.notify(
            RevRegDefFinishedEvent.with_payload(
                rev_reg_def_id=rev_reg_def_id,
                rev_reg_def=rev_reg_def,
                options=options,
            )
        )

    async def get_created_revocation_registry_definitions(
        self,
        cred_def_id: Optional[str] = None,
        state: Optional[str] = None,
    ) -> Sequence[str]:
        """Retrieve IDs of rev reg defs previously created."""
        LOGGER.debug(
            "Retrieving created revocation registry definitions for "
            "cred_def_id=%s, state=%s",
            cred_def_id,
            state,
        )
        async with self.profile.session() as session:
            # TODO limit? scan?
            rev_reg_defs = await session.handle.fetch_all(
                CATEGORY_REV_REG_DEF,
                {
                    key: value
                    for key, value in {
                        "cred_def_id": cred_def_id,
                        "state": state,
                    }.items()
                    if value is not None
                },
            )
        # entry.name was stored as the credential_definition's ID
        result = [entry.name for entry in rev_reg_defs]
        LOGGER.debug("Found %d revocation registry definitions", len(result))
        return result

    async def get_created_revocation_registry_definition_state(
        self,
        rev_reg_def_id: str,
    ) -> Optional[str]:
        """Retrieve rev reg def by ID from rev reg defs previously created."""
        LOGGER.debug(
            "Retrieving state for revocation registry definition: %s", rev_reg_def_id
        )
        async with self.profile.session() as session:
            rev_reg_def_entry = await session.handle.fetch(
                CATEGORY_REV_REG_DEF,
                name=rev_reg_def_id,
            )

        if rev_reg_def_entry:
            state = rev_reg_def_entry.tags.get("state")
            LOGGER.debug(
                "Found state %s for registry definition %s", state, rev_reg_def_id
            )
            return state

        LOGGER.debug("No registry definition found for %s", rev_reg_def_id)
        return None

    async def get_created_revocation_registry_definition(
        self,
        rev_reg_def_id: str,
    ) -> Optional[RevRegDef]:
        """Retrieve rev reg def by ID from rev reg defs previously created."""
        LOGGER.debug("Retrieving revocation registry definition: %s", rev_reg_def_id)
        async with self.profile.session() as session:
            rev_reg_def_entry = await session.handle.fetch(
                CATEGORY_REV_REG_DEF,
                name=rev_reg_def_id,
            )

        if rev_reg_def_entry:
            LOGGER.debug("Found registry definition %s", rev_reg_def_id)
            return RevRegDef.deserialize(rev_reg_def_entry.value_json)

        LOGGER.debug("No registry definition found for %s", rev_reg_def_id)
        return None

    async def set_active_registry(self, rev_reg_def_id: str) -> None:
        """Mark a registry as active."""
        LOGGER.debug("Setting registry %s as active", rev_reg_def_id)
        async with self.profile.transaction() as txn:
            entry = await txn.handle.fetch(
                CATEGORY_REV_REG_DEF,
                rev_reg_def_id,
                for_update=True,
            )
            if not entry:
                LOGGER.error("Registry definition %s not found", rev_reg_def_id)
                raise AnonCredsRevocationError(
                    f"{CATEGORY_REV_REG_DEF} with id {rev_reg_def_id} could not be found"
                )

            if entry.tags["active"] == "true":
                LOGGER.warning("Registry %s is already active", rev_reg_def_id)
                # NOTE If there are other registries set as active, we're not
                # clearing them if the one we want to be active is already
                # active. This probably isn't an issue.
                LOGGER.debug("Registry %s is already active, skipping", rev_reg_def_id)
                return

            cred_def_id = entry.tags["cred_def_id"]
            LOGGER.debug("Deactivating other registries for cred_def_id=%s", cred_def_id)

            old_active_entries = await txn.handle.fetch_all(
                CATEGORY_REV_REG_DEF,
                {
                    "active": "true",
                    "cred_def_id": cred_def_id,
                },
                for_update=True,
            )

            if len(old_active_entries) > 1:
                LOGGER.error(
                    "More than one registry was set as active for "
                    "cred def %s; clearing active tag from all records",
                    cred_def_id,
                )

            for old_entry in old_active_entries:
                tags = old_entry.tags
                tags["active"] = "false"
                await txn.handle.replace(
                    CATEGORY_REV_REG_DEF,
                    old_entry.name,
                    old_entry.value,
                    tags,
                )
                LOGGER.debug("Deactivated registry %s", old_entry.name)

            tags = entry.tags
            tags["active"] = "true"
            await txn.handle.replace(
                CATEGORY_REV_REG_DEF,
                rev_reg_def_id,
                value=entry.value,
                tags=tags,
            )
            LOGGER.debug("Activated registry %s", rev_reg_def_id)
            await txn.commit()

        LOGGER.debug("Registry %s set as active", rev_reg_def_id)

    async def emit_create_and_register_revocation_list_event(  # ✅
        self,
        rev_reg_def_id: str,
        options: Optional[dict] = None,
    ) -> None:
        """Emit event to request revocation list creation.

        Args:
            rev_reg_def_id (str): revocation registry definition ID
            options (dict): creation options

        """
        LOGGER.debug(
            "Emitting create and register revocation list event for rev_reg_def_id: %s",
            rev_reg_def_id,
        )
        options = options or {}

        # Emit event to request revocation list creation
        event = RevListCreateRequestedEvent.with_payload(
            rev_reg_def_id=rev_reg_def_id, options=options
        )
        await self.notify(event)

    async def emit_store_revocation_list_event(
        self,
        rev_reg_def_id: str,
        result: RevListResult,
        options: Optional[dict] = None,
    ) -> None:
        """Emit event to request revocation list storage.

        Args:
            rev_reg_def_id (str): revocation registry definition ID
            result (RevListResult): revocation list result
            options (dict): storage options

        """
        LOGGER.debug(
            "Emitting store revocation list event for rev_reg_def_id: %s",
            rev_reg_def_id,
        )
        options = options or {}

        # Emit event to request revocation list storage
        event = RevListStoreRequestedEvent.with_payload(
            rev_reg_def_id=rev_reg_def_id, result=result, options=options
        )
        await self.notify(event)

    async def create_and_register_revocation_list(
        self, rev_reg_def_id: str, options: Optional[dict] = None
    ) -> None:
        """Handle revocation list creation request event.

        Args:
            rev_reg_def_id (str): revocation registry definition ID
            options (dict): creation options

        """
        options = options or {}
        retry_count = options.get("retry_count", 0)

        try:
            # Fetch revocation registry definition and private definition
            async with self.profile.session() as session:
                LOGGER.debug("Fetching revocation registry definition and private data")
                rev_reg_def_entry = await session.handle.fetch(
                    CATEGORY_REV_REG_DEF, rev_reg_def_id
                )
                rev_reg_def_private_entry = await session.handle.fetch(
                    CATEGORY_REV_REG_DEF_PRIVATE, rev_reg_def_id
                )

                # Ensure both rev reg definition and private definition are present
                missing_items = []
                if not rev_reg_def_entry:
                    missing_items.append("revocation registry definition")
                if not rev_reg_def_private_entry:
                    missing_items.append("revocation registry private definition")

                if missing_items:
                    raise AskarError(
                        AskarErrorCode.NOT_FOUND,
                        f"Revocation registry data not found: {', '.join(missing_items)}",
                    )

                # Fetch credential definition
                cred_def_id = rev_reg_def_entry.value_json["credDefId"]
                cred_def_entry = await session.handle.fetch(
                    CATEGORY_CRED_DEF, cred_def_id
                )
                if not cred_def_entry:
                    raise AskarError(
                        AskarErrorCode.NOT_FOUND,
                        f"Credential definition {cred_def_id} not found",
                    )

            # Deserialize rev reg def, private def, and cred def
            rev_reg_def = RevRegDef.deserialize(rev_reg_def_entry.value_json)
            rev_reg_def_private = RevocationRegistryDefinitionPrivate.load(
                rev_reg_def_private_entry.value_json
            )
            cred_def = CredDef.deserialize(cred_def_entry.value_json)

            # TODO This is a little rough; stored tails location will have public uri
            rev_reg_def.value.tails_location = self.get_local_tails_path(rev_reg_def)

            rev_list = RevocationStatusList.create(
                cred_def.to_native(),
                rev_reg_def_id,
                rev_reg_def.to_native(),
                rev_reg_def_private,
                rev_reg_def.issuer_id,
            )

            # Perform the actual revocation list creation and registration
            anoncreds_registry = self.profile.inject(AnonCredsRegistry)
            result = await anoncreds_registry.register_revocation_list(
                self.profile, rev_reg_def, RevList.from_native(rev_list), options
            )

            if options.get("failed_to_upload", False):
                # ??? Why register revocation list if we already know tails upload failed?
                result.revocation_list_state.state = RevListState.STATE_FAILED

            # Emit success event with the result to trigger store request
            LOGGER.debug(
                "Emitting successful create and register revocation list event for "
                "rev_reg_def_id: %s, tag: %s",
                rev_reg_def_id,
                rev_reg_def.tag,
            )
            options["first_registry"] = rev_reg_def.tag == FIRST_REGISTRY_TAG
            event = RevListCreateResponseEvent.with_payload(
                rev_reg_def_id=rev_reg_def_id,
                rev_list_result=result,
                options=options,
            )
            await self.notify(event)

        except Exception as err:
            # Emit failure event with appropriate error message based on exception type
            should_retry = True
            if isinstance(err, AskarError):
                error_msg = f"Error retrieving records: {str(err)}"
                if err.code == AskarErrorCode.NOT_FOUND:
                    should_retry = False
            elif isinstance(err, AnoncredsError):
                error_msg = f"Error creating revocation list: {str(err)}"
            else:
                error_msg = f"Revocation list creation failed: {str(err)}"

            event = RevListCreateResponseEvent.with_failure(
                rev_reg_def_id=rev_reg_def_id,
                error_msg=error_msg,
                should_retry=should_retry,
                retry_count=retry_count,
                options=options,
            )
            await self.notify(event)

    async def store_revocation_registry_list(self, result: RevListResult) -> None:
        """Store a revocation registry list."""
        LOGGER.debug("Storing revocation registry list")

        identifier = result.job_id or result.rev_reg_def_id
        if not identifier:
            LOGGER.error("No identifier found in revocation list result")
            raise AnonCredsRevocationError(
                "Revocation registry definition id or job id not found"
            )

        rev_list = result.revocation_list_state.revocation_list
        try:
            async with self.profile.session() as session:
                LOGGER.debug("Inserting revocation list with identifier=%s", identifier)
                await session.handle.insert(
                    CATEGORY_REV_LIST,
                    identifier,
                    value_json={
                        "rev_list": rev_list.serialize(),
                        # AnonCreds uses the 0 index internally
                        # and can't be used for a credential
                        "next_index": 1,
                        "pending": None,
                    },
                    tags={
                        "state": result.revocation_list_state.state,
                        "pending": "false",
                    },
                )
                LOGGER.debug("Revocation list stored successfully")

            if result.revocation_list_state.state == STATE_FINISHED:
                LOGGER.debug("Revocation list is finished, emitting event")
                await self.notify(
                    RevListFinishedEvent.with_payload(
                        rev_list.rev_reg_def_id, rev_list.revocation_list
                    )
                )

        except AskarError as err:
            LOGGER.error("Failed to store revocation registry list: %s", err)
            raise AnonCredsRevocationError(
                "Error saving new revocation registry"
            ) from err

    async def handle_store_revocation_list_request(
        self,
        rev_reg_def_id: str,
        result: RevListResult,
        options: Optional[dict] = None,
    ) -> None:
        """Handle revocation list store request.

        Args:
            rev_reg_def_id (str): revocation registry definition ID
            result (RevListResult): revocation list result
            options (dict): storage options

        """
        options = options or {}
        retry_count = options.pop("retry_count", 0)

        try:
            # Store the revocation list
            await self.store_revocation_registry_list(result)

            # Emit success event
            event = RevListStoreResponseEvent.with_payload(
                rev_reg_def_id=rev_reg_def_id,
                result=result,
                options=options,
            )
            await self.notify(event)

        except Exception as err:
            # Emit failure event
            should_retry = True
            if isinstance(err, AskarError):
                error_msg = f"Error storing revocation list: {str(err)}"
                if err.code == AskarErrorCode.NOT_FOUND:
                    should_retry = False
            else:
                error_msg = f"Revocation list store failed: {str(err)}"

            event = RevListStoreResponseEvent.with_failure(
                rev_reg_def_id=rev_reg_def_id,
                error_msg=error_msg,
                should_retry=should_retry,
                retry_count=retry_count,
                result=result,
                options=options,
            )
            await self.notify(event)

    async def finish_revocation_list(  # From TXN manager
        self, job_id: str, rev_reg_def_id: str, revoked: list
    ) -> None:
        """Mark a revocation list as finished."""
        LOGGER.debug(
            "Finishing revocation list job_id=%s, rev_reg_def_id=%s, revoked=%s",
            job_id,
            rev_reg_def_id,
            revoked,
        )
        async with self.profile.transaction() as txn:
            # Finish the registration if the list is new, otherwise already updated
            existing_list = await txn.handle.fetch(
                CATEGORY_REV_LIST,
                rev_reg_def_id,
            )
            if not existing_list:
                LOGGER.debug("No existing list found, finishing registration")
                await self._finish_registration(
                    txn,
                    CATEGORY_REV_LIST,
                    job_id,
                    rev_reg_def_id,
                    state=STATE_FINISHED,
                )
                await txn.commit()
                LOGGER.debug("Revocation list finish transaction committed")
            else:
                LOGGER.debug("Existing list found, skipping registration finish")
            # Notify about revoked creds on any list update
            await self.notify(RevListFinishedEvent.with_payload(rev_reg_def_id, revoked))

    async def update_revocation_list(  # From TXN manager
        self,
        rev_reg_def_id: str,
        prev: RevList,
        curr: RevList,
        revoked: Sequence[int],
        options: Optional[dict] = None,
    ) -> RevListResult:
        """Publish and update to a revocation list."""
        LOGGER.debug(
            "Updating revocation list for rev_reg_def_id=%s with %d revoked credentials",
            rev_reg_def_id,
            len(revoked),
        )
        options = options or {}

        try:
            async with self.profile.session() as session:
                LOGGER.debug(
                    "Fetching revocation registry definition for %s", rev_reg_def_id
                )
                rev_reg_def_entry = await session.handle.fetch(
                    CATEGORY_REV_REG_DEF, rev_reg_def_id
                )
        except AskarError as err:
            LOGGER.error(
                "Failed to retrieve revocation registry definition for %s: %s",
                rev_reg_def_id,
                str(err),
            )
            raise AnonCredsRevocationError(
                "Error retrieving revocation registry definition"
            ) from err

        if not rev_reg_def_entry:
            LOGGER.error(
                "Revocation registry definition not found for id %s",
                rev_reg_def_id,
            )
            raise AnonCredsRevocationError(
                f"Revocation registry definition not found for id {rev_reg_def_id}"
            )

        LOGGER.debug("Successfully retrieved revocation registry definition")

        try:
            async with self.profile.session() as session:
                LOGGER.debug("Fetching revocation list for %s", rev_reg_def_id)
                rev_list_entry = await session.handle.fetch(
                    CATEGORY_REV_LIST, rev_reg_def_id
                )
        except AskarError as err:
            LOGGER.error(
                "Failed to retrieve revocation list for %s: %s",
                rev_reg_def_id,
                str(err),
            )
            raise AnonCredsRevocationError("Error retrieving revocation list") from err

        if not rev_list_entry:
            LOGGER.error("Revocation list not found for id %s", rev_reg_def_id)
            raise AnonCredsRevocationError(
                f"Revocation list not found for id {rev_reg_def_id}"
            )

        LOGGER.debug("Successfully retrieved revocation list")

        rev_reg_def = RevRegDef.deserialize(rev_reg_def_entry.value_json)
        rev_list = RevList.deserialize(rev_list_entry.value_json["rev_list"])

        if rev_list.revocation_list != curr.revocation_list:
            LOGGER.error(
                "Revocation list mismatch for %s: stored list does not match passed list",
                rev_reg_def_id,
            )
            raise AnonCredsRevocationError("Passed revocation list does not match stored")

        LOGGER.debug("Revocation list validation passed, proceeding with registry update")

        anoncreds_registry = self.profile.inject(AnonCredsRegistry)
        result = await anoncreds_registry.update_revocation_list(
            self.profile, rev_reg_def, prev, curr, revoked, options
        )

        LOGGER.debug(
            "Registry update completed with state: %s",
            result.revocation_list_state.state,
        )

        try:
            async with self.profile.session() as session:
                LOGGER.debug("Updating revocation list entry in storage")
                rev_list_entry_upd = await session.handle.fetch(
                    CATEGORY_REV_LIST, result.rev_reg_def_id, for_update=True
                )
                if not rev_list_entry_upd:
                    LOGGER.error(
                        "Revocation list entry disappeared during update for %s",
                        rev_reg_def_id,
                    )
                    raise AnonCredsRevocationError(
                        f"Revocation list not found for id {rev_reg_def_id}"
                    )
                tags = rev_list_entry_upd.tags
                tags["state"] = result.revocation_list_state.state
                await session.handle.replace(
                    CATEGORY_REV_LIST,
                    result.rev_reg_def_id,
                    value=rev_list_entry_upd.value,
                    tags=tags,
                )
                LOGGER.debug("Successfully updated revocation list entry in storage")
        except AskarError as err:
            LOGGER.error(
                "Failed to save updated revocation list for %s: %s",
                rev_reg_def_id,
                str(err),
            )
            raise AnonCredsRevocationError(
                "Error saving new revocation registry"
            ) from err

        LOGGER.debug(
            "Completed revocation list update for %s with %d revoked credentials",
            rev_reg_def_id,
            len(revoked),
        )
        return result

    async def get_created_revocation_list(  # From TXN manager
        self, rev_reg_def_id: str
    ) -> Optional[RevList]:
        """Return rev list from record in wallet."""
        LOGGER.debug(
            "Retrieving created revocation list for rev_reg_def_id: %s",
            rev_reg_def_id,
        )

        try:
            async with self.profile.session() as session:
                LOGGER.debug("Fetching revocation list entry from storage")
                rev_list_entry = await session.handle.fetch(
                    CATEGORY_REV_LIST, rev_reg_def_id
                )
        except AskarError as err:
            LOGGER.error(
                "Failed to retrieve revocation list for %s: %s",
                rev_reg_def_id,
                str(err),
            )
            raise AnonCredsRevocationError("Error retrieving revocation list") from err

        if rev_list_entry:
            LOGGER.debug(
                "Successfully retrieved revocation list entry, deserializing RevList"
            )
            return RevList.deserialize(rev_list_entry.value_json["rev_list"])

        LOGGER.debug("No revocation list entry found, returning None")
        return None

    async def get_revocation_lists_with_pending_revocations(  # From TXN manager
        self,
    ) -> Sequence[str]:
        """Return a list of rev reg def ids with pending revocations."""
        LOGGER.debug("Retrieving revocation lists with pending revocations")

        try:
            async with self.profile.session() as session:
                LOGGER.debug("Fetching all revocation list entries with pending=True")
                rev_list_entries = await session.handle.fetch_all(
                    CATEGORY_REV_LIST,
                    {"pending": "true"},
                )
        except AskarError as err:
            LOGGER.error(
                "Failed to retrieve revocation lists with pending revocations: %s",
                str(err),
            )
            raise AnonCredsRevocationError("Error retrieving revocation list") from err

        if rev_list_entries:
            result = [entry.name for entry in rev_list_entries]
            LOGGER.debug(
                "Found %d revocation lists with pending revocations: %s",
                len(result),
                result,
            )
            return result

        LOGGER.debug("No revocation lists with pending revocations found")
        return []

    async def retrieve_tails(self, rev_reg_def: RevRegDef) -> str:
        """Retrieve tails file from server."""
        LOGGER.debug(
            "Starting tails file download for hash: %s from location: %s",
            rev_reg_def.value.tails_hash,
            rev_reg_def.value.tails_location,
        )

        tails_file_path = Path(self.get_local_tails_path(rev_reg_def))
        tails_file_dir = tails_file_path.parent
        if not tails_file_dir.exists():
            LOGGER.debug("Creating tails directory: %s", tails_file_dir)
            tails_file_dir.mkdir(parents=True)

        buffer_size = 65536  # should be multiple of 32 bytes for sha256
        file_hasher = hashlib.sha256()
        LOGGER.debug("Opening tails file for writing: %s", tails_file_path)
        with open(tails_file_path, "wb", buffer_size) as tails_file:
            with Session() as req_session:
                try:
                    LOGGER.debug("Making HTTP request to download tails file")
                    resp = req_session.get(rev_reg_def.value.tails_location, stream=True)
                    # Should this directly raise an Error?
                    if resp.status_code != http.HTTPStatus.OK:
                        LOGGER.warning(
                            "Unexpected status code for tails file: %s (expected 200)",
                            resp.status_code,
                        )
                    LOGGER.debug("Writing tails file content and computing hash")
                    for buf in resp.iter_content(chunk_size=buffer_size):
                        tails_file.write(buf)
                        file_hasher.update(buf)
                except RequestException as rx:
                    LOGGER.error(
                        "HTTP request failed while retrieving tails file: %s", rx
                    )
                    raise AnonCredsRevocationError(f"Error retrieving tails file: {rx}")

        download_tails_hash = base58.b58encode(file_hasher.digest()).decode("utf-8")
        LOGGER.debug(
            "Computed hash for downloaded file: %s, expected: %s",
            download_tails_hash,
            rev_reg_def.value.tails_hash,
        )

        if download_tails_hash != rev_reg_def.value.tails_hash:
            LOGGER.debug("Hash mismatch detected, attempting to delete invalid file")
            try:
                os.remove(tails_file_path)
                LOGGER.debug("Successfully deleted invalid tails file")
            except OSError as err:
                LOGGER.warning("Could not delete invalid tails file: %s", err)

            LOGGER.error(
                "Tails file hash verification failed - downloaded: %s, expected: %s",
                download_tails_hash,
                rev_reg_def.value.tails_hash,
            )
            raise AnonCredsRevocationError(
                "The hash of the downloaded tails file does not match."
            )

        LOGGER.debug(
            "Successfully downloaded and verified tails file: %s",
            tails_file_path,
        )
        return str(tails_file_path)

    def _check_url(self, url: str) -> None:
        parsed = urlparse(url)
        if not (parsed.scheme and parsed.netloc and parsed.path):
            LOGGER.error("Invalid URL format: %s", url)
            raise AnonCredsRevocationError("URI {} is not a valid URL".format(url))

    def generate_public_tails_uri(self, rev_reg_def: RevRegDef) -> str:
        """Construct tails uri from rev_reg_def."""
        LOGGER.debug(
            "Generating public tails URI for cred def id %s", rev_reg_def.cred_def_id
        )
        tails_base_url = self.profile.settings.get("tails_server_base_url")
        if not tails_base_url:
            LOGGER.error("tails_server_base_url not configured in profile settings")
            raise AnonCredsRevocationError("tails_server_base_url not configured")

        public_tails_uri = (
            tails_base_url.rstrip("/") + f"/hash/{rev_reg_def.value.tails_hash}"
        )

        self._check_url(public_tails_uri)
        LOGGER.debug("Generated public tails URI: %s", public_tails_uri)
        return public_tails_uri

    def get_local_tails_path(self, rev_reg_def: RevRegDef) -> str:
        """Get the local path to the tails file."""
        tails_dir = indy_client_dir("tails", create=False)
        return os.path.join(tails_dir, rev_reg_def.value.tails_hash)

    async def emit_upload_tails_file_event(
        self,
        rev_reg_def_id: str,
        rev_reg_def: RevRegDef,
        options: Optional[dict] = None,
    ) -> None:
        """Emit event to request tails file upload.

        Args:
            rev_reg_def_id (str): revocation registry definition ID
            rev_reg_def (RevRegDef): revocation registry definition
            options (dict): upload options

        """
        options = options or {}

        event = TailsUploadRequestedEvent.with_payload(
            rev_reg_def_id=rev_reg_def_id,
            rev_reg_def=rev_reg_def,
            options=options,
        )
        await self.notify(event)

    async def upload_tails_file(self, rev_reg_def: RevRegDef) -> None:
        """Upload the local tails file to the tails server."""
        LOGGER.debug("Uploading tails file for cred def id %s", rev_reg_def.cred_def_id)
        tails_server = AnonCredsTailsServer()

        local_path = self.get_local_tails_path(rev_reg_def)
        if not Path(local_path).is_file():
            LOGGER.error("Local tails file not found at %s", local_path)
            raise AnonCredsRevocationError("Local tails file not found")

        LOGGER.debug("Starting tails file upload")
        (upload_success, result) = await tails_server.upload_tails_file(
            self.profile.context,
            rev_reg_def.value.tails_hash,
            local_path,
            interval=0.8,
            backoff=-0.5,
            max_attempts=5,  # heuristic: respect HTTP timeout
        )

        if not upload_success:
            LOGGER.error(
                "Tails file upload failed for %s: %s", rev_reg_def.cred_def_id, result
            )
            raise AnonCredsRevocationError(
                f"Tails file for rev reg for {rev_reg_def.cred_def_id} "
                f"failed to upload: {result}"
            )
        if rev_reg_def.value.tails_location != result:
            LOGGER.error(
                "Tails file uploaded to wrong location: expected %s, got %s",
                rev_reg_def.value.tails_location,
                result,
            )
            raise AnonCredsRevocationError(
                f"Tails file for rev reg for {rev_reg_def.cred_def_id} "
                f"uploaded to wrong location: {result} "
                f"(should have been {rev_reg_def.value.tails_location})"
            )

    async def handle_tails_upload_request(
        self,
        rev_reg_def_id: str,
        rev_reg_def: RevRegDef,
        options: Optional[dict] = None,
    ) -> None:
        """Handle tails upload request event.

        Args:
            rev_reg_def_id (str): revocation registry definition ID
            rev_reg_def (RevRegDef): revocation registry definition
            options (dict): upload options

        """
        options = options or {}
        retry_count = options.pop("retry_count", 0)

        try:
            # Perform tails upload
            await self.upload_tails_file(rev_reg_def)

            # Emit success event
            event = TailsUploadResponseEvent.with_payload(
                rev_reg_def_id=rev_reg_def_id,
                rev_reg_def=rev_reg_def,
                options=options,
            )
            await self.notify(event)

        except Exception as err:
            # Emit failure event
            error_msg = f"Tails upload failed: {str(err)}"

            event = TailsUploadResponseEvent.with_failure(
                rev_reg_def_id=rev_reg_def_id,
                rev_reg_def=rev_reg_def,
                error_msg=error_msg,
                retry_count=retry_count,
                options=options,
            )
            await self.notify(event)

    async def get_or_fetch_local_tails_path(self, rev_reg_def: RevRegDef) -> str:
        """Return path to local tails file.

        If not present, retrieve from tails server.
        """
        LOGGER.debug(
            "Getting or fetching local tails path for cred def id %s",
            rev_reg_def.cred_def_id,
        )
        tails_file_path = self.get_local_tails_path(rev_reg_def)
        if Path(tails_file_path).is_file():
            LOGGER.debug("Local tails file exists at %s", tails_file_path)
            return tails_file_path
        LOGGER.debug("Local tails file not found, retrieving from server")
        return await self.retrieve_tails(rev_reg_def)

    # Registry Management
    async def handle_full_registry_event(
        self,
        rev_reg_def_id: str,
        cred_def_id: str,
        options: Optional[dict] = None,
    ) -> None:
        """Handle the full registry process event.

        This method handles the full registry process by:
        1. Finding the backup registry that should become active
        2. Setting the current registry state to full
        3. Activating the backup registry (event-driven)
        4. Creating a new backup registry (event-driven)

        Args:
            rev_reg_def_id (str): revocation registry definition ID that is full
            cred_def_id (str): credential definition ID
            options (dict): handling options

        """
        LOGGER.debug(
            "Handling full registry event for cred def id: %s, rev reg def id: %s",
            cred_def_id,
            rev_reg_def_id,
        )
        options = options or {}
        retry_count = options.get("retry_count", 0)

        try:
            # Find the backup registry that should become active
            async with self.profile.session() as session:
                # First, get the active registry
                active_rev_reg_def = await session.handle.fetch(
                    CATEGORY_REV_REG_DEF, rev_reg_def_id
                )
                if not active_rev_reg_def:
                    raise AnonCredsRevocationError(
                        f"Active registry {rev_reg_def_id} not found"
                    )

                # Then, find the backup registry (finished and not active)
                rev_reg_defs = await session.handle.fetch_all(
                    CATEGORY_REV_REG_DEF,
                    {
                        "active": "false",
                        "cred_def_id": cred_def_id,
                        "state": RevRegDefState.STATE_FINISHED,
                    },
                    limit=1,
                )
                if not rev_reg_defs:
                    raise AnonCredsRevocationError(
                        "Error handling full registry. No backup registry available."
                    )

                backup_rev_reg_def_id = rev_reg_defs[0].name

            # Set the current registry state to full
            await self.set_rev_reg_state(rev_reg_def_id, RevRegDefState.STATE_FULL)

            LOGGER.info(
                "Registry %s state set to full, activating backup registry %s",
                rev_reg_def_id,
                backup_rev_reg_def_id,
            )

            # Store context for later use in creating new backup after activation
            set_active_registry_options = options.copy()
            set_active_registry_options["cred_def_id"] = cred_def_id
            set_active_registry_options["old_rev_reg_def_id"] = rev_reg_def_id

            # Activate the backup registry (this will trigger creation of new backup)
            await self.emit_set_active_registry_event(
                rev_reg_def_id=backup_rev_reg_def_id,
                options=set_active_registry_options,
            )

            full_handling_response_event = RevRegFullHandlingResponseEvent.with_payload(
                old_rev_reg_def_id=rev_reg_def_id,
                new_active_rev_reg_def_id=backup_rev_reg_def_id,
                cred_def_id=cred_def_id,
                options=options,
            )
            await self.notify(full_handling_response_event)

        except Exception as err:
            # Emit failure event
            error_msg = f"Full registry handling failed: {str(err)}"

            event = RevRegFullHandlingResponseEvent.with_failure(
                old_rev_reg_def_id=rev_reg_def_id,
                cred_def_id=cred_def_id,
                error_msg=error_msg,
                retry_count=retry_count,
                options=options,
            )
            await self.notify(event)

    async def decommission_registry(self, cred_def_id: str) -> list:  # ✅
        """Decommission post-init registries and start the next registry generation."""
        LOGGER.debug("Decommissioning registries for cred_def_id=%s", cred_def_id)
        active_reg = await self.get_or_create_active_registry(cred_def_id)

        # create new one and set active
        LOGGER.debug("Creating new registry to replace active one")
        new_reg = await self.create_and_register_revocation_registry_definition(
            issuer_id=active_reg.rev_reg_def.issuer_id,
            cred_def_id=active_reg.rev_reg_def.cred_def_id,
            registry_type=active_reg.rev_reg_def.type,
            tag=self._generate_backup_registry_tag(),
            max_cred_num=active_reg.rev_reg_def.value.max_cred_num,
        )
        # set new as active...
        LOGGER.debug("Setting new registry %s as active", new_reg.rev_reg_def_id)
        await self.set_active_registry(new_reg.rev_reg_def_id)

        # decommission everything except init/wait
        LOGGER.debug("Decommissioning existing registries except init/wait state")
        async with self.profile.transaction() as txn:
            registries = await txn.handle.fetch_all(
                CATEGORY_REV_REG_DEF,
                {
                    "cred_def_id": cred_def_id,
                },
                for_update=True,
            )

            recs = list(
                filter(
                    lambda r: r.tags.get("state") != RevRegDefState.STATE_WAIT,
                    registries,
                )
            )
            LOGGER.debug("Found %d registries to decommission", len(recs))
            for rec in recs:
                if rec.name != new_reg.rev_reg_def_id:
                    LOGGER.debug("Decommissioning registry %s", rec.name)
                    tags = rec.tags
                    tags["active"] = "false"
                    tags["state"] = RevRegDefState.STATE_DECOMMISSIONED
                    await txn.handle.replace(
                        CATEGORY_REV_REG_DEF,
                        rec.name,
                        rec.value,
                        tags,
                    )
            await txn.commit()
            LOGGER.debug("Committed decommissioning transaction")
        # create a second one for backup, don't make it active
        LOGGER.debug("Creating backup registry")
        backup_reg = await self.create_and_register_revocation_registry_definition(
            issuer_id=active_reg.rev_reg_def.issuer_id,
            cred_def_id=active_reg.rev_reg_def.cred_def_id,
            registry_type=active_reg.rev_reg_def.type,
            tag=self._generate_backup_registry_tag(),
            max_cred_num=active_reg.rev_reg_def.value.max_cred_num,
        )

        LOGGER.debug(
            "New registry = %s.\nBackup registry = %s.\nDecommissioned registries = %s",
            new_reg,
            backup_reg,
            recs,
        )
        return recs

    async def get_or_create_active_registry(self, cred_def_id: str) -> RevRegDefResult:
        """Get or create a revocation registry for the given cred def id."""
        LOGGER.debug(
            "Getting or creating active registry for cred_def_id=%s", cred_def_id
        )
        async with self.profile.session() as session:
            rev_reg_defs = await session.handle.fetch_all(
                CATEGORY_REV_REG_DEF,
                {
                    "cred_def_id": cred_def_id,
                    "active": "true",
                },
                limit=1,
            )

        if not rev_reg_defs:
            LOGGER.error("No active registry found for cred_def_id=%s", cred_def_id)
            raise AnonCredsRevocationError("No active registry")

        entry = rev_reg_defs[0]
        LOGGER.debug("Found active registry %s", entry.name)

        rev_reg_def = RevRegDef.deserialize(entry.value_json)
        result = RevRegDefResult(
            None,
            RevRegDefState(
                state=STATE_FINISHED,
                revocation_registry_definition_id=entry.name,
                revocation_registry_definition=rev_reg_def,
            ),
            registration_metadata={},
            revocation_registry_definition_metadata={},
        )
        return result

    async def emit_full_registry_event(
        self,
        rev_reg_def_id: str,
        cred_def_id: str,
        options: Optional[dict] = None,
    ) -> None:
        """Emit event to indicate full registry detected.

        Args:
            rev_reg_def_id (str): revocation registry definition ID that is full
            cred_def_id (str): credential definition ID
            options (dict): handling options

        """
        LOGGER.debug(
            "Emitting full registry event for cred def id: %s, rev reg def id: %s",
            cred_def_id,
            rev_reg_def_id,
        )
        options = options or {}

        # Emit event to indicate full registry detected
        event = RevRegFullDetectedEvent.with_payload(
            rev_reg_def_id=rev_reg_def_id,
            cred_def_id=cred_def_id,
            options=options,
        )
        await self.notify(event)

    async def emit_set_active_registry_event(
        self,
        rev_reg_def_id: str,
        options: Optional[dict] = None,
    ) -> None:
        """Emit event to request registry activation.

        Args:
            rev_reg_def_id (str): revocation registry definition ID
            options (dict): activation options

        """
        LOGGER.debug(
            "Emitting set active registry event for rev reg def id: %s", rev_reg_def_id
        )
        options = options or {}

        event = RevRegActivationRequestedEvent.with_payload(
            rev_reg_def_id=rev_reg_def_id,
            options=options,
        )
        await self.notify(event)

    async def handle_activate_registry_request(
        self,
        rev_reg_def_id: str,
        options: Optional[dict] = None,
    ) -> None:
        """Handle registry activation request event.

        Args:
            rev_reg_def_id (str): revocation registry definition ID
            options (dict): activation options

        """
        options = options or {}
        retry_count = options.pop("retry_count", 0)

        try:
            # Perform registry activation
            await self.set_active_registry(rev_reg_def_id)

            # Emit success event
            event = RevRegActivationResponseEvent.with_payload(
                rev_reg_def_id=rev_reg_def_id,
                options=options,
            )
            await self.notify(event)

        except Exception as err:
            # Emit failure event
            error_msg = f"Registry activation failed: {str(err)}"

            event = RevRegActivationResponseEvent.with_failure(
                rev_reg_def_id=rev_reg_def_id,
                error_msg=error_msg,
                retry_count=retry_count,
                options=options,
            )
            await self.notify(event)

    # Credential Operations
    async def create_credential_w3c(
        self,
        w3c_credential_offer: dict,
        w3c_credential_request: dict,
        w3c_credential_values: dict,
        *,
        retries: int = 5,
    ) -> Tuple[str, str, str]:
        """Create a w3c_credential.

        Args:
            w3c_credential_offer: Credential Offer to create w3c_credential for
            w3c_credential_request: Credential request to create w3c_credential for
            w3c_credential_values: Values to go in w3c_credential
            retries: number of times to retry w3c_credential creation

        Returns:
            A tuple of created w3c_credential and revocation id

        """
        LOGGER.debug("Creating W3C credential with %d retries", retries)
        return await self._create_credential_helper(
            w3c_credential_offer,
            w3c_credential_request,
            w3c_credential_values,
            W3cCredential,
            retries=retries,
        )

    async def _get_cred_def_objects(
        self, credential_definition_id: str
    ) -> tuple[Entry, Entry]:
        LOGGER.debug(
            "Fetching credential definition objects for %s", credential_definition_id
        )
        try:
            async with self.profile.session() as session:
                cred_def = await session.handle.fetch(
                    CATEGORY_CRED_DEF, credential_definition_id
                )
                cred_def_private = await session.handle.fetch(
                    CATEGORY_CRED_DEF_PRIVATE, credential_definition_id
                )
        except AskarError as err:
            LOGGER.error(
                "Error retrieving credential definition %s: %s",
                credential_definition_id,
                err,
            )
            raise AnonCredsRevocationError(
                "Error retrieving credential definition"
            ) from err
        if not cred_def or not cred_def_private:
            LOGGER.error(
                "Credential definition not found for %s", credential_definition_id
            )
            raise AnonCredsRevocationError(
                "Credential definition not found for credential issuance"
            )
        LOGGER.debug("Successfully retrieved credential definition objects")
        return cred_def, cred_def_private

    def _check_and_get_attribute_raw_values(
        self, schema_attributes: List[str], credential_values: dict
    ) -> Mapping[str, str]:
        LOGGER.debug(
            "Checking and getting attribute raw values for %d attributes",
            len(schema_attributes),
        )
        raw_values = {}
        for attribute in schema_attributes:
            # Ensure every attribute present in schema to be set.
            # Extraneous attribute names are ignored.
            try:
                credential_value = credential_values[attribute]
            except KeyError:
                LOGGER.error("Missing value for schema attribute '%s'", attribute)
                raise AnonCredsRevocationError(
                    "Provided credential values are missing a value "
                    f"for the schema attribute '{attribute}'"
                )

            raw_values[attribute] = str(credential_value)
        LOGGER.debug("Successfully processed all attribute values")
        return raw_values

    async def _create_credential(
        self,
        credential_definition_id: str,
        schema_attributes: List[str],
        credential_offer: dict,
        credential_request: dict,
        credential_values: dict,
        credential_type: Union[Credential, W3cCredential],
        rev_reg_def_id: Optional[str] = None,
        tails_file_path: Optional[str] = None,
    ) -> Tuple[str, str]:
        """Create a credential.

        Args:
            credential_definition_id: The credential definition ID
            schema_attributes: The schema attributes
            credential_offer: The credential offer
            credential_request: The credential request
            credential_values: The credential values
            credential_type: The credential type
            rev_reg_def_id: The revocation registry definition ID
            tails_file_path: The tails file path

        Returns:
            A tuple of created credential and revocation ID

        """
        LOGGER.debug(
            "Creating credential for cred_def_id=%s with rev_reg_def_id=%s",
            credential_definition_id,
            rev_reg_def_id,
        )

        def _handle_missing_entries(rev_list: Entry, rev_reg_def: Entry, rev_key: Entry):
            if not rev_list:
                LOGGER.error("Revocation registry list not found for %s", rev_reg_def_id)
                raise AnonCredsRevocationError("Revocation registry list not found")
            if not rev_reg_def:
                LOGGER.error(
                    "Revocation registry definition not found for %s", rev_reg_def_id
                )
                raise AnonCredsRevocationError("Revocation registry definition not found")
            if not rev_key:
                LOGGER.error(
                    "Revocation registry definition private data not found for %s",
                    rev_reg_def_id,
                )
                raise AnonCredsRevocationError(
                    "Revocation registry definition private data not found"
                )

        def _has_required_id_and_tails_path():
            return rev_reg_def_id and tails_file_path

        revoc = None
        credential_revocation_id = None
        rev_list = None

        if _has_required_id_and_tails_path():
            # We need to make sure the read, index increment, and write
            # operations are done in a transaction.
            # TODO: This isn't fully atomic in a clustered environment as the
            # read transaction may happen concurrently with another.
            async with self.profile.transaction() as txn:
                rev_reg_def = await txn.handle.fetch(CATEGORY_REV_REG_DEF, rev_reg_def_id)
                rev_list = await txn.handle.fetch(CATEGORY_REV_LIST, rev_reg_def_id)
                rev_key = await txn.handle.fetch(
                    CATEGORY_REV_REG_DEF_PRIVATE, rev_reg_def_id
                )

                _handle_missing_entries(rev_list, rev_reg_def, rev_key)

                rev_list_value_json = rev_list.value_json
                rev_list_tags = rev_list.tags

                # If the rev_list state is failed then the tails file was never uploaded,
                # try to upload it now and finish the revocation list
                if rev_list_tags.get("state") == RevListState.STATE_FAILED:
                    LOGGER.debug(
                        "Revocation list in failed state, attempting to upload tails file"
                    )
                    await self.upload_tails_file(
                        RevRegDef.deserialize(rev_reg_def.value_json)
                    )
                    rev_list_tags["state"] = RevListState.STATE_FINISHED
                    LOGGER.debug("Updated revocation list state to finished")

                rev_reg_index = rev_list_value_json["next_index"]
                LOGGER.debug("Using revocation registry index %d", rev_reg_index)
                try:
                    rev_reg_def = RevocationRegistryDefinition.load(rev_reg_def.raw_value)
                    rev_list = RevocationStatusList.load(rev_list_value_json["rev_list"])
                except AnoncredsError as err:
                    LOGGER.error("Error loading revocation registry: %s", err)
                    raise AnonCredsRevocationError(
                        "Error loading revocation registry"
                    ) from err

                # NOTE: we increment the index ahead of time to keep the
                # transaction short. The revocation registry itself will NOT
                # be updated because we always use ISSUANCE_BY_DEFAULT.
                # If something goes wrong later, the index will be skipped.
                # FIXME - double check issuance type in case of upgraded wallet?
                if rev_reg_index > rev_reg_def.max_cred_num:
                    LOGGER.error(
                        "Revocation registry is full: index %d > max %d",
                        rev_reg_index,
                        rev_reg_def.max_cred_num,
                    )
                    raise AnonCredsRevocationRegistryFullError(
                        "Revocation registry is full"
                    )
                rev_list_value_json["next_index"] = rev_reg_index + 1
                await txn.handle.replace(
                    CATEGORY_REV_LIST,
                    rev_reg_def_id,
                    value_json=rev_list_value_json,
                    tags=rev_list_tags,
                )
                await txn.commit()

            revoc = CredentialRevocationConfig(
                rev_reg_def,
                rev_key.raw_value,
                rev_list,
                rev_reg_index,
            )
            credential_revocation_id = str(rev_reg_index)
            LOGGER.debug(
                "Created revocation config with cred_rev_id=%s",
                credential_revocation_id,
            )

        cred_def, cred_def_private = await self._get_cred_def_objects(
            credential_definition_id
        )

        try:
            LOGGER.debug("Creating credential using anoncreds library")
            credential = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: credential_type.create(
                    cred_def=cred_def.raw_value,
                    cred_def_private=cred_def_private.raw_value,
                    cred_offer=credential_offer,
                    cred_request=credential_request,
                    attr_raw_values=self._check_and_get_attribute_raw_values(
                        schema_attributes, credential_values
                    ),
                    revocation_config=revoc,
                ),
            )
            LOGGER.debug("Successfully created credential")
        except AnoncredsError as err:
            LOGGER.error("Error creating credential: %s", err)
            raise AnonCredsRevocationError("Error creating credential") from err

        return credential.to_json(), credential_revocation_id

    async def create_credential(
        self,
        credential_offer: dict,
        credential_request: dict,
        credential_values: dict,
        *,
        retries: int = 5,
    ) -> Tuple[str, str, str]:
        """Create a credential.

        Args:
            credential_offer: Credential Offer to create credential for
            credential_request: Credential request to create credential for
            credential_values: Values to go in credential
            revoc_reg_id: ID of the revocation registry
            retries: number of times to retry credential creation

        Returns:
            A tuple of created credential and revocation id

        """
        LOGGER.debug("Creating credential with %d retries", retries)
        return await self._create_credential_helper(
            credential_offer,
            credential_request,
            credential_values,
            Credential,
            retries=retries,
        )

    async def _create_credential_helper(  # ✅
        self,
        credential_offer: dict,
        credential_request: dict,
        credential_values: dict,
        credential_type: Union[Credential, W3cCredential],
        *,
        retries: int = 5,
    ) -> Tuple[str, str, str]:
        """Create a credential.

        Args:
            credential_offer: Credential Offer to create credential for
            credential_request: Credential request to create credential for
            credential_values: Values to go in credential
            credential_type: Credential or W3cCredential
            retries: number of times to retry credential creation

        Returns:
            A tuple of created credential, revocation id, and the rev reg def id

        """
        LOGGER.debug(
            "Starting credential creation helper with credential type %s",
            credential_type.__name__,
        )
        issuer = AnonCredsIssuer(self.profile)
        anoncreds_registry = self.profile.inject(AnonCredsRegistry)
        schema_id = credential_offer["schema_id"]
        schema_result = await anoncreds_registry.get_schema(self.profile, schema_id)
        cred_def_id = credential_offer["cred_def_id"]

        revocable = await issuer.cred_def_supports_revocation(cred_def_id)
        LOGGER.debug("Credential definition %s revocable: %s", cred_def_id, revocable)

        for attempt in range(max(retries, 1)):
            if attempt > 0:
                LOGGER.debug(
                    "Waiting 2s before retrying credential issuance for cred def '%s'",
                    cred_def_id,
                )
                await asyncio.sleep(2)

            LOGGER.debug(
                "Credential creation attempt %d/%d", attempt + 1, max(retries, 1)
            )
            rev_reg_def_result = None
            if revocable:
                LOGGER.debug("Getting active registry for revocable credential")
                rev_reg_def_result = await self.get_or_create_active_registry(cred_def_id)
                if (
                    rev_reg_def_result.revocation_registry_definition_state.state
                    != STATE_FINISHED
                ):
                    LOGGER.debug(
                        "Registry not in finished state, continuing to next attempt"
                    )
                    continue
                rev_reg_def_id = rev_reg_def_result.rev_reg_def_id
                tails_file_path = self.get_local_tails_path(
                    rev_reg_def_result.rev_reg_def
                )
                LOGGER.debug(
                    "Using revocation registry %s with tails path %s",
                    rev_reg_def_id,
                    tails_file_path,
                )
            else:
                rev_reg_def_id = None
                tails_file_path = None

            try:
                cred_json, cred_rev_id = await self._create_credential(
                    cred_def_id,
                    schema_result.schema_value.attr_names,
                    credential_offer,
                    credential_request,
                    credential_values,
                    credential_type,
                    rev_reg_def_id,
                    tails_file_path,
                )
                LOGGER.debug(
                    "Successfully created credential with rev_id=%s", cred_rev_id
                )
            except AnonCredsRevocationError as err:
                LOGGER.warning("Failed to create credential: %s, retrying", err.message)
                continue

            def _is_full_registry(
                rev_reg_def_result: RevRegDefResult, cred_rev_id: str
            ) -> bool:
                # if we wait until max cred num is reached, we are too late.
                return (
                    rev_reg_def_result.rev_reg_def.value.max_cred_num
                    <= int(cred_rev_id) + 1
                )

            if rev_reg_def_id and _is_full_registry(rev_reg_def_result, cred_rev_id):
                await self.emit_full_registry_event(rev_reg_def_id, cred_def_id)

            LOGGER.debug("Credential creation completed successfully")
            return cred_json, cred_rev_id, rev_reg_def_id

        LOGGER.error(
            "Failed to create credential after %d attempts for cred_def_id=%s",
            max(retries, 1),
            cred_def_id,
        )
        raise AnonCredsRevocationError(
            f"Cred def '{cred_def_id}' revocation registry or list is in a bad state"
        )

    async def revoke_pending_credentials(
        self,
        revoc_reg_id: str,
        *,
        additional_crids: Optional[Sequence[int]] = None,
        limit_crids: Optional[Sequence[int]] = None,
    ) -> RevokeResult:
        """Revoke a set of credentials in a revocation registry.

        Args:
            revoc_reg_id: ID of the revocation registry
            additional_crids: sequences of additional credential indexes to revoke
            limit_crids: a sequence of credential indexes to limit revocation to
                If None, all pending revocations will be published.
                If given, the intersection of pending and limit crids will be published.

        Returns:
            Tuple with the update revocation list, list of cred rev ids not revoked

        """
        LOGGER.debug(
            "Starting revocation process for registry %s with "
            "additional_crids=%s, limit_crids=%s",
            revoc_reg_id,
            additional_crids,
            limit_crids,
        )
        updated_list = None
        failed_crids = set()
        max_attempt = 5
        attempt = 0

        while True:
            attempt += 1
            LOGGER.debug("Revocation attempt %d/%d", attempt, max_attempt)
            if attempt >= max_attempt:
                LOGGER.error(
                    "Max attempts (%d) reached while trying to update registry %s",
                    max_attempt,
                    revoc_reg_id,
                )
                raise AnonCredsRevocationError(
                    "Repeated conflict attempting to update registry"
                )
            try:
                async with self.profile.session() as session:
                    LOGGER.debug("Fetching revocation registry data for %s", revoc_reg_id)
                    rev_reg_def_entry = await session.handle.fetch(
                        CATEGORY_REV_REG_DEF, revoc_reg_id
                    )
                    rev_list_entry = await session.handle.fetch(
                        CATEGORY_REV_LIST, revoc_reg_id
                    )
                    rev_reg_def_private_entry = await session.handle.fetch(
                        CATEGORY_REV_REG_DEF_PRIVATE, revoc_reg_id
                    )
            except AskarError as err:
                LOGGER.error(
                    "Failed to retrieve revocation registry data for %s: %s",
                    revoc_reg_id,
                    str(err),
                )
                raise AnonCredsRevocationError(
                    "Error retrieving revocation registry"
                ) from err

            if (
                not rev_reg_def_entry
                or not rev_list_entry
                or not rev_reg_def_private_entry
            ):
                missing_data = []
                if not rev_reg_def_entry:
                    missing_data.append("revocation registry definition")
                if not rev_list_entry:
                    missing_data.append("revocation list")
                if not rev_reg_def_private_entry:
                    missing_data.append("revocation registry private definition")
                LOGGER.error(
                    "Missing required revocation registry data for %s: %s",
                    revoc_reg_id,
                    ", ".join(missing_data),
                )
                raise AnonCredsRevocationError(
                    f"Missing required revocation registry data: {' '.join(missing_data)}"
                )

            try:
                async with self.profile.session() as session:
                    cred_def_id = rev_reg_def_entry.value_json["credDefId"]
                    LOGGER.debug("Fetching credential definition %s", cred_def_id)
                    cred_def_entry = await session.handle.fetch(
                        CATEGORY_CRED_DEF, cred_def_id
                    )
            except AskarError as err:
                LOGGER.error(
                    "Failed to retrieve credential definition %s: %s",
                    cred_def_id,
                    str(err),
                )
                raise AnonCredsRevocationError(
                    f"Error retrieving cred def {cred_def_id}"
                ) from err

            try:
                # TODO This is a little rough; stored tails location will have public uri
                # but library needs local tails location
                LOGGER.debug("Deserializing revocation registry data")
                rev_reg_def = RevRegDef.deserialize(rev_reg_def_entry.value_json)
                rev_reg_def.value.tails_location = self.get_local_tails_path(rev_reg_def)
                cred_def = CredDef.deserialize(cred_def_entry.value_json)
                rev_reg_def_private = RevocationRegistryDefinitionPrivate.load(
                    rev_reg_def_private_entry.value_json
                )
            except AnoncredsError as err:
                LOGGER.error(
                    "Failed to load revocation registry definition: %s", str(err)
                )
                raise AnonCredsRevocationError(
                    "Error loading revocation registry definition"
                ) from err

            rev_crids = set()
            failed_crids = set()
            max_cred_num = rev_reg_def.value.max_cred_num
            rev_info = rev_list_entry.value_json
            cred_revoc_ids = (rev_info["pending"] or []) + (additional_crids or [])
            rev_list = RevList.deserialize(rev_info["rev_list"])

            LOGGER.debug(
                "Processing %d credential revocation IDs for registry %s",
                len(cred_revoc_ids),
                revoc_reg_id,
            )

            for rev_id in cred_revoc_ids:
                if rev_id < 1 or rev_id > max_cred_num:
                    LOGGER.error(
                        "Skipping requested credential revocation "
                        "on rev reg id %s, cred rev id=%s not in range (1-%d)",
                        revoc_reg_id,
                        rev_id,
                        max_cred_num,
                    )
                    failed_crids.add(rev_id)
                elif rev_id >= rev_info["next_index"]:
                    LOGGER.warning(
                        "Skipping requested credential revocation "
                        "on rev reg id %s, cred rev id=%s not yet issued (next_index=%d)",
                        revoc_reg_id,
                        rev_id,
                        rev_info["next_index"],
                    )
                    failed_crids.add(rev_id)
                elif rev_list.revocation_list[rev_id] == 1:
                    LOGGER.warning(
                        "Skipping requested credential revocation "
                        "on rev reg id %s, cred rev id=%s already revoked",
                        revoc_reg_id,
                        rev_id,
                    )
                    failed_crids.add(rev_id)
                else:
                    rev_crids.add(rev_id)

            if not rev_crids:
                LOGGER.debug(
                    "No valid credentials to revoke for registry %s", revoc_reg_id
                )
                break

            if limit_crids is None or limit_crids == []:
                skipped_crids = set()
            else:
                skipped_crids = rev_crids - set(limit_crids)
            rev_crids = rev_crids - skipped_crids

            LOGGER.debug(
                "Revoking %d credentials, skipping %d credentials for registry %s",
                len(rev_crids),
                len(skipped_crids),
                revoc_reg_id,
            )

            try:
                LOGGER.debug("Updating revocation list with new revocations")
                updated_list = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: rev_list.to_native().update(
                        cred_def=cred_def.to_native(),
                        rev_reg_def=rev_reg_def.to_native(),
                        rev_reg_def_private=rev_reg_def_private,
                        issued=None,
                        revoked=list(rev_crids),
                        timestamp=int(time.time()),
                    ),
                )
                LOGGER.debug("Successfully updated revocation list")
            except AnoncredsError as err:
                LOGGER.error("Failed to update revocation registry: %s", str(err))
                raise AnonCredsRevocationError(
                    "Error updating revocation registry"
                ) from err

            try:
                async with self.profile.transaction() as txn:
                    LOGGER.debug("Saving updated revocation list")
                    rev_info_upd = await txn.handle.fetch(
                        CATEGORY_REV_LIST, revoc_reg_id, for_update=True
                    )
                    if not rev_info_upd:
                        LOGGER.warning(
                            "Revocation registry %s missing during update, skipping",
                            revoc_reg_id,
                        )
                        updated_list = None
                        break
                    tags = rev_info_upd.tags
                    rev_info_upd = rev_info_upd.value_json
                    if rev_info_upd != rev_info:
                        LOGGER.debug(
                            "Concurrent update detected for registry %s, retrying",
                            revoc_reg_id,
                        )
                        continue
                    rev_info_upd["rev_list"] = updated_list.to_dict()
                    rev_info_upd["pending"] = (
                        list(skipped_crids) if skipped_crids else None
                    )
                    tags["pending"] = "true" if skipped_crids else "false"
                    await txn.handle.replace(
                        CATEGORY_REV_LIST,
                        revoc_reg_id,
                        value_json=rev_info_upd,
                        tags=tags,
                    )
                    await txn.commit()
                    LOGGER.debug(
                        "Successfully updated revocation list for registry %s",
                        revoc_reg_id,
                    )
            except AskarError as err:
                LOGGER.error("Failed to save revocation registry: %s", str(err))
                raise AnonCredsRevocationError(
                    "Error saving revocation registry"
                ) from err
            break

        revoked = list(rev_crids)
        failed = [str(rev_id) for rev_id in sorted(failed_crids)]

        result = RevokeResult(
            prev=rev_list,
            curr=RevList.from_native(updated_list) if updated_list else None,
            revoked=revoked,
            failed=failed,
        )
        LOGGER.debug(
            "Completed revocation process for registry %s: %d revoked, %d failed",
            revoc_reg_id,
            len(revoked),
            len(failed),
        )
        return result

    async def mark_pending_revocations(self, rev_reg_def_id: str, *crids: int) -> None:
        """Cred rev ids stored to publish later."""
        LOGGER.debug(
            "Marking %d credentials as pending revocation for registry %s",
            len(crids),
            rev_reg_def_id,
        )
        async with self.profile.transaction() as txn:
            entry = await txn.handle.fetch(
                CATEGORY_REV_LIST,
                rev_reg_def_id,
                for_update=True,
            )

            if not entry:
                LOGGER.error("Revocation list not found for registry %s", rev_reg_def_id)
                raise AnonCredsRevocationError(
                    "Revocation list with id {rev_reg_def_id} not found"
                )

            pending: Optional[List[int]] = entry.value_json["pending"]
            if pending:
                pending.extend(crids)
                LOGGER.debug("Added %d credentials to existing pending list", len(crids))
            else:
                pending = list(crids)
                LOGGER.debug("Created new pending list with %d credentials", len(crids))

            value = entry.value_json
            value["pending"] = pending
            tags = entry.tags
            tags["pending"] = "true"
            await txn.handle.replace(
                CATEGORY_REV_LIST,
                rev_reg_def_id,
                value_json=value,
                tags=tags,
            )
            await txn.commit()
            LOGGER.debug("Successfully marked credentials as pending revocation")

    async def get_pending_revocations(self, rev_reg_def_id: str) -> List[int]:
        """Retrieve the list of credential revocation ids pending revocation."""
        LOGGER.debug("Getting pending revocations for registry %s", rev_reg_def_id)
        async with self.profile.session() as session:
            entry = await session.handle.fetch(CATEGORY_REV_LIST, rev_reg_def_id)
            if not entry:
                LOGGER.debug("No revocation list found for registry %s", rev_reg_def_id)
                return []

            pending = entry.value_json["pending"] or []
            LOGGER.debug(
                "Found %d pending revocations for registry %s",
                len(pending),
                rev_reg_def_id,
            )
            return pending

    async def clear_pending_revocations(
        self,
        txn: ProfileSession,
        rev_reg_def_id: str,
        crid_mask: Optional[Sequence[int]] = None,
    ) -> None:
        """Clear pending revocations."""
        LOGGER.debug(
            "Clearing pending revocations for registry %s with crid_mask %s",
            rev_reg_def_id,
            crid_mask,
        )
        if not isinstance(txn, AskarAnonCredsProfileSession):
            LOGGER.error("Askar wallet required but got txn type: %s", type(txn))
            raise ValueError("Askar wallet required")

        entry = await txn.handle.fetch(
            CATEGORY_REV_LIST,
            rev_reg_def_id,
            for_update=True,
        )

        if not entry:
            LOGGER.error("Revocation list not found for registry %s", rev_reg_def_id)
            raise AnonCredsRevocationError(
                "Revocation list with id {rev_reg_def_id} not found"
            )

        value = entry.value_json
        if crid_mask is None:
            LOGGER.debug("Clearing all pending revocations")
            value["pending"] = None
        else:
            LOGGER.debug("Clearing %d specific pending revocations", len(crid_mask))
            value["pending"] = set(value["pending"]) - set(crid_mask)

        tags = entry.tags
        tags["pending"] = "false"
        await txn.handle.replace(
            CATEGORY_REV_LIST,
            rev_reg_def_id,
            value_json=value,
            tags=tags,
        )
        LOGGER.debug("Successfully cleared pending revocations")

    async def set_tails_file_public_uri(self, rev_reg_id: str, tails_public_uri: str):
        """Update Revocation Registry tails file public uri."""
        LOGGER.warning(
            "Not implemented: Setting tails file public URI for registry %s to %s",
            rev_reg_id,
            tails_public_uri,
        )
        # TODO: Implement or remove

    async def set_rev_reg_state(self, rev_reg_id: str, state: str) -> RevRegDef:
        """Update Revocation Registry state."""
        try:
            async with self.profile.transaction() as txn:
                # Fetch the revocation registry definition entry
                rev_reg_def_entry = await txn.handle.fetch(
                    CATEGORY_REV_REG_DEF, rev_reg_id, for_update=True
                )

                if not rev_reg_def_entry:
                    raise AnonCredsRevocationError(
                        f"Revocation registry definition not found for id {rev_reg_id}"
                    )

                # Update the state in the tags
                tags = rev_reg_def_entry.tags
                tags["state"] = state

                # Replace the entry with updated tags
                await txn.handle.replace(
                    CATEGORY_REV_REG_DEF,
                    rev_reg_id,
                    value=rev_reg_def_entry.value,
                    tags=tags,
                )

                await txn.commit()
        except AskarError as err:
            raise AnonCredsRevocationError(
                f"Error updating revocation registry state: {err}"
            ) from err

        LOGGER.debug("Set registry %s state: %s", rev_reg_id, state)
        return RevRegDef.deserialize(rev_reg_def_entry.value_json)

    def _generate_backup_registry_tag(self) -> str:
        """Generate a unique tag for a backup registry."""
        return str(uuid4())
