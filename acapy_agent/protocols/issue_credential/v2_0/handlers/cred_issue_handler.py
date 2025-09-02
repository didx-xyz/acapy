"""Credential issue message handler."""

import asyncio

from acapy_agent.protocols.issue_credential.v2_0.models.cred_ex_record import (
    V20CredExRecord,
)

from .....anoncreds.holder import AnonCredsHolderError
from .....core.oob_processor import OobMessageProcessor
from .....indy.holder import IndyHolderError
from .....messaging.base_handler import BaseHandler, HandlerException
from .....messaging.models.base import BaseModelError
from .....messaging.request_context import RequestContext
from .....messaging.responder import BaseResponder
from .....storage.error import StorageError
from .....utils.tracing import get_timer, trace_event
from .. import problem_report_for_record
from ..manager import V20CredManager, V20CredManagerError
from ..messages.cred_issue import V20CredIssue
from ..messages.cred_problem_report import ProblemReportReason


class V20CredIssueHandler(BaseHandler):
    """Message handler class for credential offers."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """Message handler logic for credential offers.

        Args:
            context: request context
            responder: responder callback

        """
        r_time = get_timer()

        self._logger.debug("V20CredIssueHandler called with context %s", context)
        assert isinstance(context.message, V20CredIssue)
        self._logger.debug(
            "Received v2.0 credential issue message: %s",
            context.message.serialize(as_string=True),
        )

        # If connection is present it must be ready for use
        if context.connection_record and not context.connection_ready:
            raise HandlerException("Connection used for credential not ready")

        # Find associated oob record
        oob_processor = context.inject(OobMessageProcessor)
        oob_record = await oob_processor.find_oob_record_for_inbound_message(context)

        # Either connection or oob context must be present
        if not context.connection_record and not oob_record:
            raise HandlerException(
                "No connection or associated connectionless exchange found for credential"
            )

        connection_id = (
            context.connection_record.connection_id if context.connection_record else None
        )
        cred_manager = V20CredManager(context.profile)

        cred_ex_record = await cred_manager.receive_credential(
            context.message, connection_id
        )  # mgr only finds, saves record: on exception, saving null state is hopeless

        r_time = trace_event(
            context.settings,
            context.message,
            outcome="V20CredIssueHandler.handle.END",
            perf_counter=r_time,
        )

        # Automatically move to next state if flag is set
        if context.settings.get("debug.auto_store_credential"):
            max_retries = 5
            retry_count = 0
            should_retry = True
            state = V20CredExRecord.STATE_DONE

            while retry_count < max_retries:
                try:
                    cred_ex_record = await cred_manager.store_credential(cred_ex_record)
                    break  # Exit loop if successful
                except (
                    BaseModelError,
                    AnonCredsHolderError,
                    IndyHolderError,
                    StorageError,
                    V20CredManagerError,
                ) as err:
                    retry_count += 1
                    self._logger.exception(
                        f"Error storing issued credential, attempt {retry_count}"
                    )
                    if "Issuer is sending incorrect data" in str(err):
                        should_retry = False

                    if should_retry and retry_count < max_retries:
                        await asyncio.sleep(1)  # Wait before retrying
                    else:
                        async with context.profile.session() as session:
                            state = V20CredExRecord.STATE_ABANDONED
                            await cred_ex_record.save_error_state(
                                session,
                                state=state,
                                reason=err.roll_up,  # us: be specific
                            )
                        abandoned_code = ProblemReportReason.ISSUANCE_ABANDONED.value
                        await responder.send_reply(  # them: vague
                            problem_report_for_record(cred_ex_record, abandoned_code)
                        )
                        break

            cred_ack_message = await cred_manager.send_cred_ack(
                cred_ex_record, state=state
            )

            trace_event(
                context.settings,
                cred_ack_message,
                outcome="V20CredIssueHandler.handle.STORE",
                perf_counter=r_time,
            )
