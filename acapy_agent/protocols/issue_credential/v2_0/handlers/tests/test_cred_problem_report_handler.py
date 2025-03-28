from unittest import IsolatedAsyncioTestCase

from ......messaging.request_context import RequestContext
from ......messaging.responder import MockResponder
from ......tests import mock
from ......transport.inbound.receipt import MessageReceipt
from ......utils.testing import create_test_profile
from ...messages.cred_problem_report import ProblemReportReason, V20CredProblemReport
from .. import cred_problem_report_handler as test_module


class TestCredProblemReportHandler(IsolatedAsyncioTestCase):
    async def test_called(self):
        request_context = RequestContext.test_context(await create_test_profile())
        request_context.message_receipt = MessageReceipt()
        request_context.connection_record = mock.MagicMock()

        with mock.patch.object(
            test_module, "V20CredManager", autospec=True
        ) as mock_cred_mgr:
            mock_cred_mgr.return_value.receive_problem_report = mock.CoroutineMock()
            request_context.connection_ready = True
            request_context.message = V20CredProblemReport(
                description={
                    "en": "oh no",
                    "code": ProblemReportReason.ISSUANCE_ABANDONED.value,
                }
            )
            handler = test_module.CredProblemReportHandler()
            responder = MockResponder()
            await handler.handle(request_context, responder)

        mock_cred_mgr.assert_called_once_with(request_context.profile)
        mock_cred_mgr.return_value.receive_problem_report.assert_called_once_with(
            request_context.message, request_context.connection_record.connection_id
        )
        assert not responder.messages

    async def test_called_x(self):
        request_context = RequestContext.test_context(await create_test_profile())
        request_context.message_receipt = MessageReceipt()
        request_context.connection_record = mock.MagicMock()

        with mock.patch.object(
            test_module, "V20CredManager", autospec=True
        ) as mock_cred_mgr:
            request_context.connection_ready = True
            mock_cred_mgr.return_value.receive_problem_report = mock.CoroutineMock(
                side_effect=test_module.StorageError("Disk full")
            )
            request_context.message = V20CredProblemReport(
                description={
                    "en": "oh no",
                    "code": ProblemReportReason.ISSUANCE_ABANDONED.value,
                }
            )
            handler = test_module.CredProblemReportHandler()
            responder = MockResponder()
            await handler.handle(request_context, responder)

        mock_cred_mgr.assert_called_once_with(request_context.profile)
        mock_cred_mgr.return_value.receive_problem_report.assert_called_once_with(
            request_context.message, request_context.connection_record.connection_id
        )
        assert not responder.messages

    async def test_called_not_ready(self):
        request_context = RequestContext.test_context(await create_test_profile())
        request_context.message_receipt = MessageReceipt()
        request_context.connection_record = mock.MagicMock()
        request_context.connection_ready = False

        request_context.message = V20CredProblemReport(
            description={
                "en": "Change of plans",
                "code": ProblemReportReason.ISSUANCE_ABANDONED.value,
            }
        )
        handler = test_module.CredProblemReportHandler()
        responder = MockResponder()

        with self.assertRaises(test_module.HandlerException) as err:
            await handler.handle(request_context, responder)
        assert (
            err.exception.message
            == "Connection used for credential problem report not ready"
        )

    async def test_called_no_connection(self):
        request_context = RequestContext.test_context(await create_test_profile())
        request_context.message_receipt = MessageReceipt()
        request_context.connection_record = None

        request_context.message = V20CredProblemReport(
            description={
                "en": "Change of plans",
                "code": ProblemReportReason.ISSUANCE_ABANDONED.value,
            }
        )
        handler = test_module.CredProblemReportHandler()
        responder = MockResponder()

        with self.assertRaises(test_module.HandlerException) as err:
            await handler.handle(request_context, responder)
        assert (
            err.exception.message
            == "Connectionless not supported for credential problem report"
        )

        assert not responder.messages
