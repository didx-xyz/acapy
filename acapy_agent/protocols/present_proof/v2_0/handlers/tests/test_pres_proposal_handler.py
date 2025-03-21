from unittest import IsolatedAsyncioTestCase

from ......messaging.request_context import RequestContext
from ......messaging.responder import MockResponder
from ......tests import mock
from ......transport.inbound.receipt import MessageReceipt
from ......utils.testing import create_test_profile
from ...messages.pres_proposal import V20PresProposal
from .. import pres_proposal_handler as test_module


class TestV20PresProposalHandler(IsolatedAsyncioTestCase):
    async def test_called(self):
        request_context = RequestContext.test_context(await create_test_profile())
        request_context.connection_record = mock.MagicMock()
        request_context.message_receipt = MessageReceipt()
        request_context.settings["debug.auto_respond_presentation_proposal"] = False

        with mock.patch.object(
            test_module, "V20PresManager", autospec=True
        ) as mock_pres_mgr:
            mock_pres_mgr.return_value.receive_pres_proposal = mock.CoroutineMock(
                return_value=mock.MagicMock()
            )
            request_context.message = V20PresProposal()
            request_context.connection_ready = True
            request_context.connection_record = mock.MagicMock()
            handler = test_module.V20PresProposalHandler()
            responder = MockResponder()
            await handler.handle(request_context, responder)

        mock_pres_mgr.assert_called_once_with(request_context.profile)
        mock_pres_mgr.return_value.receive_pres_proposal.assert_called_once_with(
            request_context.message, request_context.connection_record
        )
        assert not responder.messages

    async def test_called_auto_request(self):
        request_context = RequestContext.test_context(await create_test_profile())
        request_context.message = mock.MagicMock()
        request_context.connection_record = mock.MagicMock()
        request_context.message.comment = "hello world"
        request_context.message_receipt = MessageReceipt()
        request_context.settings["debug.auto_respond_presentation_proposal"] = True

        with mock.patch.object(
            test_module, "V20PresManager", autospec=True
        ) as mock_pres_mgr:
            mock_pres_mgr.return_value.receive_pres_proposal = mock.CoroutineMock(
                return_value="presentation_exchange_record"
            )
            mock_pres_mgr.return_value.create_bound_request = mock.CoroutineMock(
                return_value=(
                    mock_pres_mgr.return_value.receive_pres_proposal.return_value,
                    "presentation_request_message",
                )
            )
            request_context.message = V20PresProposal()
            request_context.connection_ready = True
            handler = test_module.V20PresProposalHandler()
            responder = MockResponder()
            await handler.handle(request_context, responder)

        mock_pres_mgr.assert_called_once_with(request_context.profile)
        mock_pres_mgr.return_value.create_bound_request.assert_called_once_with(
            pres_ex_record=(
                mock_pres_mgr.return_value.receive_pres_proposal.return_value
            ),
            comment=request_context.message.comment,
        )
        messages = responder.messages
        assert len(messages) == 1
        (result, target) = messages[0]
        assert result == "presentation_request_message"
        assert target == {}

    async def test_called_auto_request_x(self):
        request_context = RequestContext.test_context(await create_test_profile())
        request_context.connection_record = mock.MagicMock()
        request_context.message = mock.MagicMock()
        request_context.message.comment = "hello world"
        request_context.message_receipt = MessageReceipt()
        request_context.settings["debug.auto_respond_presentation_proposal"] = True

        with mock.patch.object(
            test_module, "V20PresManager", autospec=True
        ) as mock_pres_mgr:
            mock_pres_mgr.return_value.receive_pres_proposal = mock.CoroutineMock(
                return_value=mock.MagicMock(save_error_state=mock.CoroutineMock())
            )
            mock_pres_mgr.return_value.create_bound_request = mock.CoroutineMock(
                side_effect=test_module.LedgerError()
            )

            request_context.message = V20PresProposal()
            request_context.connection_ready = True
            handler = test_module.V20PresProposalHandler()
            responder = MockResponder()

            with mock.patch.object(
                handler._logger, "exception", mock.MagicMock()
            ) as mock_log_exc:
                await handler.handle(request_context, responder)
                mock_log_exc.assert_called_once()

    async def test_called_not_ready(self):
        request_context = RequestContext.test_context(await create_test_profile())
        request_context.message_receipt = MessageReceipt()
        request_context.connection_record = mock.MagicMock()

        with mock.patch.object(
            test_module, "V20PresManager", autospec=True
        ) as mock_pres_mgr:
            mock_pres_mgr.return_value.receive_pres_proposal = mock.CoroutineMock()
            request_context.message = V20PresProposal()
            request_context.connection_ready = False
            handler = test_module.V20PresProposalHandler()
            responder = MockResponder()
            with self.assertRaises(test_module.HandlerException) as err:
                await handler.handle(request_context, responder)
            assert (
                err.exception.message
                == "Connection used for presentation proposal not ready"
            )

        assert not responder.messages

    async def test_called_no_connection(self):
        request_context = RequestContext.test_context(await create_test_profile())
        request_context.message_receipt = MessageReceipt()

        request_context.message = V20PresProposal()
        handler = test_module.V20PresProposalHandler()
        responder = MockResponder()
        with self.assertRaises(test_module.HandlerException) as err:
            await handler.handle(request_context, responder)
        assert (
            err.exception.message
            == "Connectionless not supported for presentation proposal"
        )

        assert not responder.messages
