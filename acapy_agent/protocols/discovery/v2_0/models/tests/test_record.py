from unittest import IsolatedAsyncioTestCase

from ......storage.error import StorageDuplicateError, StorageNotFoundError
from ......tests import mock
from ......utils.testing import create_test_profile
from .....didcomm_prefix import DIDCommPrefix
from ...messages.disclosures import Disclosures
from ...messages.queries import Queries, QueryItem
from ..discovery_record import V20DiscoveryExchangeRecord


class TestV20DiscoveryExchangeRecord(IsolatedAsyncioTestCase):
    """Test de/serialization."""

    async def test_record(self):
        same = [
            V20DiscoveryExchangeRecord(
                discovery_exchange_id="3fa85f64-5717-4562-b3fc-2c963f66afa6",
                queries_msg=Queries(
                    queries=[
                        QueryItem(feature_type="protocol", match="*"),
                        QueryItem(feature_type="goal-code", match="test"),
                    ]
                ),
                disclosures=Disclosures(
                    disclosures=[
                        {
                            "id": DIDCommPrefix.qualify_current(
                                "basicmessage/1.0/message"
                            ),
                            "feature-type": "protocol",
                            "roles": [],
                        }
                    ]
                ),
            )
        ] * 2
        diff = [
            V20DiscoveryExchangeRecord(
                discovery_exchange_id="3fa85f64-5717-4562-b3fc-2c963f66afa6",
                queries_msg=Queries(
                    queries=[
                        QueryItem(feature_type="protocol", match="test1.*"),
                        QueryItem(feature_type="goal-code", match="test1"),
                    ]
                ),
                disclosures=Disclosures(
                    disclosures=[
                        {
                            "id": DIDCommPrefix.qualify_current(
                                "basicmessage/1.0/message"
                            ),
                            "feature-type": "protocol",
                            "roles": [],
                        }
                    ]
                ),
            ),
            V20DiscoveryExchangeRecord(
                discovery_exchange_id="3fa85f64-5717-4562-b3fc-2c963f66afa6",
                queries_msg=Queries(
                    queries=[
                        QueryItem(feature_type="protocol", match="test2.*"),
                        QueryItem(feature_type="goal-code", match="test2"),
                    ]
                ),
            ),
        ]

        for i in range(len(same) - 1):
            for j in range(i, len(same)):
                assert same[i] == same[j]

        for i in range(len(diff) - 1):
            for j in range(i, len(diff)):
                assert diff[i] == diff[j] if i == j else diff[i] != diff[j]

    async def test_serde(self):
        """Test de/serialization."""
        queries = Queries(
            queries=[
                QueryItem(feature_type="protocol", match="*"),
                QueryItem(feature_type="goal-code", match="test"),
            ]
        )
        disclosures = Disclosures(
            disclosures=[
                {
                    "id": DIDCommPrefix.qualify_current("basicmessage/1.0/message"),
                    "feature-type": "protocol",
                    "roles": [],
                }
            ]
        )
        ex_rec = V20DiscoveryExchangeRecord(
            discovery_exchange_id="3fa85f64-5717-4562-b3fc-2c963f66afa6",
            disclosures=disclosures,
        )
        ex_rec.queries_msg = queries
        assert isinstance(ex_rec.queries_msg, Queries)
        ser = ex_rec.serialize()
        deser = V20DiscoveryExchangeRecord.deserialize(ser)
        assert isinstance(deser.queries_msg, Queries)

        assert isinstance(ex_rec.disclosures, Disclosures)
        ser = ex_rec.serialize()
        deser = V20DiscoveryExchangeRecord.deserialize(ser)
        assert isinstance(deser.disclosures, Disclosures)

    async def test_retrieve_by_conn_id(self):
        self.profile = await create_test_profile()
        async with self.profile.session() as session:
            record = V20DiscoveryExchangeRecord(
                queries_msg=Queries(
                    queries=[
                        QueryItem(feature_type="protocol", match="*"),
                        QueryItem(feature_type="goal-code", match="test"),
                    ],
                ),
                connection_id="test123",
            )
            await record.save(session)
            retrieved = await V20DiscoveryExchangeRecord.retrieve_by_connection_id(
                session=session, connection_id="test123"
            )
            assert retrieved
            assert retrieved.connection_id == "test123"

    async def test_exists_for_connection_id(self):
        self.profile = await create_test_profile()
        async with self.profile.session() as session:
            record = V20DiscoveryExchangeRecord(
                queries_msg=Queries(
                    queries=[
                        QueryItem(feature_type="protocol", match="*"),
                        QueryItem(feature_type="goal-code", match="test"),
                    ],
                ),
                connection_id="test123",
            )
            await record.save(session)
            check = await V20DiscoveryExchangeRecord.exists_for_connection_id(
                session=session, connection_id="test123"
            )
            assert check

    async def test_exists_for_connection_id_not_found(self):
        self.profile = await create_test_profile()
        async with self.profile.session() as session:
            with mock.patch.object(
                V20DiscoveryExchangeRecord,
                "retrieve_by_tag_filter",
                mock.CoroutineMock(),
            ) as mock_retrieve_by_tag_filter:
                mock_retrieve_by_tag_filter.side_effect = StorageNotFoundError
                check = await V20DiscoveryExchangeRecord.exists_for_connection_id(
                    session=session, connection_id="test123"
                )
                assert not check

    async def test_exists_for_connection_id_duplicate(self):
        self.profile = await create_test_profile()
        async with self.profile.session() as session:
            with mock.patch.object(
                V20DiscoveryExchangeRecord,
                "retrieve_by_tag_filter",
                mock.CoroutineMock(),
            ) as mock_retrieve_by_tag_filter:
                mock_retrieve_by_tag_filter.side_effect = StorageDuplicateError
                check = await V20DiscoveryExchangeRecord.exists_for_connection_id(
                    session=session, connection_id="test123"
                )
                assert check
