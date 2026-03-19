from unittest.mock import Mock, patch, call

import pytest
from keri import kering
from keri.kering import ConfigurationError

from kept.core.authentication import (
    CryptSigner,
    scan_for_delegates,
    process_delegator_event_seals,
    CHUNK_SIZE,
)
from kept.db import basing


class TestCryptSigner:

    @pytest.fixture
    def mock_hby(self):
        """Mock Habery object"""
        hby = Mock()
        hby.name = "test_habery"
        hby.temp = False
        hby.habs = {}
        hby.kevers = {}
        hby.db = Mock()
        hby.db.clonePreIter = Mock()
        hby.db.setAes = Mock()
        hby.habByName = Mock(return_value=None)
        hby.makeHab = Mock()
        return hby

    @pytest.fixture
    def mock_hab(self):
        """Mock Hab object"""
        hab = Mock()
        hab.name = "test_hab"
        hab.pre = "EABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        hab.kever = Mock()
        hab.kever.serder = Mock()
        hab.kever.serder.sn = 1
        hab.kever.serder.saidb = b"test_said"
        hab.interact = Mock()
        hab.endorse = Mock()
        hab.psr = Mock()
        hab.psr.parseOne = Mock()
        hab.db = Mock()
        hab.db.essrs = Mock()
        hab.db.essrs.rem = Mock()
        hab.db.epath = Mock()
        hab.db.epath.rem = Mock()
        return hab

    @pytest.fixture
    def mock_rt(self):
        """Mock RouteTable object"""
        rt = Mock(spec=basing.RouteTable)
        rt.dlgs = Mock()
        rt.dlgs.add = Mock()
        rt.dlgs.get = Mock(return_value=[])
        rt.dlgs.rem = Mock()
        rt.cur = Mock()
        rt.cur.get = Mock(return_value=None)
        rt.cur.pin = Mock()
        rt.encs = Mock()
        rt.encs.add = Mock()
        return rt

    @pytest.fixture
    def crypt_signer(self, mock_hby, mock_hab, mock_rt):
        """Create CryptSigner instance with mocked dependencies"""
        return CryptSigner(
            hby=mock_hby, hab=mock_hab, rt=mock_rt, encryption_target="test_target"
        )

    def test_init_with_rt(self, mock_hby, mock_hab, mock_rt):
        """Test CryptSigner initialization with provided RouteTable"""
        signer = CryptSigner(
            hby=mock_hby, hab=mock_hab, rt=mock_rt, encryption_target="test_target"
        )

        assert signer.hby == mock_hby
        assert signer._hab == mock_hab
        assert signer.rt == mock_rt
        assert signer.encryption_target == "test_target"
        assert signer.scan == set()

    def test_init_without_rt(self, mock_hby, mock_hab):
        """Test CryptSigner initialization without RouteTable (creates new one)"""
        with patch("kept.db.basing.RouteTable") as mock_route_table:
            mock_rt_instance = Mock()
            mock_route_table.return_value = mock_rt_instance

            signer = CryptSigner(
                hby=mock_hby, hab=mock_hab, encryption_target="test_target"
            )

            assert signer.hby == mock_hby
            assert signer._hab == mock_hab
            assert signer.rt == mock_rt_instance
            assert signer.encryption_target == "test_target"
            mock_route_table.assert_called_once_with(
                name="test_habery", reopen=True, temp=False
            )

    def test_pre_property(self, crypt_signer, mock_hab):
        """Test pre property returns hab's pre"""
        assert crypt_signer.pre == mock_hab.pre

    def test_make_randy_algo_success(self, crypt_signer, mock_hby, mock_hab, mock_rt):
        """Test make method with randy algorithm"""
        # Setup mock hab values
        mock_hby.habs = {"existing_hab": Mock()}
        mock_hab.name = "delegator"

        # Setup mock delegate habs
        mock_delegate_habs = []
        for i in range(3):
            delegate_hab = Mock()
            delegate_hab.pre = f"delegate_{i}_pre"
            mock_delegate_habs.append(delegate_hab)

        mock_hby.makeHab.side_effect = mock_delegate_habs

        # Mock seqner and couple for anchoring
        with patch("keri.core.coring.Seqner") as mock_seqner_class:
            mock_seqner = Mock()
            mock_seqner.qb64b = b"seq_bytes"
            mock_seqner_class.return_value = mock_seqner

            with patch("keri.db.dbing.dgKey", return_value="dgkey"):
                delegates = crypt_signer.make(
                    count=3, algo="randy", icount=2, isith="2"
                )

        assert len(delegates) == 3
        assert delegates == mock_delegate_habs

        # Verify makeHab calls
        expected_calls = []
        for i in range(3):
            expected_calls.append(
                call(
                    name=f"delegator-{i+1}",
                    algo="randy",
                    salt=None,
                    icount=2,
                    isith=2,
                    ncount=1,
                    nsith=1,
                    delpre=mock_hab.pre,
                    estOnly=False,
                )
            )
        mock_hby.makeHab.assert_has_calls(expected_calls)

        # Verify interaction call with anchors
        expected_anchors = []
        for i in range(3):
            expected_anchors.append(
                {"i": f"delegate_{i}_pre", "s": "0", "d": f"delegate_{i}_pre"}
            )
        mock_hab.interact.assert_called_once_with(data=expected_anchors)

        # Verify delegates added to route table
        for i in range(3):
            mock_rt.dlgs.add.assert_any_call(
                keys=(mock_hab.pre,), val=f"delegate_{i}_pre"
            )

    def test_make_salty_algo_success(self, crypt_signer, mock_hby, mock_hab):
        """Test make method with salty algorithm"""
        mock_hby.habs = {}
        mock_hab.name = "delegator"

        mock_delegate_hab = Mock()
        mock_delegate_hab.pre = "delegate_pre"
        mock_hby.makeHab.return_value = mock_delegate_hab

        with patch("keri.core.coring.Seqner") as mock_seqner_class:
            mock_seqner = Mock()
            mock_seqner.qb64b = b"seq_bytes"
            mock_seqner_class.return_value = mock_seqner

            with patch("keri.db.dbing.dgKey", return_value="dgkey"):
                delegates = crypt_signer.make(
                    count=1,
                    algo="salty",
                    salt="123456789012345678901234",
                    icount=1,
                    isith="1",
                )

        assert len(delegates) == 1
        mock_hby.makeHab.assert_called_once_with(
            name="delegator-0",
            algo="salty",
            salt="123456789012345678901234",
            icount=1,
            isith=1,
            ncount=1,
            nsith=1,
            delpre=mock_hab.pre,
            estOnly=False,
        )

    def test_make_salty_invalid_salt(self, crypt_signer):
        """Test make method with salty algorithm and invalid salt"""
        with pytest.raises(
            ValueError, match="Salt is required and must be 24 characters long"
        ):
            crypt_signer.make(algo="salty", salt="short_salt")

        with pytest.raises(
            ValueError, match="Salt is required and must be 24 characters long"
        ):
            crypt_signer.make(algo="salty", salt=None)

    def test_make_alias_already_exists(self, crypt_signer, mock_hby, mock_hab):
        """Test make method when alias already exists"""
        mock_hby.habs = {}
        mock_hab.name = "delegator"
        mock_hby.habByName.return_value = Mock()  # Simulate existing hab

        with pytest.raises(ValueError, match="delegator-0 is already in use"):
            crypt_signer.make(count=1)

    def test_delegates(self, crypt_signer, mock_rt):
        """Test delegates method"""
        test_aid = "test_aid"
        expected_delegates = ["delegate1", "delegate2"]
        mock_rt.dlgs.get.return_value = expected_delegates

        result = crypt_signer.delegates(test_aid)

        assert result == expected_delegates
        mock_rt.dlgs.get.assert_called_once_with(keys=(test_aid,))

    def test_scan_for_delegates_not_scanned(self, crypt_signer):
        """Test scan_for_delegates when aid not yet scanned"""
        test_aid = "test_aid"

        with patch("kept.core.authentication.scan_for_delegates") as mock_scan:
            crypt_signer.scan_for_delegates(test_aid)

            mock_scan.assert_called_once_with(
                crypt_signer.hby, crypt_signer.rt, test_aid
            )
            assert test_aid in crypt_signer.scan

    def test_scan_for_delegates_already_scanned(self, crypt_signer):
        """Test scan_for_delegates when aid already scanned"""
        test_aid = "test_aid"
        crypt_signer.scan.add(test_aid)

        with patch("kept.core.authentication.scan_for_delegates") as mock_scan:
            crypt_signer.scan_for_delegates(test_aid)

            mock_scan.assert_not_called()

    def test_hab_with_current_delegate(self, crypt_signer, mock_rt, mock_hby):
        """Test hab method with current delegate assigned"""
        test_aid = "test_aid"
        delegate_id = "delegate_id"
        mock_delegate_hab = Mock()

        mock_rt.cur.get.return_value = delegate_id
        mock_hby.habs = {delegate_id: mock_delegate_hab}

        result = crypt_signer.hab(test_aid)

        assert result == mock_delegate_hab
        mock_rt.cur.get.assert_called_once_with(keys=(test_aid,))

    def test_hab_assign_first_delegate(self, crypt_signer, mock_rt, mock_hby):
        """Test hab method assigns first delegate when no current delegate"""
        test_aid = "test_aid"
        delegate_id = "delegate_id"
        mock_delegate_hab = Mock()

        mock_rt.cur.get.return_value = None
        mock_rt.dlgs.get.return_value = [delegate_id, "delegate2"]
        mock_hby.habs = {delegate_id: mock_delegate_hab}

        result = crypt_signer.hab(test_aid)

        assert result == mock_delegate_hab
        mock_rt.cur.pin.assert_called_once_with(keys=(test_aid,), val=delegate_id)

    def test_hab_fallback_to_aid(self, crypt_signer, mock_rt, mock_hby):
        """Test hab method falls back to aid when no delegates"""
        test_aid = "test_aid"
        mock_hab = Mock()

        mock_rt.cur.get.return_value = None
        mock_rt.dlgs.get.return_value = []
        mock_hby.habs = {test_aid: mock_hab}

        result = crypt_signer.hab(test_aid)

        assert result == mock_hab

    def test_hab_configuration_error(self, crypt_signer, mock_rt, mock_hby):
        """Test hab method raises ConfigurationError when no hab found"""
        test_aid = "test_aid"

        mock_rt.cur.get.return_value = None
        mock_rt.dlgs.get.return_value = []
        mock_hby.habs = {}

        with pytest.raises(
            kering.ConfigurationError, match=f"Unable to find Hab for {test_aid}"
        ):
            crypt_signer.hab(test_aid)

    def test_kever_with_delegates(self, crypt_signer, mock_rt, mock_hby):
        """Test kever method with delegates available"""
        test_aid = "test_aid"
        delegate_id = "delegate_id"
        mock_kever = Mock()

        mock_rt.dlgs.get.return_value = [delegate_id]
        mock_hby.kevers = {delegate_id: mock_kever}

        with patch("random.choice", return_value=delegate_id):
            result = crypt_signer.kever(test_aid)

        assert result == mock_kever

    def test_kever_with_delegates_not_found(self, crypt_signer, mock_rt, mock_hby):
        """Test kever method with delegates but kever not found"""
        test_aid = "test_aid"
        delegate_id = "delegate_id"

        mock_rt.dlgs.get.return_value = [delegate_id]
        mock_hby.kevers = {}

        with patch("random.choice", return_value=delegate_id):
            with pytest.raises(
                kering.ConfigurationError, match=f"Unable to find kever for {test_aid}"
            ):
                crypt_signer.kever(test_aid)

    def test_kever_fallback_to_aid(self, crypt_signer, mock_rt, mock_hby):
        """Test kever method falls back to aid when no delegates"""
        test_aid = "test_aid"
        mock_kever = Mock()

        mock_rt.dlgs.get.return_value = []
        mock_hby.kevers = {test_aid: mock_kever}

        result = crypt_signer.kever(test_aid)

        assert result == mock_kever

    def test_kever_configuration_error(self, crypt_signer, mock_rt, mock_hby):
        """Test kever method raises ConfigurationError when no kever found"""
        test_aid = "test_aid"

        mock_rt.dlgs.get.return_value = []
        mock_hby.kevers = {}

        with pytest.raises(
            kering.ConfigurationError, match=f"Unable to find kever for {test_aid}"
        ):
            crypt_signer.kever(test_aid)

    @patch("pysodium.crypto_sign_pk_to_box_pk")
    @patch("pysodium.crypto_box_seal")
    @patch("cbor.dumps")
    @patch("keri.core.coring.Diger")
    @patch("keri.peer.exchanging.exchange")
    @patch("keri.help.helping.nowIso8601")
    @patch("keri.core.Counter")
    @patch("keri.core.coring.Matter")
    def test_encode_success(
        self,
        mock_matter,
        mock_counter,
        mock_now,
        mock_exchange,
        mock_diger,
        mock_cbor_dumps,
        mock_crypto_box_seal,
        mock_crypto_sign_pk_to_box_pk,
        crypt_signer,
        mock_hab,
        mock_rt,
    ):
        """Test encode method successful execution"""
        # Setup test data
        path = "test/path"
        payload = {"data": "test_payload"}
        target = "test_target"
        said = "test_said"

        # Setup mocks
        mock_hab_instance = Mock()
        mock_hab_instance.pre = "hab_pre"
        mock_hab_instance.endorse.return_value = bytearray(b"endorsed_bytes")
        mock_hab_instance.psr.parseOne = Mock()
        mock_hab_instance.db.essrs.rem = Mock()
        mock_hab_instance.db.epath.rem = Mock()
        mock_hab_instance.kever.serder.said = "hab_said"

        # Setup kever mock
        mock_kever = Mock()
        mock_verfer = Mock()
        mock_verfer.raw = b"verfer_raw_bytes"
        mock_kever.verfers = [mock_verfer]
        mock_kever.prefixer.qb64 = "kever_pre"

        # Configure CryptSigner methods
        crypt_signer.hab = Mock(return_value=mock_hab_instance)
        crypt_signer.kever = Mock(return_value=mock_kever)

        # Setup crypto mocks
        mock_crypto_sign_pk_to_box_pk.return_value = b"public_key"
        mock_crypto_box_seal.return_value = (
            b"sealed_data" * 1000
        )  # Make it large enough to test chunking
        mock_cbor_dumps.return_value = b"cbor_data"

        # Setup other mocks
        mock_diger_instance = Mock()
        mock_diger.return_value = mock_diger_instance
        mock_now.return_value = "2023-01-01T00:00:00Z"

        mock_exn = Mock()
        mock_exn.said = "exn_said"
        mock_exchange.return_value = (mock_exn, None)

        mock_counter_instance = Mock()
        mock_counter_instance.qb64b = b"counter_bytes"
        mock_counter.return_value = mock_counter_instance

        mock_texter = Mock()
        mock_texter.qb64b = b"texter_bytes"
        mock_matter.return_value = mock_texter

        # Execute
        result = crypt_signer.encode(path, payload, target, said)

        # Verify payload modification
        expected_payload = {"i": "hab_pre", "data": "test_payload"}
        mock_cbor_dumps.assert_called_once_with(expected_payload)

        # Verify crypto operations
        mock_crypto_sign_pk_to_box_pk.assert_called_once_with(b"verfer_raw_bytes")
        mock_crypto_box_seal.assert_called_once_with(b"cbor_data", b"public_key")

        # Verify exchange call
        mock_exchange.assert_called_once_with(
            route=path,
            diger=mock_diger_instance,
            sender="hab_pre",
            recipient="kever_pre",
            date="2023-01-01T00:00:00Z",
            dig=said,
        )

        # Verify result is bytes
        assert isinstance(result, bytearray)

    def test_encode_no_encryption_target(self, crypt_signer):
        """Test encode method with no encryption target"""
        crypt_signer.hab = Mock(return_value=Mock(pre="test_pre"))
        crypt_signer.encryption_target = None

        with pytest.raises(
            ConfigurationError, match="Unable to determine encryption target"
        ):
            crypt_signer.encode("path", {"data": "test"})

    def test_encode_no_kever_found(self, crypt_signer):
        """Test encode method when kever not found"""
        crypt_signer.kever = Mock(return_value=None)
        crypt_signer.hab = Mock(return_value=Mock(pre="test_pre"))

        with pytest.raises(
            ConfigurationError, match="Unable to find kever for encryption target"
        ):
            crypt_signer.encode("path", {"data": "test"})

    def test_rotate_signer_no_delegates(self, crypt_signer, mock_rt):
        """Test rotate_signer with no delegates"""
        test_aid = "test_aid"
        mock_rt.dlgs.get.return_value = []

        with pytest.raises(
            kering.ConfigurationError, match=f"No delegates assigned for {test_aid}"
        ):
            crypt_signer.rotate_signer(test_aid)

    def test_rotate_signer_no_current_delegate(self, crypt_signer, mock_rt, mock_hby):
        """Test rotate_signer with no current delegate assigned"""
        test_aid = "test_aid"
        delegates = ["delegate1", "delegate2"]
        mock_delegate_hab = Mock()

        mock_rt.dlgs.get.return_value = delegates
        mock_rt.cur.get.return_value = None
        mock_hby.habs = {"delegate1": mock_delegate_hab}

        crypt_signer.rotate_signer(test_aid)

        mock_rt.cur.pin.assert_called_once_with(keys=(test_aid,), val="delegate1")

    def test_rotate_signer_rotate_to_next(self, crypt_signer, mock_rt, mock_hby):
        """Test rotate_signer rotates to next delegate"""
        test_aid = "test_aid"
        delegates = ["delegate1", "delegate2", "delegate3"]
        current_delegate = "delegate2"
        mock_delegate_hab = Mock()

        mock_rt.dlgs.get.return_value = delegates
        mock_rt.cur.get.return_value = current_delegate
        mock_hby.habs = {"delegate3": mock_delegate_hab}

        crypt_signer.rotate_signer(test_aid)

        mock_rt.cur.pin.assert_called_once_with(keys=(test_aid,), val="delegate3")

    def test_rotate_signer_wrap_around(self, crypt_signer, mock_rt, mock_hby):
        """Test rotate_signer wraps around to first delegate"""
        test_aid = "test_aid"
        delegates = ["delegate1", "delegate2", "delegate3"]
        current_delegate = "delegate3"  # Last delegate
        mock_delegate_hab = Mock()

        mock_rt.dlgs.get.return_value = delegates
        mock_rt.cur.get.return_value = current_delegate
        mock_hby.habs = {"delegate1": mock_delegate_hab}

        crypt_signer.rotate_signer(test_aid)

        mock_rt.cur.pin.assert_called_once_with(keys=(test_aid,), val="delegate1")

    def test_rotate_signer_current_not_in_delegates(
        self, crypt_signer, mock_rt, mock_hby
    ):
        """Test rotate_signer when current delegate not in delegates list"""
        test_aid = "test_aid"
        delegates = ["delegate1", "delegate2"]
        current_delegate = "old_delegate"  # Not in current delegates
        mock_delegate_hab = Mock()

        mock_rt.dlgs.get.return_value = delegates
        mock_rt.cur.get.return_value = current_delegate
        mock_hby.habs = {"delegate1": mock_delegate_hab}

        crypt_signer.rotate_signer(test_aid)

        mock_rt.cur.pin.assert_called_once_with(keys=(test_aid,), val="delegate1")


class TestScanForDelegates:
    """Tests for scan_for_delegates function"""

    def test_scan_for_delegates(self):
        """Test scan_for_delegates function"""
        mock_hby = Mock()
        mock_rt = Mock()
        delegator = "test_delegator"

        # Setup clone iterator
        mock_cloner = [b"msg1", b"msg2"]
        mock_hby.db.clonePreIter.return_value = mock_cloner

        with patch("keri.core.serdering.SerderKERI") as mock_serder:
            mock_srdr1 = Mock()
            mock_srdr2 = Mock()
            mock_serder.side_effect = [mock_srdr1, mock_srdr2]

            with patch(
                "kept.core.authentication.process_delegator_event_seals"
            ) as mock_process:
                scan_for_delegates(mock_hby, mock_rt, delegator)

        # Verify clonePreIter called correctly
        mock_hby.db.clonePreIter.assert_called_once_with(pre=delegator, fn=0)

        # Verify delegates cleared
        mock_rt.dlgs.rem.assert_called_once_with(keys=(delegator,))

        # Verify SerderKERI created for each message
        assert mock_serder.call_count == 2
        mock_serder.assert_any_call(raw=b"msg1")
        mock_serder.assert_any_call(raw=b"msg2")

        # Verify process_delegator_event_seals called for each serder
        assert mock_process.call_count == 2
        mock_process.assert_any_call(mock_hby, mock_rt, mock_srdr1)
        mock_process.assert_any_call(mock_hby, mock_rt, mock_srdr2)


class TestProcessDelegatorEventSeals:
    """Tests for process_delegator_event_seals function"""

    def test_process_delegator_event_seals_valid_inception(self):
        """Test process_delegator_event_seals with valid inception seal"""
        mock_hby = Mock()
        mock_rt = Mock()

        # Setup serder
        mock_srdr = Mock()
        mock_srdr.pre = "delegator_pre"
        mock_srdr.seals = [{"i": "delegate_pre", "s": "0", "d": "delegate_pre"}]

        # Setup delegate kever
        mock_delegate_kever = Mock()
        mock_delegate_kever.delpre = "delegator_pre"
        mock_delegate_kever.ndigers = ["ndiger1"]  # Non-empty list
        mock_hby.kevers = {"delegate_pre": mock_delegate_kever}

        with patch("kept.core.authentication.logger") as mock_logger:
            process_delegator_event_seals(mock_hby, mock_rt, mock_srdr)

        # Verify delegate added
        mock_rt.dlgs.add.assert_called_once_with(
            keys=("delegator_pre",), val="delegate_pre"
        )
        mock_logger.info.assert_called_once_with(
            "Signer delegate_pre added for delegator delegator_pre"
        )

    def test_process_delegator_event_seals_invalid_seal_format(self):
        """Test process_delegator_event_seals with invalid seal format"""
        mock_hby = Mock()
        mock_rt = Mock()

        mock_srdr = Mock()
        mock_srdr.pre = "delegator_pre"
        mock_srdr.seals = [{"invalid": "seal"}]  # Missing required fields

        process_delegator_event_seals(mock_hby, mock_rt, mock_srdr)

        # Verify no delegate added
        mock_rt.dlgs.add.assert_not_called()

    def test_process_delegator_event_seals_not_inception(self):
        """Test process_delegator_event_seals with non-inception seal"""
        mock_hby = Mock()
        mock_rt = Mock()

        mock_srdr = Mock()
        mock_srdr.pre = "delegator_pre"
        mock_srdr.seals = [
            {
                "i": "delegate_pre",
                "s": "1",
                "d": "different_d",
            }  # Not inception (s != "0")
        ]

        process_delegator_event_seals(mock_hby, mock_rt, mock_srdr)

        # Verify no delegate added
        mock_rt.dlgs.add.assert_not_called()

    def test_process_delegator_event_seals_wrong_delegator(self):
        """Test process_delegator_event_seals with wrong delegator"""
        mock_hby = Mock()
        mock_rt = Mock()

        mock_srdr = Mock()
        mock_srdr.pre = "delegator_pre"
        mock_srdr.seals = [{"i": "delegate_pre", "s": "0", "d": "delegate_pre"}]

        # Setup delegate kever with wrong delegator
        mock_delegate_kever = Mock()
        mock_delegate_kever.delpre = "wrong_delegator"
        mock_delegate_kever.ndigers = ["ndiger1"]
        mock_hby.kevers = {"delegate_pre": mock_delegate_kever}

        process_delegator_event_seals(mock_hby, mock_rt, mock_srdr)

        # Verify no delegate added
        mock_rt.dlgs.add.assert_not_called()

    def test_process_delegator_event_seals_neutered_delegate(self):
        """Test process_delegator_event_seals with neutered delegate"""
        mock_hby = Mock()
        mock_rt = Mock()

        mock_srdr = Mock()
        mock_srdr.pre = "delegator_pre"
        mock_srdr.seals = [{"i": "delegate_pre", "s": "0", "d": "delegate_pre"}]

        # Setup delegate kever that's neutered (empty ndigers)
        mock_delegate_kever = Mock()
        mock_delegate_kever.delpre = "delegator_pre"
        mock_delegate_kever.ndigers = []  # Empty list means neutered
        mock_hby.kevers = {"delegate_pre": mock_delegate_kever}

        process_delegator_event_seals(mock_hby, mock_rt, mock_srdr)

        # Verify no delegate added
        mock_rt.dlgs.add.assert_not_called()


class TestConstants:
    """Test module constants"""

    def test_chunk_size(self):
        """Test CHUNK_SIZE constant"""
        assert CHUNK_SIZE == 65536
        assert isinstance(CHUNK_SIZE, int)
