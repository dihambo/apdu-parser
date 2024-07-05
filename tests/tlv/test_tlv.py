import pytest
from apdu_parser.tlv.BER_TLV import BER_TLV, TLV_Array
from apdu_parser.tlv.tlv_error import TLVError, InvalidTagError, InvalidLengthError, InvalidValueError


def test_bertlv_baisc():
    tlv = BER_TLV(b"\x01", b"\x01", b"\x01")
    assert tlv.get_tag() == "01"
    assert tlv.get_length() == 1
    assert tlv.get_value() == "01"


def test_bertlv_from_bytes():
    tlv = BER_TLV.from_bytes(b"\x01\x01\x01")
    assert tlv.get_tag() == "01"
    assert tlv.get_length() == 1
    assert tlv.get_value() == "01"


def test_BER_TLV_tag():
    one_tag_one_len_tlv_0 = bytes.fromhex("0f0132")
    one_tag_one_len_tlv_1 = bytes.fromhex("4410000102030405060708090a0b0c0d0e0f")
    one_tag_two_len_tlv_0 = bytes.fromhex("0f810132")
    two_tag_one_len_tlv_0 = bytes.fromhex("9F 1F 03 56 78 90")
    three_tag_one_len_tlv_0 = bytes.fromhex("DF 81 1F 04 11 22 33 44")
    tlv0 = BER_TLV.from_bytes(one_tag_one_len_tlv_0)
    tlv1 = BER_TLV.from_bytes(one_tag_one_len_tlv_1)
    tlv2 = BER_TLV.from_bytes(one_tag_two_len_tlv_0)
    tlv3 = BER_TLV.from_bytes(two_tag_one_len_tlv_0)
    tlv4 = BER_TLV.from_bytes(three_tag_one_len_tlv_0)
    assert tlv0.get_tag() == "0F"
    assert tlv1.get_tag() == "44"
    assert tlv2.get_tag() == "0F"
    assert tlv3.get_tag() == "9F1F"
    assert tlv4.get_tag() == "DF811F"


def test_BER_TLV_wrong_tag():
    zero_tag_tlv = bytes.fromhex("000132")
    ff_tag_tlv = bytes.fromhex("ff0132")
    muti_byte_tag_tlv = bytes.fromhex("1f81828300")
    faulty_tag_tlv1 = bytes.fromhex("9F 00 01 11")
    faulty_tag_tlv2 = bytes.fromhex("9F 1E 01 22")
    faulty_tag_tlv3 = bytes.fromhex("9F 80 01 33")
    faulty_tag_tlv4 = bytes.fromhex("DF 80 1F 02 44 55")
    faulty_tag_tlv5 = bytes.fromhex("DF 81 80 02 66 77")
    with pytest.raises(InvalidTagError, match="tag's first bytes is 0x00 or 0xff"):
        BER_TLV.from_bytes(zero_tag_tlv).get_tag()
    with pytest.raises(InvalidTagError, match="tag's first bytes is 0x00 or 0xff"):
        BER_TLV.from_bytes(ff_tag_tlv).get_tag()
    with pytest.raises(
        InvalidTagError,
        match="three-byte tag's third byte is not in the range of 0x00 to 0x7f",
    ):
        BER_TLV.from_bytes(muti_byte_tag_tlv).get_tag()
    with pytest.raises(
        InvalidTagError,
        match="three-byte tag's third byte is not in the range of 0x00 to 0x7f",
    ):
        BER_TLV.from_bytes(bytes.fromhex("1fBfff7f020001")).get_tag()
    with pytest.raises(
        InvalidTagError,
        match="two-byte tag's second byte is not in the range of 0x1f to 0x7f",
    ):
        BER_TLV.from_bytes(faulty_tag_tlv1).get_tag()
    with pytest.raises(
        InvalidTagError,
        match="two-byte tag's second byte is not in the range of 0x1f to 0x7f",
    ):
        BER_TLV.from_bytes(faulty_tag_tlv2).get_tag()
    with pytest.raises(
        InvalidTagError,
        match="three-byte tag's second byte is not in the range of 0x81 to 0xff",
    ):
        BER_TLV.from_bytes(faulty_tag_tlv3).get_tag()
    with pytest.raises(
        InvalidTagError,
        match="three-byte tag's second byte is not in the range of 0x81 to 0xff",
    ):
        BER_TLV.from_bytes(faulty_tag_tlv4).get_tag()
    with pytest.raises(
        InvalidTagError,
        match="three-byte tag's third byte is not in the range of 0x00 to 0x7f",
    ):
        BER_TLV.from_bytes(faulty_tag_tlv5).get_tag()


def test_BER_TLV_length():
    short_len_tlv1 = bytes.fromhex("5A 02 12 34")
    short_len_tlv2 = bytes.fromhex(
        "9F 1F 7F 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
    )
    long_len_tlv1 = bytes.fromhex(
        "9F 1F 81 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
    )
    long_len_tlv2 = bytes.fromhex(
        "DF 81 1F 82 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
    )
    tlv1 = BER_TLV.from_bytes(short_len_tlv1)
    tlv2 = BER_TLV.from_bytes(short_len_tlv2)
    tlv3 = BER_TLV.from_bytes(long_len_tlv1)
    tlv4 = BER_TLV.from_bytes(long_len_tlv2)
    assert tlv1.get_length() == 0x02
    assert tlv2.get_length() == 0x7F
    assert tlv3.get_length() == 0x80
    assert tlv4.get_length() == 0x100


def test_BER_TLV_wrong_length():
    faulty_len_tlv1 = bytes.fromhex("5A 80 01 11")
    faulty_len_tlv2 = bytes.fromhex("9F 1F 83 01 01 22")
    faulty_len_tlv3 = bytes.fromhex("9F 1F FF 01 01 33")

    with pytest.raises(InvalidLengthError, match="length field is invalid"):
        BER_TLV.from_bytes(faulty_len_tlv1).get_length()
    with pytest.raises(InvalidLengthError, match="length field is invalid"):
        BER_TLV.from_bytes(faulty_len_tlv2).get_length()
    with pytest.raises(InvalidLengthError, match="length field is invalid"):
        BER_TLV.from_bytes(faulty_len_tlv3).get_length()


def test_BERR_TLV_value():
    tlv1 = BER_TLV.from_bytes(bytes.fromhex("5A 00"))
    tlv2 = BER_TLV.from_bytes(bytes.fromhex("5B 02 12 34"))
    tlv3 = BER_TLV.from_bytes(bytes.fromhex("9F 1F 03 56 78 90"))
    tlv4 = BER_TLV.from_bytes(bytes.fromhex("DF 81 1F 04 11 22 33 44"))
    tlv5 = BER_TLV.from_bytes(
        bytes.fromhex(
            "9F 1F 7F 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        )
    )
    tlv6 = BER_TLV.from_bytes(
        bytes.fromhex(
            "9F 1F 81 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        )
    )
    tlv7 = BER_TLV.from_bytes(
        bytes.fromhex(
            "DF 81 1F 82 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        )
    )

    assert tlv1.get_value() == ""
    assert tlv2.get_value() == "1234"
    assert tlv3.get_value() == "567890"
    assert tlv4.get_value() == "11223344"
    assert (
        tlv5.get_value()
        == "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    )
    assert (
        tlv6.get_value()
        == "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    )
    assert (
        tlv7.get_value()
        == "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    )


def test_BER_TLV_wrong_value():
    faulty_value_tlv1 = bytes.fromhex("5B 02 12")
    # faulty_value_tlv2 = bytes.fromhex("5B 02 12 34 56")
    faulty_value_tlv3 = bytes.fromhex("9F 1F 03 56 78")
    faulty_value_tlv4 = bytes.fromhex("DF 81 1F 04 11 22 33")
    faulty_value_tlv5 = bytes.fromhex("9F 1F 7F 00 00")
    faulty_value_tlv6 = bytes.fromhex("9F 1F 81 80 00 00")
    faulty_value_tlv7 = bytes.fromhex("DF 81 1F 82 01 00 00 00 00")
    faulty_value_tlv8 = bytes.fromhex("E1 0C 5A 02 12 34 9F 00 03 56 78 90")
    faulty_value_tlv9 = bytes.fromhex("E1 0D 5A 02 12 34 9F 1F 80 01 11")
    with pytest.raises(
        InvalidValueError, match="value length is not equal to length field"
    ):
        BER_TLV.from_bytes(faulty_value_tlv1).get_value()
    # with pytest.raises(InvalidValueError, match="value length is not equal to length field"):
    #     BER_TLV.from_bytes(faulty_value_tlv2).get_value()
    with pytest.raises(
        InvalidValueError, match="value length is not equal to length field"
    ):
        BER_TLV.from_bytes(faulty_value_tlv3).get_value()
    with pytest.raises(
        InvalidValueError, match="value length is not equal to length field"
    ):
        BER_TLV.from_bytes(faulty_value_tlv4).get_value()
    with pytest.raises(
        InvalidValueError, match="value length is not equal to length field"
    ):
        BER_TLV.from_bytes(faulty_value_tlv5).get_value()
    with pytest.raises(
        InvalidValueError, match="value length is not equal to length field"
    ):
        BER_TLV.from_bytes(faulty_value_tlv6).get_value()
    with pytest.raises(
        InvalidValueError, match="value length is not equal to length field"
    ):
        BER_TLV.from_bytes(faulty_value_tlv7).get_value()
    with pytest.raises(TLVError):
        BER_TLV.from_bytes(faulty_value_tlv8).get_value()
    with pytest.raises(TLVError):
        BER_TLV.from_bytes(faulty_value_tlv9).get_value()


def test_BER_tlv_array():
    tlv_array1 = bytes.fromhex(
        "5A 02 12 34 5B 02 12 34 9F 1F 03 56 78 90 DF 81 1F 04 11 22 33 44"
    )

    tlv_list = TLV_Array.from_bytes(tlv_array1, BER_TLV).get_tlv_list()
    assert len(tlv_list) == 4
    assert tlv_list[0].get_tag() == "5A"
    assert tlv_list[1].get_tag() == "5B"
    assert tlv_list[2].get_tag() == "9F1F"
    assert tlv_list[3].get_tag() == "DF811F"


def test_BER_TLV_array_wrong():
    faulty_tlv_array1 = bytes.fromhex(
        "5A 02 12 34 5B 02 12 34 9F 1F 03 56 78 90 DF 81 1F 04 11 22 33"
    )
    faulty_tlv_array2 = bytes.fromhex(
        "5A 02 12 34 5B 02 12 34 9F 1F 03 56 78 90 DF 81 1F 04 11 22 33 44 55"
    )
    faulty_value_tlv2 = bytes.fromhex("5B 02 12 34 56")

    with pytest.raises(TLVError):
        TLV_Array.from_bytes(faulty_tlv_array1, BER_TLV).get_tlv_list()
    with pytest.raises(TLVError):
        TLV_Array.from_bytes(faulty_tlv_array2, BER_TLV).get_tlv_list()
    with pytest.raises(TLVError):
        TLV_Array.from_bytes(faulty_value_tlv2, BER_TLV).get_tlv_list()


def test_BER_TLV_nest():
    tlv1 = BER_TLV.from_bytes("E2 10 5A 02 12 34 E1 0A 9F 1F 03 56 78 90 5B 02 12 34")
    # tlv2 = BER_TLV.from_bytes(bytes.fromhex("E1 0A 5A 02 12 34 9F 1F 03 56 78 90"))

    assert isinstance(tlv1.parse_constructed_value(BER_TLV), list)
    # todo 待完善
