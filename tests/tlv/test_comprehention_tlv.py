# import pytest
from apdu_parser.tlv.BER_TLV import BER_TLV
from apdu_parser.tlv.COMPREHENSION_TLV import COMPREHENSION_TLV
from apdu_parser.tlv.tlv import TLV_Array

def test_COMPREHENTION_TLV():
    tlv1 = "D00E810301050082028182990303090A"
    tlv2 = "D1 81 84 82 02 83 81 06 04 81 21 43 65 8B 78 40 06 81 21 43 65 7F F6 31 40 32 61 51 00 00 68 02 70 00 00 63 15 02 01 15 15 B2 02 12 00 00 00 00 00 00 1F 5F EB 45 96 D8 2B F2 AA 4B 22 49 80 D8 00 81 43 21 80 10 4F 93 80 B6 FA 2A FE 82 1C C6 3D B0 69 3B 16 C0 03 1F 17 DB 80 10 1C C6 3D B0 69 3B 16 C0 4F 93 80 B6 FA 2A FE 82 03 56 8A 4A 80 10 27 9D 3E 82 C0 FB CE 94 22 04 EF FE AB F8 2A 22 03 AA 43 2D 00 00"
    tlv1 = BER_TLV.from_bytes(tlv1)
    tlv2 = BER_TLV.from_bytes(tlv2)
    tlv1.constructed_value = TLV_Array.from_bytes(tlv1.to_dict()['value'],COMPREHENSION_TLV).get_tlv_list()
    tlv2.constructed_value = TLV_Array.from_bytes(tlv2.to_dict()['value'],COMPREHENSION_TLV).get_tlv_list()
    tlv1.to_dict()
    tlv2.to_dict()
    pass
