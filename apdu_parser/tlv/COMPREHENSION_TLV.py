from apdu_parser.tlv.tlv import TLV
from apdu_parser.tlv.tlv_error import (
    InvalidTagError,
    InvalidLengthError,
    InvalidValueError,
    TLVError,
)


class COMPREHENSION_TLV(TLV):
    def __init__(
        self,
        tag_field: bytes | str,
        length_field: bytes | str,
        value_field: bytes | str,
    ) -> None:
        super().__init__(tag_field, length_field, value_field)
        self.tag_class: int = None
        self.tag_constructed: bool = None
        self.tag_number: int = None
        self.parse_tag_header()

    @classmethod
    def from_bytes(cls, data: bytes | str):
        if isinstance(data, str):
            data = bytes.fromhex(data)
        try:
            if len(data) < 2:
                raise TLVError("data is too short: {data}")
            tag = cls.get_tag_field_from_bytes(data)
            tag_len = len(tag)
            length_field = cls.get_length_field_from_bytes(data[tag_len:])
            length_len = len(length_field)
            length = cls.parse_length_field(length_field)
            value = data[tag_len + length_len : tag_len + length_len + length]
            return cls(tag, length_field, value)
        except Exception as e:
            raise e

    @staticmethod
    def get_tag_field_from_bytes(data: bytes | str) -> bytes:
        if isinstance(data, str):
            data = bytes.fromhex(data)

        if data[0] == 0x7F:
            # tag is three bytes
            tag = data[:3]
        else:
            # tag is one byte
            tag = data[:1]
        try:
            COMPREHENSION_TLV.check_tag_valid(tag)
        except TLVError as e:
            raise e
        return tag

    @staticmethod
    def get_length_field_from_bytes(data: bytes) -> bytes:
        if data[0] < 0x80:
            return data[:1]
        elif data[0] == 0x81:
            return data[:2]
        elif data[0] == 0x82:
            return data[:3]
        elif data[0] == 0x83:
            return data[:4]
        else:
            raise InvalidLengthError(data[:1], "length field is invalid")
            
    @staticmethod
    def check_tag_valid(tag: bytes):
        if tag[0] == 0x00 or tag[0] == 0xFF or tag[0] == 0x80:
            raise InvalidTagError(tag, "tag's first bytes is 0x00 or 0xff")
        if tag[0] == 0x7F:
            if len(tag) != 3:
                raise InvalidTagError(
                    tag, "tag is three bytes, but the length is not 3"
                )
        else:
            if len(tag) != 1:
                raise InvalidTagError(tag, "tag is one byte, but the length is not 1")

    @staticmethod
    def check_length_valid(length_field: bytes):
        if len(length_field) == 1:
            if length_field[0] >= 0x80:
                raise InvalidLengthError(length_field, "length field is invalid")
            return
        if length_field[0] == 0x81:
            if len(length_field) != 2:
                raise InvalidLengthError(length_field, "length field is invalid")
        elif length_field[0] == 0x82:
            if len(length_field) != 3:
                raise InvalidLengthError(length_field, "length field is invalid")
        elif length_field[0] == 0x83:
            if len(length_field) != 4:
                raise InvalidLengthError(length_field, "length field is invalid")
        else:
            raise InvalidLengthError(length_field, "length field is invalid")

    @staticmethod
    def parse_length_field(length_field: bytes):
        try:
            COMPREHENSION_TLV.check_length_valid(length_field)
            if length_field[0] < 0x80:
                return length_field[0]
            else:
                return int.from_bytes(length_field[1:], "big")
        except Exception as e:
            raise e

    def check_value_valid(self, value: bytes):
        try:
            if len(value) != self.get_length():
                raise InvalidValueError(
                    value, "value length is not equal to length field"
                )
        except InvalidValueError as e:
            raise e

    def get_length(self):
        return self.parse_length_field(self.length)

    def parse_tag_header(self):
        self.tag_cr = bool((self.tag[0] & 0x80) >> 7)
        self.tag_number = self.tag[0] & 0x7F
