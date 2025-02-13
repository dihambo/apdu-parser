from apdu_parser.tlv.tlv import TLV, TLV_Array
from apdu_parser.tlv.tlv_error import (
    InvalidTagError,
    InvalidLengthError,
    InvalidValueError,
    TLVError,
)


class BER_TLV(TLV):
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
        if self.tag_constructed:
            try:
                self.constructed_value = self.parse_constructed_value()
            except Exception as e:
                raise e

    @classmethod
    def from_bytes(cls, data: bytes | str):
        if isinstance(data, str):
            data = bytes.fromhex(data)
        try:
            if len(data) < 2:
                raise TLVError("data is too short: {data}")
            tag = cls.__get_tag_from_bytes(data)
            tag_len = len(tag)
            length_field = cls.get_length_field_from_bytes(data[tag_len:])
            length_len = len(length_field)
            length = cls.parse_length_filed(length_field)
            value = data[tag_len + length_len : tag_len + length_len + length]
            return cls(tag, length_field, value)
        except Exception as e:
            raise e

    @staticmethod
    def __get_tag_from_bytes(data: bytes | str) -> bytes:
        """Return first tag field from the head of data. suppose the tag is not longer than 3 bytes.

        Args:
            data (bytes): bytes data to get tag

        Raises:
            InvalidTagError: _description_
            InvalidTagError: _description_
            InvalidTagError: _description_
            e: _description_

        Returns:
            byts: tag field
        """
        if isinstance(data, str):
            data = bytes.fromhex(data)
        if data[0] == 0x00 or data[0] == 0xFF:
            raise InvalidTagError(data[:1], "tag's first bytes is 0x00 or 0xff")

        if data[0] & 0x1F == 0x1F:
            if data[1] & 0x80 == 0x80:
                # three-byte tag
                tag = data[:3]
            else:
                # two-byte tag
                tag = data[:2]
        else:
            # one-byte tag
            tag = data[:1]
        try:
            BER_TLV.check_tag_valid(tag)
        except InvalidTagError as e:
            raise e
        return tag

    @staticmethod
    def check_tag_valid(tag: bytes):
        """check if tag is valid. According to ISO/IEC 7816-4.

        Args:
            tag (bytes): tag field

        Returns:
            bool: True if tag is valid, False otherwise

        Note:
            In tag fields of two or more bytes, the values '00' to '1E' and '80' are invalid for the second byte.
            - In two-byte tag fields, the second byte consists of bit 8 set to 0 and bits 7 to 1 encoding a number greater
            than thirty. The second byte is valued from '1F' to '7F; the tag number is from 31 to 127.
            - In three-byte tag fields, the second byte consists of bit 8 set to 1 and bits 7 to 1 not all set to 0; the third
            byte consists of bit 8 set to 0 and bits 7 to 1 with any value. The second byte is valued from '81' to 'FF'
            and the third byte from '00' to '7F'; the tag number is from 128 to 16 383.
        """
        tag_len = len(tag)
        try:
            if tag[0] == 0x00 or tag[0] == 0xFF:
                raise InvalidTagError(tag, "tag's first bytes is 0x00 or 0xff")
            if tag_len == 1 and tag[0] & 0x1F < 0x1F:
                return
            elif tag[0] & 0x1F == 0x1F and tag_len > 1:
                if tag_len == 2:
                    if not (tag[1] >= 0x1F and tag[1] <= 0x7F):
                        raise InvalidTagError(
                            tag,
                            "two-byte tag's second byte is not in the range of 0x1f to 0x7f",
                        )
                elif tag_len == 3:
                    if not (tag[1] >= 0x81 and tag[1] <= 0xFF):
                        raise InvalidTagError(
                            tag,
                            "three-byte tag's second byte is not in the range of 0x81 to 0xff",
                        )
                    if not (tag[2] >= 0x00 and tag[2] <= 0x7F):
                        raise InvalidTagError(
                            tag,
                            "three-byte tag's third byte is not in the range of 0x00 to 0x7f",
                        )
            else:
                raise InvalidTagError(tag, "tag is invalid")
        except InvalidTagError as e:
            raise e
    @staticmethod
    def get_length_field_from_bytes(data: bytes) -> bytes:
        """Return length field from the head of data. suppose the length is not longer than 3 bytes.

        Args:
            data (bytes): data to get length field

        Raises:
            InvalidLengthError: length field is invalid

        Returns:
            bytes: length field. note that the length field is not the length of data, but the length of value field.

        Note:
            - If the first byte of the Length field is '00' to '7F', then the length is the value of the first byte.
            - If the first byte of the Length field is '81', then the Length field is two bytes long, and the length is
            the value of the second byte.
            - If the first byte of the Length field is '82', then the Length field is three bytes long, and the length is
            the value of the second byte concatenated with the value of the third byte.
        """
        # suppose the data has been processed by __get_tag_from_bytes, and the data is beginning with length field
        if data[0] < 0x80:
            len_filed = data[:1]
        elif data[0] == 0x81:
            len_filed = data[:2]
        elif data[0] == 0x82:
            len_filed = data[:3]
        else:
            raise InvalidLengthError(data[0], "length field is invalid")
        return len_filed

    @staticmethod
    def check_length_valid(length_field: bytes):
        """check if length field is valid. According to ISO/IEC 7816-4.

        Args:
            length_field (bytes): length field

        Returns:
            bool: True if length field is valid, False otherwise

        Note:
            - If the first byte of the Length field is '00' to '7F', then the length is the value of the first byte.
            - If the first byte of the Length field is '81', then the Length field is two bytes long, and the length is
            the value of the second byte.
            - If the first byte of the Length field is '82', then the Length field is three bytes long, and the length is
            the value of the second byte concatenated with the value of the third byte.
        """
        len_len = len(length_field)
        res = False
        try:
            if len_len == 0:
                raise InvalidLengthError(length_field, "length field is empty")
            if len_len == 1:
                res = True
            elif len_len == 2:
                if length_field[0] != 0x81:
                    raise InvalidLengthError(length_field, "length field is invalid")
                res = True
            elif len_len == 3:
                if length_field[0] != 0x82:
                    raise InvalidLengthError(length_field, "length field is invalid")
                res = True
            else:
                raise InvalidLengthError(length_field, "length field is invalid")
        except InvalidLengthError as e:
            raise e
        finally:
            return res

    @staticmethod
    def parse_length_filed(length_field: bytes) -> int:
        if not BER_TLV.check_length_valid(length_field):
            raise InvalidLengthError(length_field, "length field is invalid")
        len_len = len(length_field)
        if len_len == 1:
            return length_field[0]
        elif len_len == 2:
            return length_field[1]
        elif len_len == 3:
            return int.from_bytes(length_field[1:], "big")

    def parse_tag_header(self):
        self.tag_class = (self.tag[0] & 0xC0) >> 6
        self.tag_constructed = bool((self.tag[0] & 0x20) >> 5)
        if len(self.tag) == 1:
            self.tag_number = self.tag[0] & 0x1F
        elif len(self.tag) == 2:
            self.tag_number = self.tag[1] & 0x7F
        elif len(self.tag) == 3:
            self.tag_number = (self.tag[1] & 0x7F) << 7 | (self.tag[2] & 0x7F)

        if self.tag_number > 0x3FFF:
            raise InvalidTagError(self.tag, "tag number is greater than 0x3fff")

    def parse_constructed_value(self):
        if not self.tag_constructed:
            return self.value.hex().upper()
        else:
            try:
                tlv_list = TLV_Array.from_bytes(
                    self.value, self.__class__
                ).get_tlv_list()
                return tlv_list
            except Exception as e:
                raise e

    def check_value_valid(self, value: bytes):
        # todo need tlv array be implemented
        try:
            if self.get_length() != len(value):
                raise InvalidValueError(
                    value, "value length is not equal to length field"
                )
        except InvalidValueError as e:
            raise e

    def get_length(self):
        return self.parse_length_filed(self.length)

    def get_constructed_value(self):
        if not self.tag_constructed:
            raise TLVError("tag is not constructed")
        return self.constructed_value
