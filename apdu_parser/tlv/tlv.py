from abc import ABC, abstractmethod
from apdu_parser.tlv.tlv_error import (
    TLVError,
)
class TLV(ABC):
    """最基本的TLV类。tag域和length域的编码会根据具体的TLV子类而有所不同。
    """
    def __init__(
        self,
        tag_field: str | bytes,
        len_field: str | bytes,
        value_field: str | bytes = None,
    ) -> None:
        self.tag: bytes = None
        self.length: bytes = None
        self.value: bytes = None
        self.tlv_len: int = 0
        self.bytes_array: bytes = None

        self.tag_detail:dict = None
        self.length_detail:int = 0
        self.value_detail:dict|str = None

        self.tag = self._convert_to_bytes(tag_field)
        self.length = self._convert_to_bytes(len_field)
        self.value = self._convert_to_bytes(value_field) if value_field is not None else b''

        self.check_validity()

        self.tag_detail = self.parse_tag_field(self.tag)
        self.length_detail = self.parse_length_field(self.length)
        # value的具体解析留在子类中实现，这里只放置value的原始数据
        self.value_detail = self.value.hex().upper() if self.value else ""

        self.tlv_len = len(self.tag) + len(self.length) + len(self.value)
        self.bytes_array = self.tag + self.length + self.value

    def _convert_to_bytes(self, field: str | bytes) -> bytes:
        return bytes.fromhex(field) if isinstance(field, str) else field

    def check_validity(self):
        self.check_tag_valid(self.tag)
        self.check_length_valid(self.length)
        if self.value:
            self.check_value_valid(self.value)

    @classmethod
    def from_bytes(cls, data: bytes | str):
        if isinstance(data, str):
            data = bytes.fromhex(data)
        try:
            if len(data)<2:
                raise TLVError(f"data is too short: {data}")
            tag_field = cls.get_tag_field_from_bytes(data)
            tag_len = len(tag_field)
            length_field = cls.get_length_field_from_bytes(data[tag_len:])
            length_field_len = len(length_field)
            length = cls.parse_length_field(length_field)
            value = data[tag_len + length_field_len:tag_len + length_field_len + length]
            return cls(tag_field, length_field, value)
        except Exception as e:
            raise e

    @abstractmethod
    def to_dict(self):
        tlv_dict = {
            "tag": self.get_tag(),
            "length": self.get_length(),
            "value": self.get_value() if self.value else ""
        }
        return tlv_dict

    def get_tag(self):
        return self.tag.hex().upper()

    def get_length(self):
        return self.length.hex().upper()

    def get_value(self):
        return self.value.hex().upper()
    
    @staticmethod
    @abstractmethod
    def get_tag_field_from_bytes(data: bytes) -> bytes:
        pass

    @staticmethod
    @abstractmethod
    def get_length_field_from_bytes(data: bytes) -> bytes:
        pass
    
    #? 似乎没有必要有这个接口。因为有了get_tag_field_from_bytes和get_length_field_from_bytes，就可以直接解析出value了。
    # @abstractmethod
    # def get_value_field_from_bytes(self, data: bytes) -> bytes:
    #     pass

    @staticmethod
    @abstractmethod
    def parse_tag_field(data: bytes) -> dict:
        pass

    @staticmethod
    @abstractmethod
    def parse_length_field(data: bytes) -> int:
        pass

    @abstractmethod
    def parse_value_field(data: bytes) -> dict|str:
        pass

    @staticmethod
    @abstractmethod
    def check_tag_valid(tag: bytes):
        pass

    @staticmethod
    @abstractmethod
    def check_length_valid(length: bytes):
        pass

    @abstractmethod
    def check_value_valid(self, value: bytes):
        pass


class TLV_Array:
    def __init__(self, tlv_array: list[TLV]) -> None:
        self.tlv_list = tlv_array

    def get_tlv_list(self):
        return self.tlv_list

    @classmethod
    def from_bytes(cls, data: bytes | str, tlv_class: TLV):
        if isinstance(data, str):
            data = bytes.fromhex(data)
        tlv_array = []
        while len(data) > 0:
            try:
                tlv = tlv_class.from_bytes(data)
                tlv_array.append(tlv)
                data = data[tlv.tlv_len :]
            except Exception as e:
                raise e
        return cls(tlv_array)


# todo factory
