from abc import ABC, abstractmethod
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

        self.tag = self._convert_to_bytes(tag_field)
        self.length = self._convert_to_bytes(len_field)
        self.value = self._convert_to_bytes(value_field) if value_field is not None else b''

        self.check_validity()

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
    @abstractmethod
    def from_bytes(cls, data: bytes | str):
        pass

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
    def __init__(self, tlv_array: list) -> None:
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
