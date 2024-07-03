class TLV:
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
        self.bytes_arrary: bytes = None

        if isinstance(tag_field, str):
            tag_field = bytes.fromhex(tag_field)
        if isinstance(len_field, str):
            len_field = bytes.fromhex(len_field)
        if value_field is not None and isinstance(value_field, str):
            value_field = bytes.fromhex(value_field)

        try:
            self.check_tag_valid(tag_field)
            self.check_length_valid(len_field)

            self.tag = tag_field
            self.length = len_field

            if value_field is not None:
                self.check_value_valid(value_field)
                self.value = value_field

            self.tlv_len = len(self.tag) + len(self.length) + len(self.value)
            self.bytes_arrary = self.tag + self.length + self.value
        except Exception as e:
            raise e

    @classmethod
    def from_bytes(cls, data: bytes | str):
        raise NotImplementedError()

    def to_dict(self):
        tlv_dict = dict()
        tlv_dict["tag"] = self.get_tag()
        tlv_dict["length"] = self.get_length()
        if self.value is not None:
            if hasattr(self, "constructed_value"):
                tlv_dict["constructed_value"] = [
                    tlv.to_dict() for tlv in self.constructed_value
                ]
            else:
                tlv_dict["value"] = self.get_value()
        return tlv_dict

    def get_tag(self):
        return self.tag.hex().upper()

    def get_length(self):
        return self.length.hex().upper()

    def get_value(self):
        return self.value.hex().upper()

    @staticmethod
    def check_tag_valid(tag: bytes):
        raise NotImplementedError()

    @staticmethod
    def check_length_valid(length: bytes):
        raise NotImplementedError()

    def check_value_valid(self):
        raise NotImplementedError()


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
