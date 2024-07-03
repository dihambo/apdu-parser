class TLVError(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


class InvalidTagError(TLVError):
    def __init__(self, tag: int, message: str = None):
        self.tag = tag
        if message:
            message = " : " + message
        self.message = f"Invalid tag: {tag} :" + message
        super().__init__(self.message)


class InvalidLengthError(TLVError):
    def __init__(self, length: int, message: str = None):
        self.length = length
        if message:
            message = " : " + message
        self.message = f"Invalid length: {length} :" + message
        super().__init__(self.message)


class InvalidValueError(TLVError):
    def __init__(self, value: bytes, message: str = None):
        self.value = value
        if message:
            message = " : " + message
        self.message = f"Invalid value: {value} :" + message
        super().__init__(self.message)
