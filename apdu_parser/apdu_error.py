class APDUError(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


class APDU_CLA_Error(APDUError):
    def __init__(self, cla: bytes, message: str):
        self.cla = cla
        if message:
            message = " : " + message
        self.message = f"Invalid cla: {cla} :" + message
        super().__init__(message)


class APDU_Parameter_Error(APDUError):
    def __init__(self, pa1, pa2, message: str):
        if message:
            message = " : " + message
        self.message = f"Invalid parameter: pa1:{pa1},pa2:{pa2} :" + message
        super().__init__(message)
