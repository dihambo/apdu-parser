from apdu_parser.apdu_error import APDUError
from apdu_parser.tlv.tlv import TLV_Array


class APDU:
    def __init__(self, apdu_cmd) -> None:
        self.cla_name = None
        self.ins_name = None
        self.data = None
        self.data_detail = None
        self.lc = None
        self.le = None
        self.response = None

        if isinstance(apdu_cmd, str):
            # 去除SW状态字
            if "SW" in apdu_cmd:
                apdu_cmd = apdu_cmd[:-6]
            self.command = bytes.fromhex(apdu_cmd)
        elif isinstance(apdu_cmd, tuple) and len(apdu_cmd) == 2:
            # 去除SW状态字
            if "SW" in apdu_cmd[0]:
                apdu_cmd[0] = apdu_cmd[0][:-6]
            self.command = bytes.fromhex(apdu_cmd[0])
            if len(apdu_cmd) > 1:
                self.response = bytes.fromhex(apdu_cmd[1])

        self.case_type = self.determine_case()
        if self.case_type == 0:
            raise Exception("wrong type")

        self.cla = self.command[0]
        self.ins = self.command[1]
        self.pa1 = self.command[2]
        self.pa2 = self.command[3]
        self.header = {
            "cla": "{:02X}".format(self.cla),
            "ins": "{:02X}".format(self.ins),
            "pa1": "{:02X}".format(self.pa1),
            "pa2": "{:02X}".format(self.pa2),
        }
        if self.case_type == 2:
            self.le = self.command[4]
            # self.header["le"] = "{:02X}".format(self.le)
            # if self.le > 0:
            #     self.header["r_apdu"] = self.response.hex()
        elif self.case_type >= 3:
            self.lc = self.command[4]
            self.data = self.command[5 : 5 + self.lc]
            # self.header["lc"] = "{:02X}".format(self.lc)
            # self.header["data"] = self.data.hex()
            if self.case_type == 4:
                self.le = self.command[-1]
                # self.header["le"] = "{:02X}".format(self.le)

        self.ins_table = {
            0x04: self.DEACTIVATE_FILE,
            0x0C: self.ERASE_RECORD,
            0x0E: self.ERASE_BINARY,
            0x0F: self.ERASE_BINARY,
            0x10: self.PERFORM_SCQL_OPERATION,
            0x12: self.PERFORM_TRANSACTION_OPERATION,
            0x14: self.PERFORM_USER_OPERATION,
            0x20: self.VERIFY,
            0x21: self.VERIFY,
            0x22: self.MANAGE_SECURITY_ENVIRONMENT,
            0x24: self.CHANGE_REFERENCE_DATA,
            0x26: self.DISABLE_VERIFICATION_REQUIREMENT,
            0x28: self.ENABLE_VERIFICATION_REQUIREMENT,
            0x2A: self.PERFORM_SECURITY_OPERATION,
            0x2C: self.RESET_RETRY_COUNTER,
            0x44: self.ACTIVATE_FILE,
            0x46: self.GENERATE_ASYMMETRIC_KEY_PAIR,
            0x70: self.MANAGE_CHANNEL,
            0x82: self.EXTERNAL_AUTHENTICATE,
            0x84: self.GET_CHALLENGE,
            0x86: self.GENERAL_AUTHENTICATE,
            0x87: self.GENERAL_AUTHENTICATE,
            0x88: self.INTERNAL_AUTHENTICATE,
            0xA0: self.SEARCH_BINARY,
            0xA1: self.SEARCH_BINARY,
            0xA2: self.SEARCH_RECORD,
            0xA4: self.SELECT,
            0xB0: self.READ_BINARY,
            0xB1: self.READ_BINARY,
            0xB2: self.READ_RECORD,
            0xB3: self.READ_RECORD,
            0xC0: self.GET_RESPONSE,
            0xC2: self.ENVELOPE,
            0xC3: self.ENVELOPE,
            0xCA: self.GET_DATA,
            0xCB: self.GET_DATA,
            0xD0: self.WRITE_BINARY,
            0xD1: self.WRITE_BINARY,
            0xD2: self.WRITE_RECORD,
            0xD6: self.UPDATE_BINARY,
            0xD7: self.UPDATE_BINARY,
            0xDA: self.PUT_DATA,
            0xDB: self.PUT_DATA,
            0xDC: self.UPDATE_RECORD,
            0xDD: self.UPDATE_RECORD,
            0xE0: self.CREATE_FILE,
            0xE2: self.APPEND_RECORD,
            0xE4: self.DELETE_FILE,
            0xE6: self.TERMINATE_DF,
            0xE8: self.TERMINATE_EF,
            0xFE: self.TERMINATE_CARD_USAGE,
        }
        self.parse_cla()
        self.parse_ins()

    def to_dict(self):
        res = dict()
        res["header"] = self.header
        res["class"] = self.cla_name
        res["logical_channel"] = self.logical_channel
        res["is_last_cmd"] = self.command_chain
        res["ins"] = self.ins_name
        if self.data:
            res["data_length"] = self.lc
            res["data"] = self.data.hex()
        if self.le:
            res['response_length'] = self.le

        if self.data_detail:
            if isinstance(self.data_detail,TLV_Array):
                res['data_detail'] = [tlv.to_dict() for tlv in self.data_detail.get_tlv_list()]
            elif isinstance(self.data_detail,dict):
                res['data_detail'] = self.data_detail
        return res

    def determine_case(self):
        length = len(self.command)
        if length == 4:
            return 1
        elif length == 5:
            return 2
        elif length >= 6:
            lc = self.command[4]
            if length == 4 + 1 + lc:
                return 3
            elif length == 4 + 1 + lc + 1:
                return 4
        return 0

    def parse_lv(self, data: bytes):
        pass
        # lv_list = []
        # offset = 0
        # while offset < len(data):
        #     lv = {"length": data[offset]}
        #     if lv["length"] == 0x81:
        #         lv["length"] = data[offset + 2]
        #         offset += 1
        #     lv["value"] = data[offset + 1 : offset + 1 + lv["length"]].hex()
        #     offset += 1 + lv["length"]
        #     lv["length"] = "{:02X}".format(lv["length"])
        #     lv_list.append(lv)
        # return lv_list

    def parse_cla(self):
        # 解析cla种类
        kind = self.cla & 0xE0
        self.command_chain = self.cla & 0x10
        self.secure_message = self.cla & 0x0C
        self.logical_channel = self.cla & 0x03
        if kind == 0x00:
            self.cla_name = "ISO7816"
        # ? 0x80既是gp也是tel的cla
        # elif kind == 0x80:
        #     self.cla_name = "GlobalPlatform"
        else:
            self.cla_name = "other"

    def parse_ins(self):
        if self.ins in self.ins_table:
            self.ins_table[self.ins]()
        else:
            raise APDUError("未知指令")

    def DEACTIVATE_FILE(self):
        pass

    def ERASE_RECORD(self):
        pass

    def ERASE_BINARY(self):
        pass

    def PERFORM_SCQL_OPERATION(self):
        pass

    def PERFORM_TRANSACTION_OPERATION(self):
        pass

    def PERFORM_USER_OPERATION(self):
        pass

    def VERIFY(self):
        pass

    def MANAGE_SECURITY_ENVIRONMENT(self):
        pass

    def CHANGE_REFERENCE_DATA(self):
        pass

    def DISABLE_VERIFICATION_REQUIREMENT(self):
        pass

    def ENABLE_VERIFICATION_REQUIREMENT(self):
        pass

    def PERFORM_SECURITY_OPERATION(self):
        pass

    def RESET_RETRY_COUNTER(self):
        pass

    def ACTIVATE_FILE(self):
        pass

    def GENERATE_ASYMMETRIC_KEY_PAIR(self):
        pass

    def MANAGE_CHANNEL(self):
        pass

    def EXTERNAL_AUTHENTICATE(self):
        pass

    def GET_CHALLENGE(self):
        pass

    def GENERAL_AUTHENTICATE(self):
        pass

    def INTERNAL_AUTHENTICATE(self):
        pass

    def SEARCH_BINARY(self):
        pass

    def SEARCH_RECORD(self):
        pass

    def SELECT(self):
        pass

    def READ_BINARY(self):
        pass

    def READ_RECORD(self):
        pass

    def GET_RESPONSE(self):
        self.ins_name = "GET_RESPONSE"
        pass

    def ENVELOPE(self):
        self.ins_name = "ENVELOPE"

    def GET_DATA(self):
        self.ins_name = "GET_DATA"
        pass

    def WRITE_BINARY(self):
        pass

    def WRITE_RECORD(self):
        pass

    def UPDATE_BINARY(self):
        pass

    def PUT_DATA(self):
        pass

    def UPDATE_RECORD(self):
        pass

    def CREATE_FILE(self):
        pass

    def APPEND_RECORD(self):
        self.ins_name = "APPEND_RECORD"

    def DELETE_FILE(self):
        self.ins_name = "DELETE_FILE"

    def TERMINATE_DF(self):
        pass

    def TERMINATE_EF(self):
        pass

    def TERMINATE_CARD_USAGE(self):
        pass


class RAPDU:
    def __init__(self, data: str | bytes):
        if isinstance(data, str):
            data = bytes.fromhex(data)
        self.data = data
