from apdu import APDU


class GlobalPlateformAPDU(APDU):
    def __init__(self, apdu_cmd):
        super().__init__(apdu_cmd)

    def parse_ins(self):
        for index, ins_name in self.ins_table:
            if index == self.ins:
                ins_to_call = getattr(self, ins_name)
                self.format["cmd_name"] = ins_name
                ins_to_call()
                return
        print(f"未知指令: {self.ins}\n")

    def INSTALL(self):
        if self.pa1 == 0xC:
            # install for install and make selectable
            self.format["ins_name"] = "install for install and make selectable"
            self.format["install cmd"] = self.parse_lv(self.data)
            if self.format["install cmd"][4]["length"] != "00":
                self.format["install cmd"][4]["Install Parameters"] = (
                    self.parse_tlv_rec(
                        bytes.fromhex(self.format["install cmd"][4]["value"])
                    )
                )
        elif self.pa1 == 0x2:
            # install for load
            self.format["ins_name"] = "install for load"
            self.format["install cmd"] = self.parse_lv(self.data)
        elif self.pa1 == 0x4:
            # install for install
            self.format["ins_name"] = "install for install"
            self.format["install cmd"] = self.parse_lv(self.data)
            if self.format["install cmd"][4]["length"] != "00":
                self.format["install cmd"][4]["Install Parameters"] = (
                    self.parse_tlv_rec(
                        bytes.fromhex(self.format["install cmd"][4]["value"])
                    )
                )

    def parse_GET_STATUS(self):
        self.format["ins_name"] = "GET_STATUS"
        self.format["cmd"] = self.parse_tlv(self.data)

    def parse_SET_STATUS(self):
        self.format["ins_name"] = "SET_STATUS"
        self.format["aid"] = self.parse_tlv(self.data)

    def parse_LOAD(self):
        self.format["ins_name"] = "LOAD"
        # self.format['parsed_data'] = self.parse_lv(self.data)
