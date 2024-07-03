from apdu_parser.apdu import APDU, RAPDU
from apdu_parser.apdu_error import APDU_CLA_Error, APDU_Parameter_Error
from apdu_parser.tlv.COMPREHENSION_TLV import COMPREHENSION_TLV
from apdu_parser.tlv.BER_TLV import BER_TLV
from apdu_parser.tlv.tlv import TLV_Array
from apdu_parser.tlv.tlv_error import InvalidTagError, TLVError

import datetime


class CAT_COMTLV(COMPREHENSION_TLV):
    def __init__(
        self,
        tag_field: bytes | str,
        length_field: bytes | str,
        value_field: bytes | str,
    ) -> None:
        super().__init__(tag_field, length_field, value_field)
        self.tag_name = None
        self.value_detail = dict()
        self.cat_data_obj_table = {
            0x01: self.Command_details,
            0x02: self.Device_identity,
            0x03: self.Result,
            0x04: self.Duration,
            0x05: self.Alpha_identifier,
            0x06: self.Address,
            0x07: self.Capability_configuration_parameters,
            0x08: self.Subaddress,
            0x09: self.SS_string,
            0x0A: self.USSD_string,
            0x0B: self.SMS_TPDU,
            0x0C: self.Cell_Broadcast_page,
            0x0D: self.Text_string,
            0x0E: self.Tone,
            0x0F: self.Item,
            0x10: self.Item_identifier,
            0x11: self.Response_length,
            0x12: self.File_List,
            0x13: self.Location_Information,
            0x14: self.IMEI,
            0x15: self.Help_request,
            0x16: self.Network_Measurement_Results,
            0x17: self.Default_Text,
            0x18: self.Items_Next_Action_Indicator,
            0x19: self.Event_list,
            0x1A: self.Cause,
            0x1B: self.Location_status,
            0x1C: self.Transaction_identifier,
            0x1D: self.BCCH_channel_list,
            0x1E: self.Icon_identifier,
            0x1F: self.Item_Icon_identifier_list,
            0x20: self.Card_reader_status,
            0x21: self.Card_ATR,
            0x22: self.C_APDU,
            0x23: self.R_APDU,
            0x24: self.Timer_identifier,
            0x25: self.Timer_value,
            0x26: self.Date_Time_and_Time_zone,
            0x27: self.Call_control_requested_action,
            0x28: self.AT_Command,
            0x29: self.AT_Response,
            0x2A: self.BC_Repeat_Indicator,
            0x2B: self.Immediate_response,
            0x2C: self.DTMF_string,
            0x2D: self.Language,
            0x2E: self.Timing_Advance,
            0x2F: self.AID,
            0x30: self.Browser_Identity,
            0x31: self.URL,
            0x32: self.Bearer,
            0x33: self.Provisioning_Reference_File,
            0x34: self.Browser_Termination_Cause,
            0x35: self.Bearer_description,
            0x36: self.Channel_data,
            0x37: self.Channel_data_length,
            0x38: self.Channel_status,
            0x39: self.Buffer_size,
            0x3A: self.Card_reader_identifier,
            0x3B: self.File_Update_Information,
            0x3C: self.UICC_terminal_interface_transport_level,
            0x3D: self.Not_used,
            0x3E: self.data_destination_address,
            0x3F: self.Access_Technology,
            0x40: self.Display_parameters,
            0x41: self.Service_Record,
            0x42: self.Device_Filter,
            0x43: self.Service_Search,
            0x44: self.Attribute_information,
            0x45: self.Service_Availability,
            0x46: self.ESN,
            0x47: self.Network_Access_Name,
            0x48: self.CDMA_SMS_TPDU,
            0x49: self.Remote_Entity_Address,
            0x4A: self.I_WLAN_Identifier,
            0x4B: self.I_WLAN_Access_Status,
            0x50: self.Text_attribute,
            0x51: self.Item_text_attribute_list,
            0x52: self.PDP_context_Activation_parameter,
            0x53: self.Contactless_state_request,
            0x54: self.Contactless_functionality_state,
            0x55: self.CSG_cell_selection_status,
            0x56: self.CSG_ID,
            0x57: self.HNB_name,
            0x62: self.IMEISV,
            0x63: self.Battery_state,
            0x64: self.Browsing_status,
            0x65: self.Network_Search_Mode,
            0x66: self.Frame_Layout,
            0x67: self.Frames_Information,
            0x68: self.Frame_identifier,
            0x69: self.UTRAN_Measurement_Qualifier,
            0x6A: self.Multimedia_Message_Reference,
            0x6B: self.Multimedia_Message_Identifier,
            0x6C: self.Multimedia_Message_Transfer_Status,
            0x6D: self.MEID,
            0x6E: self.Multimedia_Message_Content_Identifier,
            0x6F: self.Multimedia_Message_Notification,
            0x70: self.Last_Envelope,
            0x71: self.Registry_application_data,
            0x72: self.PLMNwAcT_List,
            0x73: self.Routing_Area_Information,
            0x74: self.Update_Attach_Type,
            0x75: self.Rejection_Cause_Code,
            0x76: self.Geographical_Location_Parameters,
            0x77: self.GAD_Shapes,
            0x78: self.NMEA_sentence,
            0x79: self.PLMN_List,
            0x7A: self.Broadcast_Network_Information,
            0x7B: self.ACTIVATE_descriptor,
            0x7C: self.EPS_PDN_connection_activation_parameters,
            0x7D: self.Tracking_Area_Identification,
            0x7E: self.CSG_ID_list,
        }

        if self.tag_number in self.cat_data_obj_table:
            self.cat_data_obj_table[self.tag_number]()
        else:
            raise TLVError("Unkown obj type.")

    def to_dict(self):
        res = dict()
        res["tag_name"] = self.tag_name
        res.update(super().to_dict())
        res.update(self.value_detail)
        return res

    def Command_details(self):
        self.tag_name = "Command_details"
        cat_cmd_type_table = {
            0x01: "REFRESH",
            0x02: "MORE_TIME",
            0x03: "POLL_INTERVAL",
            0x04: "POLLING_OFF",
            0x05: "SET_UP_EVENT_LIST",
            0x10: "SET_UP_CALL",
            0x11: "SEND_SS",
            0x12: "SEND_USSD",
            0x13: "SEND_SHORT_MESSAGE",
            0x14: "SEND_DTMF",
            0x15: "LAUNCH_BROWSER",
            0x20: "PLAY_TONE",
            0x21: "DISPLAY_TEXT",
            0x22: "GET_INKEY",
            0x23: "GET_INPUT",
            0x24: "SELECT_ITEM",
            0x25: "SET_UP_MENU",
            0x26: "PROVIDE_LOCAL_INFORMATION",
            0x27: "TIMER_MANAGEMENT",
            0x28: "SET_UP_IDLE_MODE_TEXT",
            0x30: "PERFORM_CARD_APDU",
            0x31: "POWER_ON_CARD",
            0x32: "POWER_OFF_CARD",
            0x33: "GET_READER_STATUS",
            0x34: "RUN_AT_COMMAND",
            0x35: "LANGUAGE_NOTIFICATION",
            0x40: "OPEN_CHANNEL",
            0x41: "CLOSE_CHANNEL",
            0x42: "RECEIVE_DATA",
            0x43: "SEND_DATA",
            0x44: "GET_CHANNEL_STATUS",
            0x45: "SERVICE_SEARCH",
            0x46: "GET_SERVICE_INFORMATION",
            0x47: "DECLARE_SERVICE",
            0x50: "SET_FRAMES",
            0x51: "GET_FRAMES_STATUS",
            0x60: "RETRIEVE_MULTIMEDIA_MESSAGE",
            0x61: "SUBMIT_MULTIMEDIA_MESSAGE",
            0x62: "DISPLAY_MULTIMEDIA_MESSAGE",
            0x81: "End_of_the_proactive_session",
        }
        if self.get_length() != 3:
            raise TLVError("非法tlv")
        self.value_detail["Command number"] = self.value[0]
        self.value_detail["Type of command"] = cat_cmd_type_table[self.value[1]]
        self.value_detail["Command Qualifier"] = self.value[2]

    def Device_identity(self):
        self.tag_name = "Device_identity"
        if self.get_length() != 2:
            raise TLVError("非法tlv")
        identity_table = {
            0x01: "Keypad",
            0x02: "Display",
            0x03: "Earpiece",
            0x10: "Additional Card Reader 0",
            0x11: "Additional Card Reader 1",
            0x12: "Additional Card Reader 2",
            0x13: "Additional Card Reader 3",
            0x14: "Additional Card Reader 4",
            0x15: "Additional Card Reader 5",
            0x16: "Additional Card Reader 6",
            0x17: "Additional Card Reader 7",
            0x21: "Channel 1 ",
            0x22: "Channel 2 ",
            0x23: "Channel 3 ",
            0x24: "Channel 4 ",
            0x25: "Channel 5 ",
            0x26: "Channel 6 ",
            0x27: "Channel 7 ",
            0x81: "UICC",
            0x82: "terminal",
            0x83: "network",
        }
        self.value_detail["Source device identity"] = identity_table[self.value[0]]
        self.value_detail["Destination device identity"] = identity_table[self.value[1]]

    def Result(self):
        self.tag_name = "Result"
        # todo ...

    def Duration(self):
        self.tag_name = "Duration"
        # todo ...

    def Alpha_identifier(self):
        self.tag_name = "Alpha_identifier"
        if self.value:
            if self.value[0] == 0x80:
                self.value_detail["coded format"] = "UCS2"
                self.value_detail["text"] = self.value[1:].decode("utf-16-be")
            else:
                self.value_detail["text"] = self.value[1:].decode("ascii")

    def Address(self):
        self.tag_name = "Address"
        # todo ...

    def Capability_configuration_parameters(self):
        self.tag_name = "Capability_configuration_parameters"
        # todo ...

    def Subaddress(self):
        self.tag_name = "Subaddress"
        # todo ...

    def SS_string(self):
        self.tag_name = "SS_string"
        # todo ...

    def USSD_string(self):
        self.tag_name = "USSD_string"
        # todo ...

    def SMS_TPDU(self):
        self.tag_name = "SMS_TPDU"
        # ts_123040v180000p clause 9.2
        # first byte
        """first byte of sms tpdu
        |PDU    |bit0   |bit1   |bit2   |bit3   |bit4   | bit5  | bit6  | bit7  |
        |-------|------ |------ |------ |------ |------ |------ |------ |------ |
        |DELIVER|MTI    |MTI    |MMS    |LP     |-      |SRI    |UDHI   |RP     |
        |SUBMIT |MTI    |MTI    |RD     |VPF    |VPF    |SRR    |UDHI   |RP     |
        |COMMAND|MTI    |MTI    |-      |-      |-      |SRR    |UDHI   |-      |
        |STATUS |MTI    |MTI    |MMS    |LP     |-      |SRQ    |UDHI   |-      |
        """
        # TP-Message-Type-Indicator bit 0-1
        tp_mti = self.value[0] & 0x03
        tp_mti_table = {
            0x00: "SMS-DELIVER or SMS-DELIVER-REPORT",
            0x01: "SMS-SUBMIT or SMS-SUBMIT-REPORT",
            0x02: "SMS-COMMAND or SMS-STATUS-REPORT",
            0x03: "reserved",
        }
        if tp_mti in tp_mti_table:
            self.value_detail["TP-Message-Type-Indicator"] = tp_mti_table[tp_mti]
        else:
            self.value_detail["TP-Message-Type-Indicator"] = "reserved"

        # TP-UDHI bit6
        tp_udhi = (self.value[0] & 0x40) >> 6
        self.value_detail["TP-UDHI"] = (
            "Have a User data header"
            if tp_udhi == 1
            else "No user data header"
        )

        # according to TP-Message-Type-Indicator, parse the TPDU
        if tp_mti == 0x00:
            # deliver
            # TP-MMS bit2
            tp_mms = (self.value[0] & 0x04) >> 2
            self.value_detail["TP-More-Messages-to-Send"] = {
                0: "More messages are waiting for the MS in this SC",
                1: "No more messages are waiting for the MS in this SC",
            }[tp_mms]

            # TP-LP bit3
            tp_lp = (self.value[0] & 0x08) >> 3
            self.value_detail["TP-Loop-Prevention"] = {
                0: "No loop prevention",
                1: "Loop prevention",
            }[tp_lp]

            # TP-SRI bit5
            tp_sri = (self.value[0] & 0x20) >> 5
            self.value_detail["TP-Status-Report-Indication"] = {
                0: "A status report is not requested",
                1: "A status report is requested",
            }[tp_sri]

            # TP-RP bit7
            tp_rp = (self.value[0] & 0x80) >> 7
            self.value_detail["TP-Reply-Path"] = {
                0: "No reply path",
                1: "Reply path",
            }[tp_rp]

            # TP-OA 2-12 bytes
            tp_oa_len = 2 + self.value[1]//2 + \
                (1 if self.value[1] % 2 == 1 else 0)
            self.value_detail["TP-Originating-Address"] = self.value[1: 1 + tp_oa_len].hex()
            # tp_oa_type = self.value[2]
            # self.value_detail["TP-OA LEN"] = self.value[1]
            # self.value_detail["TP-OA TYPE"] = self.value[2]
            # self.value_detail["TP-OA VALUE"] = self.value[3:3+tp_oa_len].hex()
            # TP-PID 1 byte
            tp_pid = self.value[1 + tp_oa_len]
            if (tp_pid & 0xC0) >> 6 == 0x00:
                if (tp_pid & 0x20) >> 5 == 0x01:
                    self.value_detail["TP-PID"] = {
                        0x00: "implicit - device type is specific to this SC, or can be concluded on the basis of the address ",
                        0x01: "telex (or teletex reduced to telex format) ",
                        0x02: "group 3 telefax ",
                        0x03: "group 4 telefax ",
                        0x04: "voice telephone (i.e. conversion to speech) ",
                        0x05: "ERMES (European Radio Messaging System) ",
                        0x06: "National Paging system (known to the SC) ",
                        0x07: "Videotex (T.100 [20] /T.101 [21]) ",
                        0x08: "teletex, carrier unspecified ",
                        0x09: "teletex, in PSPDN ",
                        0x0A: "teletex, in CSPDN ",
                        0x0B: "teletex, in analog PSTN ",
                        0x0C: "teletex, in digital ISDN ",
                        0x0D: "UCI (Universal Computer Interface, ETSI DE/PS 3 01-3) ",
                        0x0E: "reserved",
                        0x0F: "reserved",
                        0x10: "a message handling facility (known to the SC) ",
                        0x11: "any public X.400-based message handling system ",
                        0x12: "Internet Electronic Mail ",
                        0x18: "values specific to each SC, usage based on mutual agreement between the SME and the SC ",
                        0x19: "values specific to each SC, usage based on mutual agreement between the SME and the SC ",
                        0x1A: "values specific to each SC, usage based on mutual agreement between the SME and the SC ",
                        0x1B: "values specific to each SC, usage based on mutual agreement between the SME and the SC ",
                        0x1C: "values specific to each SC, usage based on mutual agreement between the SME and the SC ",
                        0x1D: "values specific to each SC, usage based on mutual agreement between the SME and the SC ",
                        0x1E: "values specific to each SC, usage based on mutual agreement between the SME and the SC ",
                        0x1F: "A GSM/UMTS mobile station. The SC converts the SM from the received TP-Data-Coding-Scheme to any data coding scheme supported by that MS",
                    }[tp_pid & 0x1F]
            elif (tp_pid & 0xC0) >> 6 == 0x01:
                if (tp_pid & 0x3F) in [
                    0x00,
                    0x01,
                    0x02,
                    0x03,
                    0x04,
                    0x05,
                    0x06,
                    0x07,
                    0x08,
                    0x1E,
                    0x1F,
                    0x3C,
                    0x3D,
                    0x3E,
                    0x3F,
                ]:
                    self.value_detail["TP-PID"] = {
                        0b000000: "Short Message Type 0 ",
                        0b000001: "Replace Short Message Type 1 ",
                        0b000010: "Replace Short Message Type 2 ",
                        0b000011: "Replace Short Message Type 3 ",
                        0b000100: "Replace Short Message Type 4 ",
                        0b000101: "Replace Short Message Type 5 ",
                        0b000110: "Replace Short Message Type 6 ",
                        0b000111: "Replace Short Message Type 7 ",
                        0b001000: "Device Triggering Short Message ",
                        0b011110: "Enhanced Message Service (Obsolete) ",
                        0b011111: "Return Call Message ",
                        0b111100: "ANSI-136 R-DATA ",
                        0b111101: "ME Data download ",
                        0b111110: "ME De-personalization Short Message ",
                        0b111111: "(U)SIM Data download",
                    }[tp_pid & 0x3F]
                else:
                    self.value_detail["TP-PID"] = tp_pid

            # TP-DCS 1 byte
            tp_dcs = self.value[2 + tp_oa_len]
            if (tp_dcs & 0xC0) >> 6 == 0x00:
                # General Data Coding indication
                if (tp_dcs & 0x20) >> 5 == 0x01:
                    # compressed
                    self.value_detail["TP-DCS"] = tp_dcs
                else:
                    # uncompressed
                    if (tp_dcs & 0x10) >> 4 == 0x00:
                        # no class
                        self.value_detail["TP-DCS"] = {
                            "Coding Group": "General Data Coding indication",
                            "Message Class": "No Class",
                            "Message coding": {
                                0b00: "GSM 7 bit default alphabet ",
                                0b01: "8 bit data ",
                                0b10: "UCS2 (16bit)",
                                0b11: "Reserved ",
                            }[(tp_dcs & 0x0c) >> 2]
                        }
                    else:
                        # have class
                        self.value_detail["TP-DCS"] = {
                            "Coding Group": "General Data Coding indication",
                            "Message Class": {
                                0b00: "Class 0 ",
                                0b01: "Class 1 Default meaning: ME-specific. ",
                                0b10: "Class 2 (U)SIM specific message ",
                                0b11: "Class 3 Default meaning: TE specific (see 3GPP TS 27.005)",
                            }[tp_dcs & 0x03],
                            "Message coding": {
                                0b00: "GSM 7 bit default alphabet ",
                                0b01: "8 bit data ",
                                0b10: "UCS2 (16bit)",
                                0b11: "Reserved ",
                            }[(tp_dcs & 0x0c) >> 2]
                        }
            elif (tp_dcs & 0xC0) >> 6 == 0x01:
                self.value_detail["TP-DCS"] = hex(tp_dcs)
            if (tp_dcs & 0xF0) >> 4 == 0b1100:
                self.value_detail["TP-DCS"] = hex(tp_dcs)
            elif (tp_dcs & 0xF0) >> 4 == 0b1101:
                self.value_detail["TP-DCS"] = hex(tp_dcs)
            elif (tp_dcs & 0xF0) >> 4 == 0b1110:
                self.value_detail["TP-DCS"] = hex(tp_dcs)
            elif (tp_dcs & 0xF0) >> 4 == 0b1111:
                self.value_detail["TP-DCS"] = {
                    "Coding Group": "Data coding/message class",
                    "Message Class": {
                        0b00: "Class 0 ",
                        0b01: "Class 1 Default meaning: ME-specific. ",
                        0b10: "Class 2 (U)SIM specific message ",
                        0b11: "Class 3 Default meaning: TE specific (see 3GPP TS 27.005)",
                    }[tp_dcs & 0x03],
                    "Message coding": {
                        0b00: "GSM 7 bit default alphabet ",
                        0b01: "8 bit data ",
                        0b10: "UCS2 (16bit)",
                        0b11: "Reserved ",
                    }[(tp_dcs & 0x0c) >> 2]
                }
            # TP-SCTS 7 bytes
            tp_scts = self.value[3 + tp_oa_len: 10 + tp_oa_len]
            self.value_detail["TP-Service-Centre-Time-Stamp"] = (
                f"20{tp_scts[0:1].hex()[-1::-1]}年{tp_scts[1:2].hex()[-1::-1]}月{tp_scts[2:3].hex()[-1::-1]}日 {tp_scts[3:4].hex()[-1::-1]}:{tp_scts[4:5].hex()[-1::-1]}:{tp_scts[5:6].hex()[-1::-1]}"
            )

            # TP-UDL 1 byte
            tp_udl = self.value[10 + tp_oa_len]
            self.value_detail["TP-User-Data-Length"] = tp_udl

            # TP-UD 0-140 bytes
            tp_ud = self.value[11 + tp_oa_len: 11 + tp_oa_len + tp_udl]
            self.value_detail["TP-User-Data"] = tp_ud.hex()

        elif tp_mti == 0x01:
            # submit
            tp_rd = (self.value[0] & 0x04) >> 2
            self.value_detail["TP-RD"] = (
                "Reject duplicates" if tp_rd == 1 else "Accept duplicates"
            )

            tp_vpf = (self.value[0] & 0x18) >> 3
            self.value_detail["TP-VPF"] = {
                0x00: "No VP field",
                0x01: "Relative format",
                0x02: "Enhanced format",
                0x03: "reserved",
            }[tp_vpf]

            tp_rp = (self.value[0] & 0x20) >> 5
            self.value_detail["TP-RP"] = "Reply path" if tp_rp == 1 else "No reply path"

            tp_srr = (self.value[0] & 0x80) >> 7
            self.value_detail["TP-SRR"] = (
                "Status report requested"
                if tp_srr == 1
                else "No status report requested"
            )
            tp_mr = self.value[1]
            self.value_detail["TP-MR"] = tp_mr

            # TP-DA add_len(1byte) add_type(1byte) add_value(add_len//2 bytes) 长度是指十六位数的个数，所以要除以2
            tp_da_len = 1 + 1+self.value[2]//2 + \
                (1 if self.value[2] % 2 == 1 else 0)
            self.value_detail["TP-DA"] = self.value[2: 2 + tp_da_len].hex()
            # self.value_detail["TP-DA LEN"] = self.value[2]
            # self.value_detail["TP-DA TYPE"] = self.value[3]
            # self.value_detail["TP-DA VALUE"] = self.value[4:4+tp_da_len].hex()
            tp_pid = self.value[2 + tp_da_len]
            if (tp_pid & 0xC0) >> 6 == 0x00:
                if (tp_pid & 0x20) >> 5 == 0x01:
                    self.value_detail["TP-PID"] = {
                        0x00: "implicit - device type is specific to this SC, or can be concluded on the basis of the address ",
                        0x01: "telex (or teletex reduced to telex format) ",
                        0x02: "group 3 telefax ",
                        0x03: "group 4 telefax ",
                        0x04: "voice telephone (i.e. conversion to speech) ",
                        0x05: "ERMES (European Radio Messaging System) ",
                        0x06: "National Paging system (known to the SC) ",
                        0x07: "Videotex (T.100 [20] /T.101 [21]) ",
                        0x08: "teletex, carrier unspecified ",
                        0x09: "teletex, in PSPDN ",
                        0x0A: "teletex, in CSPDN ",
                        0x0B: "teletex, in analog PSTN ",
                        0x0C: "teletex, in digital ISDN ",
                        0x0D: "UCI (Universal Computer Interface, ETSI DE/PS 3 01-3) ",
                        0x0E: "reserved",
                        0x0F: "reserved",
                        0x10: "a message handling facility (known to the SC) ",
                        0x11: "any public X.400-based message handling system ",
                        0x12: "Internet Electronic Mail ",
                        0x18: "values specific to each SC, usage based on mutual agreement between the SME and the SC ",
                        0x19: "values specific to each SC, usage based on mutual agreement between the SME and the SC ",
                        0x1A: "values specific to each SC, usage based on mutual agreement between the SME and the SC ",
                        0x1B: "values specific to each SC, usage based on mutual agreement between the SME and the SC ",
                        0x1C: "values specific to each SC, usage based on mutual agreement between the SME and the SC ",
                        0x1D: "values specific to each SC, usage based on mutual agreement between the SME and the SC ",
                        0x1E: "values specific to each SC, usage based on mutual agreement between the SME and the SC ",
                        0x1F: "A GSM/UMTS mobile station. The SC converts the SM from the received TP-Data-Coding-Scheme to any data coding scheme supported by that MS",
                    }[tp_pid & 0x1F]
                else:
                    self.value_detail["TP-PID"] = tp_pid
            elif (tp_pid & 0xC0) >> 6 == 0x01:
                if (tp_pid & 0x3F) in [
                    0x00,
                    0x01,
                    0x02,
                    0x03,
                    0x04,
                    0x05,
                    0x06,
                    0x07,
                    0x08,
                    0x1E,
                    0x1F,
                    0x3C,
                    0x3D,
                    0x3E,
                    0x3F,
                ]:
                    self.value_detail["TP-PID"] = {
                        0b000000: "Short Message Type 0 ",
                        0b000001: "Replace Short Message Type 1 ",
                        0b000010: "Replace Short Message Type 2 ",
                        0b000011: "Replace Short Message Type 3 ",
                        0b000100: "Replace Short Message Type 4 ",
                        0b000101: "Replace Short Message Type 5 ",
                        0b000110: "Replace Short Message Type 6 ",
                        0b000111: "Replace Short Message Type 7 ",
                        0b001000: "Device Triggering Short Message ",
                        0b011110: "Enhanced Message Service (Obsolete) ",
                        0b011111: "Return Call Message ",
                        0b111100: "ANSI-136 R-DATA ",
                        0b111101: "ME Data download ",
                        0b111110: "ME De-personalization Short Message ",
                        0b111111: "(U)SIM Data download",
                    }[tp_pid & 0x3F]
                else:
                    self.value_detail["TP-PID"] = tp_pid
            else:
                self.value_detail["TP-PID"] = tp_pid

            tp_dcs = self.value[3 + tp_da_len]
            if (tp_dcs & 0xC0) >> 6 == 0x00:
                # General Data Coding indication
                if (tp_dcs & 0x20) >> 5 == 0x01:
                    # compressed
                    self.value_detail["TP-DCS"] = tp_dcs
                else:
                    # uncompressed
                    if (tp_dcs & 0x10) >> 4 == 0x00:
                        # no class
                        self.value_detail["TP-DCS"] = {
                            "Coding Group": "General Data Coding indication",
                            "Message Class": "No Class",
                            "Message coding": {
                                0b00: "GSM 7 bit default alphabet ",
                                0b01: "8 bit data ",
                                0b10: "UCS2 (16bit)",
                                0b11: "Reserved ",
                            }[(tp_dcs & 0x0c) >> 2]
                        }
                    else:
                        # have class
                        self.value_detail["TP-DCS"] = {
                            "Coding Group": "General Data Coding indication",
                            "Message Class": {
                                0b00: "Class 0 ",
                                0b01: "Class 1 Default meaning: ME-specific. ",
                                0b10: "Class 2 (U)SIM specific message ",
                                0b11: "Class 3 Default meaning: TE specific (see 3GPP TS 27.005)",
                            }[tp_dcs & 0x03],
                            "Message coding": {
                                0b00: "GSM 7 bit default alphabet ",
                                0b01: "8 bit data ",
                                0b10: "UCS2 (16bit)",
                                0b11: "Reserved ",
                            }[(tp_dcs & 0x0c) >> 2]
                        }
            elif (tp_dcs & 0xC0) >> 6 == 0x01:
                self.value_detail["TP-DCS"] = hex(tp_dcs)
            if (tp_dcs & 0xF0) >> 4 == 0b1100:
                self.value_detail["TP-DCS"] = hex(tp_dcs)
            elif (tp_dcs & 0xF0) >> 4 == 0b1101:
                self.value_detail["TP-DCS"] = hex(tp_dcs)
            elif (tp_dcs & 0xF0) >> 4 == 0b1110:
                self.value_detail["TP-DCS"] = hex(tp_dcs)
            elif (tp_dcs & 0xF0) >> 4 == 0b1111:
                self.value_detail["TP-DCS"] = {
                    "Coding Group": "Data coding/message class",
                    "Message Class": {
                        0b00: "Class 0 ",
                        0b01: "Class 1 Default meaning: ME-specific. ",
                        0b10: "Class 2 (U)SIM specific message ",
                        0b11: "Class 3 Default meaning: TE specific (see 3GPP TS 27.005)",
                    }[tp_dcs & 0x03],
                    "Message coding": {
                        0b00: "GSM 7 bit default alphabet ",
                        0b01: "8 bit data ",
                        0b10: "UCS2 (16bit)",
                        0b11: "Reserved ",
                    }[(tp_dcs & 0x0c) >> 2]
                }
            elif (tp_dcs & 0xC0) >> 6 == 0x01:
                self.value_detail["TP-DCS"] = tp_dcs
            if (tp_dcs & 0xF0) >> 4 == 0b1100:
                self.value_detail["TP-DCS"] = tp_dcs
            elif (tp_dcs & 0xF0) >> 4 == 0b1101:
                self.value_detail["TP-DCS"] = tp_dcs
            elif (tp_dcs & 0xF0) >> 4 == 0b1110:
                self.value_detail["TP-DCS"] = tp_dcs
            elif (tp_dcs & 0xF0) >> 4 == 0b1111:
                self.value_detail["TP-DCS"] = tp_dcs

            if tp_vpf == 0x01:
                # 相对时间
                tp_vp_len = 1
                tp_vp = self.value[3+tp_vp_len + tp_da_len]
                if tp_vp < 144:
                    tp_vp_secs = (tp_vp + 1) * 5 * \
                        datetime.timedelta(minutes=1)
                elif tp_vp < 167:
                    tp_vp_secs = datetime.timedelta(hours=12) + (
                        tp_vp - 143
                    ) * 30 * datetime.timedelta(minutes=1)
                elif tp_vp < 197:
                    tp_vp_secs = (tp_vp - 166) * 1 * datetime.timedelta(days=1)
                else:
                    tp_vp_secs = (tp_vp - 192) * 1 * datetime.timedelta(days=7)
                tp_vp_secs = int(tp_vp_secs.total_seconds())
                tp_vp_year, tp_vp_secs = divmod(tp_vp_secs, 31536000)
                tp_vp_month, tp_vp_secs = divmod(tp_vp_secs, 2592000)
                tp_vp_day, tp_vp_secs = divmod(tp_vp_secs, 86400)
                tp_vp_hour, tp_vp_secs = divmod(tp_vp_secs, 3600)
                tp_vp_minute, tp_vp_secs = divmod(tp_vp_secs, 60)
                self.value_detail["TP-VP"] = (
                    f"{tp_vp_year}年{tp_vp_month}月{tp_vp_day}日{tp_vp_hour}时{tp_vp_minute}分{tp_vp_secs}秒"
                )
            elif tp_vpf == 0x02:
                # 绝对时间
                tp_vp_len = 7
                self.value_detail["TP-VP"] = (
                    f"{tp_vp[6]}年{tp_vp[5]}月{tp_vp[4]}日{tp_vp[3]}时{tp_vp[2]}分{tp_vp[1]}秒"
                )
            elif tp_vpf == 0x03:
                # todo增强格式
                tp_vp_len = 7
                self.value_detail["TP-VP"] = tp_vp
            else:
                tp_vp_len = 0
            tp_udl = self.value[tp_da_len + 4 + tp_vp_len]
            self.value_detail["TP-UDL"] = tp_udl
            tp_ud = self.value[
                tp_da_len + 5 + tp_vp_len: tp_da_len + 5 + tp_vp_len + tp_udl
            ]
            if (tp_dcs & 0x10) >> 4 != 0x00:
                if (tp_dcs & 0x03) >> 2 == 0x00:
                    self.value_detail["TP-UD"] = tp_ud.decode("ascii")
                elif (tp_dcs & 0x03) >> 2 == 0x01:
                    self.value_detail["TP-UD"] = tp_ud.hex()
                elif (tp_dcs & 0x03) >> 2 == 0x02:
                    self.value_detail["TP-UD"] = tp_ud.decode("utf-16-be")
                else:
                    self.value_detail["TP-UD"] = tp_ud.hex()
            else:
                self.value_detail["TP-UD"] = tp_ud.hex()

        elif tp_mti == 0x02:
            tp_mr = self.value[1]
            self.value_detail["TP-MR"] = tp_mr
            tp_pid = self.value[2]
            self.value_detail["TP-PID"] = tp_pid
            tp_ct = self.value[3]
            if tp_ct < 4:
                self.value_detail["TP-CT"] = {
                    0x00: "Enquiry relating to previously submitted short message ",
                    0x01: "Cancel Status Report Request relating to previously submitted short message",
                    0x02: "Delete previously submitted Short Message",
                    0x03: "Enable Status Report Request relating to previously submitted short message",
                }[tp_ct]
            elif tp_ct >= 0xE0:
                self.value_detail["TP-CT"] = "Values specific for each SC "
            else:
                self.value_detail["TP-CT"] = f"{tp_ct} : Reserved"

            tp_mn = self.value[4]
            self.value_detail["TP-MN"] = tp_mn
            tp_da_len = self.value[5]
            self.value_detail["TP-DA"] = self.value[6: 6 + tp_da_len].hex()
            tp_cdl = self.value[6 + tp_da_len]
            self.value_detail["TP-CDL"] = tp_cdl.hex()
        else:
            pass

    def Cell_Broadcast_page(self):
        self.tag_name = "Cell_Broadcast_page"
        # todo ...

    def Text_string(self):
        self.tag_name = "Text_string"
        coding_table = {
            0x00: "GSM default alphabet 7 bits packed",
            0x04: "GSM default alphabet 8 bits",
            0x08: "UCS2",
        }
        self.value_detail["Data coding scheme"] = coding_table[self.value[0]]
        if self.value[0] == 0x08:
            self.value_detail["text"] = (
                self.value[1:].decode(
                    "utf-16-be").encode("utf-8").decode("utf-8")
            )
        elif self.value[0] == 0x04:
            self.value_detail["text"] = self.value[1:].decode("ascii")

    def Tone(self):
        self.tag_name = "Tone"
        # todo ...

    def Item(self):
        self.tag_name = "Item"
        self.value_detail["Identifier of item"] = self.value[0]
        if self.value[1] == 0x80:
            self.value_detail["coded format"] = "UCS2"
            self.value_detail["text"] = self.value[2:].decode("utf-16-be")
        else:
            self.value_detail["text"] = self.value[2:].decode("ascii")

    def Item_identifier(self):
        self.tag_name = "Item_identifier"
        # todo ...

    def Response_length(self):
        self.tag_name = "Response_length"
        # todo ...

    def File_List(self):
        self.tag_name = "File_List"
        # todo ...

    def Location_Information(self):
        self.tag_name = "Location_Information"
        # todo ...

    def IMEI(self):
        self.tag_name = "IMEI"
        # todo ...

    def Help_request(self):
        self.tag_name = "Help_request"
        # todo ...

    def Network_Measurement_Results(self):
        self.tag_name = "Network_Measurement_Results"
        # todo ...

    def Default_Text(self):
        self.tag_name = "Default_Text"
        # todo ...

    def Items_Next_Action_Indicator(self):
        self.tag_name = "Items_Next_Action_Indicator"
        # todo ...

    def Event_list(self):
        self.tag_name = "Event_list"
        event_list_table = {
            0x00: "MT call",
            0x01: "Call connected",
            0x02: "Call disconnected",
            0x03: "Location status",
            0x04: "User activity",
            0x05: "Idle screen available",
            0x06: "Card reader status",
            0x07: "Language selection",
            0x08: "Browser termination",
            0x09: "Data available",
            0x0A: "Channel status",
            0x0B: "Access Technology Change (single access technology)",
            0x0C: "Display parameters changed",
            0x0D: "Local connection",
            0x0E: "Network Search Mode Change",
            0x0F: "Browsing status",
            0x10: "Frames Information Change",
            0x11: "Reserved for 3GPP (I-WLAN Access Status)",
            0x12: "Reserved for 3GPP (Network Rejection)",
            0x13: "HCI connectivity event",
            0x14: "Access Technology Change (multiple access technologies)",
            0x15: "Reserved for 3GPP (CSG cell selection)",
            0x16: "Contactless state request",
            0x17: "Reserved for 3GPP (IMS Registration)",
            0x18: "Reserved for 3GPP (IMS Incoming data)",
            0x19: "Profile Container",
            0x1A: "Void",
            0x1B: "Secured Profile Container",
            0x1C: "Poll Interval Negotiation",
            0x1D: "Reserved for 3GPP (Data Connection Status Change)",
            0x1E: "Reserved for 3GPP (CAG cell selection)",
            0x1F: "Reserved for 3GPP (for future usage)",
            0x20: "Reserved for 3GPP (for future usage)",
            0x21: "Reserved for 3GPP (for future usage)",
            0x22: "Reserved for 3GPP (for future usage)",
        }
        self.value_detail["Event list"] = [
            event_list_table[self.value[i]] for i in range(self.get_length())
        ]

    def Cause(self):
        self.tag_name = "Cause"
        # todo ...

    def Location_status(self):
        self.tag_name = "Location_status"
        # todo ...

    def Transaction_identifier(self):
        self.tag_name = "Transaction_identifier"
        # todo ...

    def BCCH_channel_list(self):
        self.tag_name = "BCCH_channel_list"
        # todo ...

    def Icon_identifier(self):
        self.tag_name = "Icon_identifier"
        # todo ...

    def Item_Icon_identifier_list(self):
        self.tag_name = "Item_Icon_identifier_list"
        # todo ...

    def Card_reader_status(self):
        self.tag_name = "Card_reader_status"
        # todo ...

    def Card_ATR(self):
        self.tag_name = "Card_ATR"
        # todo ...

    def C_APDU(self):
        self.tag_name = "C_APDU"
        # todo ...

    def R_APDU(self):
        self.tag_name = "R_APDU"
        # todo ...

    def Timer_identifier(self):
        self.tag_name = "Timer_identifier"
        # todo ...

    def Timer_value(self):
        self.tag_name = "Timer_value"
        # todo ...

    def Date_Time_and_Time_zone(self):
        self.tag_name = "Date_Time_and_Time_zone"
        # todo ...

    def Call_control_requested_action(self):
        self.tag_name = "Call_control_requested_action"
        # todo ...

    def AT_Command(self):
        self.tag_name = "AT_Command"
        # todo ...

    def AT_Response(self):
        self.tag_name = "AT_Response"
        # todo ...

    def BC_Repeat_Indicator(self):
        self.tag_name = "BC_Repeat_Indicator"
        # todo ...

    def Immediate_response(self):
        self.tag_name = "Immediate_response"
        # todo ...

    def DTMF_string(self):
        self.tag_name = "DTMF_string"
        # todo ...

    def Language(self):
        self.tag_name = "Language"
        # todo ...

    def Timing_Advance(self):
        self.tag_name = "Timing_Advance"
        # todo ...

    def AID(self):
        self.tag_name = "AID"
        # todo ...

    def Browser_Identity(self):
        self.tag_name = "Browser_Identity"
        # todo ...

    def URL(self):
        self.tag_name = "URL"
        # todo ...

    def Bearer(self):
        self.tag_name = "Bearer"
        # todo ...

    def Provisioning_Reference_File(self):
        self.tag_name = "Provisioning_Reference_File"
        # todo ...

    def Browser_Termination_Cause(self):
        self.tag_name = "Browser_Termination_Cause"
        # todo ...

    def Bearer_description(self):
        self.tag_name = "Bearer_description"
        # todo ...

    def Channel_data(self):
        self.tag_name = "Channel_data"
        # todo ...

    def Channel_data_length(self):
        self.tag_name = "Channel_data_length"
        # todo ...

    def Channel_status(self):
        self.tag_name = "Channel_status"
        # todo ...

    def Buffer_size(self):
        self.tag_name = "Buffer_size"
        # todo ...

    def Card_reader_identifier(self):
        self.tag_name = "Card_reader_identifier"
        # todo ...

    def File_Update_Information(self):
        self.tag_name = "File_Update_Information"
        # todo ...

    def UICC_terminal_interface_transport_level(self):
        self.tag_name = "UICC_terminal_interface_transport_level"
        # todo ...

    def Not_used(self):
        self.tag_name = "Not_used"
        # todo ...

    def data_destination_address(self):
        self.tag_name = "data_destination_address"
        # todo ...

    def Access_Technology(self):
        self.tag_name = "Access_Technology"
        # todo ...

    def Display_parameters(self):
        self.tag_name = "Display_parameters"
        # todo ...

    def Service_Record(self):
        self.tag_name = "Service_Record"
        # todo ...

    def Device_Filter(self):
        self.tag_name = "Device_Filter"
        # todo ...

    def Service_Search(self):
        self.tag_name = "Service_Search"
        # todo ...

    def Attribute_information(self):
        self.tag_name = "Attribute_information"
        # todo ...

    def Service_Availability(self):
        self.tag_name = "Service_Availability"
        # todo ...

    def ESN(self):
        self.tag_name = "ESN"
        # todo ...

    def Network_Access_Name(self):
        self.tag_name = "Network_Access_Name"
        # todo ...

    def CDMA_SMS_TPDU(self):
        self.tag_name = "CDMA_SMS_TPDU"
        # todo ...

    def Remote_Entity_Address(self):
        self.tag_name = "Remote_Entity_Address"
        # todo ...

    def I_WLAN_Identifier(self):
        self.tag_name = "I_WLAN_Identifier"
        # todo ...

    def I_WLAN_Access_Status(self):
        self.tag_name = "I_WLAN_Access_Status"
        # todo ...

    def Text_attribute(self):
        self.tag_name = "Text_attribute"
        # todo ...

    def Item_text_attribute_list(self):
        self.tag_name = "Item_text_attribute_list"
        # todo ...

    def PDP_context_Activation_parameter(self):
        self.tag_name = "PDP_context_Activation_parameter"
        # todo ...

    def Contactless_state_request(self):
        self.tag_name = "Contactless_state_request"
        # todo ...

    def Contactless_functionality_state(self):
        self.tag_name = "Contactless_functionality_state"
        # todo ...

    def CSG_cell_selection_status(self):
        self.tag_name = "CSG_cell_selection_status"
        # todo ...

    def CSG_ID(self):
        self.tag_name = "CSG_ID"
        # todo ...

    def HNB_name(self):
        self.tag_name = "HNB_name"
        # todo ...

    def IMEISV(self):
        self.tag_name = "IMEISV"
        # todo ...

    def Battery_state(self):
        self.tag_name = "Battery_state"
        # todo ...

    def Browsing_status(self):
        self.tag_name = "Browsing_status"
        # todo ...

    def Network_Search_Mode(self):
        self.tag_name = "Network_Search_Mode"
        # todo ...

    def Frame_Layout(self):
        self.tag_name = "Frame_Layout"
        # todo ...

    def Frames_Information(self):
        self.tag_name = "Frames_Information"
        # todo ...

    def Frame_identifier(self):
        self.tag_name = "Frame_identifier"
        # todo ...

    def UTRAN_Measurement_Qualifier(self):
        self.tag_name = "UTRAN_Measurement_Qualifier"
        # todo ...

    def Multimedia_Message_Reference(self):
        self.tag_name = "Multimedia_Message_Reference"
        # todo ...

    def Multimedia_Message_Identifier(self):
        self.tag_name = "Multimedia_Message_Identifier"
        # todo ...

    def Multimedia_Message_Transfer_Status(self):
        self.tag_name = "Multimedia_Message_Transfer_Status"
        # todo ...

    def MEID(self):
        self.tag_name = "MEID"
        # todo ...

    def Multimedia_Message_Content_Identifier(self):
        self.tag_name = "Multimedia_Message_Content_Identifier"
        # todo ...

    def Multimedia_Message_Notification(self):
        self.tag_name = "Multimedia_Message_Notification"
        # todo ...

    def Last_Envelope(self):
        self.tag_name = "Last_Envelope"
        # todo ...

    def Registry_application_data(self):
        self.tag_name = "Registry_application_data"
        # todo ...

    def PLMNwAcT_List(self):
        self.tag_name = "PLMNwAcT_List"
        # todo ...

    def Routing_Area_Information(self):
        self.tag_name = "Routing_Area_Information"
        # todo ...

    def Update_Attach_Type(self):
        self.tag_name = "Update_Attach_Type"
        # todo ...

    def Rejection_Cause_Code(self):
        self.tag_name = "Rejection_Cause_Code"
        # todo ...

    def Geographical_Location_Parameters(self):
        self.tag_name = "Geographical_Location_Parameters"
        # todo ...

    def GAD_Shapes(self):
        self.tag_name = "GAD_Shapes"
        # todo ...

    def NMEA_sentence(self):
        self.tag_name = "NMEA_sentence"
        # todo ...

    def PLMN_List(self):
        self.tag_name = "PLMN_List"
        # todo ...

    def Broadcast_Network_Information(self):
        self.tag_name = "Broadcast_Network_Information"
        # todo ...

    def ACTIVATE_descriptor(self):
        self.tag_name = "ACTIVATE_descriptor"
        # todo ...

    def EPS_PDN_connection_activation_parameters(self):
        self.tag_name = "EPS_PDN_connection_activation_parameters"
        # todo ...

    def Tracking_Area_Identification(self):
        self.tag_name = "Tracking_Area_Identification"
        # todo ...

    def CSG_ID_list(self):
        self.tag_name = "CSG_ID_list"
        # todo ...


class TelcomAPDU(APDU):
    def __init__(self, apdu_cmd: bytes | str) -> None:
        super().__init__(apdu_cmd)

        self.ins_table_tel = {
            0x04: self.DEACTIVATE_FILE,
            0x10: self.TERMINAL_PROFILE,
            0x12: self.FETCH,
            0x14: self.TERMINAL_RESPONSE,
            0x20: self.VERIFY,
            0x24: self.CHANGE_PIN,
            0x26: self.DISABLE_PIN,
            0x28: self.ENABLE_PIN,
            0x2C: self.UNBLOCK_PIN,
            0x32: self.INCREASE,
            0x44: self.ACTIVATE_FILE,
            0x70: self.MANAGE_CHANNEL,
            0x84: self.GET_CHALLENGE,
            0x88: self.AUTHENTICATE,
            0x89: self.AUTHENTICATE,
            0xA4: self.SELECT_FILE,
            0xA2: self.SEARCH_RECORD,
            0xB0: self.READ_BINARY,
            0xB2: self.READ_RECORD,
            0xC2: self.ENVELOPE,
            0xCB: self.RETRIEVE_DATA,
            0xD6: self.UPDATE_BINARY,
            0xDB: self.SET_DATA,
            0xDC: self.UPDATE_RECORD,
            0xF2: self.STATUS,
        }
        self.ins_table.update(self.ins_table_tel)
        self.parse_cla()
        self.parse_ins()

    def parse_cla(self):
        super().parse_cla()
        if (self.cla & 0xE0 == 0x80) or (self.cla & 0xE0 == 0xA0):
            self.cla_name = "TLECOM"
        else:
            raise APDU_CLA_Error(self.cla, "Unknown cla")

    def TERMINAL_PROFILE(self):
        self.ins_name = "TERMINAL PROFILE"
        self.data_detail = {
            "Download": "{:02X}".format(self.data[0]),
            "Other": "{:02X}".format(self.data[1]),
            "Proactive UICC0": "{:02X}".format(self.data[2]),
            "Proactive UICC1": "{:02X}".format(self.data[3]),
            "Event driven information": "{:02X}".format(self.data[4]),
            "Event driven information extensions": "{:02X}".format(self.data[5]),
            "Multiple card proactive commands": "{:02X}".format(self.data[6]),
            "Proactive UICC2": "{:02X}".format(self.data[7]),
            "Ninth byte": "{:02X}".format(self.data[8]),
            'Soft keys support for class "d"': "{:02X}".format(self.data[9]),
            "Soft keys information": "{:02X}".format(self.data[10]),
            'Bearer Independent protocol proactive commands, class "e"': "{:02X}".format(
                self.data[11]
            ),
            'Bearer Independent protocol supported bearers, class "e"': "{:02X}".format(
                self.data[12]
            ),
            "Screen height": "{:02X}".format(self.data[13]),
            "Screen width": "{:02X}".format(self.data[14]),
            "Screen effects": "{:02X}".format(self.data[15]),
            'Bearer independent protocol supported transport interface/bearers, class "e"': "{:02X}".format(
                self.data[16]
            ),
            "Eighteenth byte": "{:02X}".format(self.data[17]),
            "reserved for TIA/EIA-136-C facilities [25]": "{:02X}".format(
                self.data[18]
            ),
            "reserved for 3GPP2 C.S0035-B CCAT [47]": "{:02X}".format(self.data[19]),
            'Extended Launch Browser Capability for class "ac"': "{:02X}".format(
                self.data[20]
            ),
            "Twenty-second byte": "{:02X}".format(self.data[21]),
            "Twenty third byte": "{:02X}".format(self.data[22]),
            'Twenty fourth byte for class "i"': "{:02X}".format(self.data[23]),
            "Twenty-fifth byte (Event driven information extensions)": "{:02X}".format(
                self.data[24]
            ),
            "Event driven information extensions0": "{:02X}".format(self.data[25]),
            "Event driven information extensions1": "{:02X}".format(self.data[26]),
            "Text attributes0": "{:02X}".format(self.data[27]),
            "Text attributes1": "{:02X}".format(self.data[28]),
            "Thirtieth byte": "{:02X}".format(self.data[29]),
        }

    def FETCH(self):
        if self.pa1 != 0x00 or self.pa2 != 0x00:
            raise APDU_Parameter_Error(
                self.pa1, self.pa2, "parameters must be 0")
        # todo 添加RAPDU的联动

    def TERMINAL_RESPONSE(self):
        if self.pa1 != 0x00 or self.pa2 != 0x00:
            raise APDU_Parameter_Error(
                self.pa1, self.pa2, "parameters must be 0")
        try:
            self.data_detail = TLV_Array.from_bytes(
                self.data, CAT_COMTLV
            )
        except Exception as e:
            raise e

    def ENVELOPE(self):
        self.cat_templete_table: dict[int, CAT_Templete] = {
            # 0xCF: Reserved_for_proprietary_use,
            # 0xD0: Proactive_Command,
            0xD1: SMS_PP_Download,
            # 0xD2: Cell_Broadcast_Download,
            0xD3: Menu_Selection,
            0xD4: Call_Control,
            # 0xD5: Short_Message_control,
            0xD6: Event_Download,
            0xD7: Timer_Expiration,
            # 0xD8: Reserved_for_intra-UICC_communication_and_not_visible_on_the_card_interface,
            # 0xD9: 3G_USSD_Download,
            # 0xDA: MMS_Transfer_status,
            # 0xDB: MMS_notification_download,
            # 0xDC: Terminal_application_tag,
            # 0xDD: 3G_Geographical_Location_Reporting_tag,
        }

        self.data_detail = (
            self.cat_templete_table[CAT_Templete.from_bytes(self.data).tag[0]]
            .from_bytes(self.data)
            .to_dict()
        )

    def CHANGE_PIN(self):
        pass

    def DISABLE_PIN(self):
        pass

    def ENABLE_PIN(self):
        pass

    def UNBLOCK_PIN(self):
        pass

    def INCREASE(self):
        pass

    def AUTHENTICATE(self):
        pass

    def SELECT_FILE(self):
        pass

    def RETRIEVE_DATA(self):
        pass

    def SET_DATA(self):
        pass

    def STATUS(self):
        pass


class CAT_Templete(BER_TLV):
    def __init__(
        self,
        tag_field: bytes | str,
        length_field: bytes | str,
        value_field: bytes | str,
    ) -> None:
        super().__init__(tag_field, length_field, value_field)
        self.constructed_value = TLV_Array.from_bytes(
            self.value, COMPREHENSION_TLV).get_tlv_list()
        self.value_detail = dict()

    def to_dict(self):
        res = super().to_dict()
        res.update(self.value_detail)
        return res


class SMS_PP_Download(CAT_Templete):
    def __init__(
        self,
        tag_field: bytes | str,
        length_field: bytes | str,
        value_field: bytes | str,
    ) -> None:
        super().__init__(tag_field, length_field, value_field)
        if self.tag[0] != 0xD1:
            raise InvalidTagError("SMS_PP_Download tag should be 0xd1")
        self.constructed_value = TLV_Array.from_bytes(
            self.value, CAT_COMTLV
        ).get_tlv_list()


class Menu_Selection(CAT_Templete):
    def __init__(
        self,
        tag_field: bytes | str,
        length_field: bytes | str,
        value_field: bytes | str,
    ) -> None:
        super().__init__(tag_field, length_field, value_field)
        if self.tag[0] != 0xD3:
            raise InvalidTagError("Menu_Selection tag should be 0xd3")
        self.constructed_value = TLV_Array.from_bytes(
            self.value, COMPREHENSION_TLV).get_tlv_list()


class Call_Control(CAT_Templete):
    def __init__(
        self,
        tag_field: bytes | str,
        length_field: bytes | str,
        value_field: bytes | str,
    ) -> None:
        super().__init__(tag_field, length_field, value_field)
        pass

    # todo...


class Event_Download(CAT_Templete):
    def __init__(
        self,
        tag_field: bytes | str,
        length_field: bytes | str,
        value_field: bytes | str,
    ) -> None:
        super().__init__(tag_field, length_field, value_field)
        pass

    # todo...


class Timer_Expiration(CAT_Templete):
    def __init__(
        self,
        tag_field: bytes | str,
        length_field: bytes | str,
        value_field: bytes | str,
    ) -> None:
        super().__init__(tag_field, length_field, value_field)
        pass

    # todo...


class Proactive_Command(RAPDU):
    def __init__(self, data: str | bytes):
        super().__init__(data)
        self.cmd_type = None
        self.cat_cmd_type_table = {
            0x01: self.REFRESH,
            0x02: self.MORE_TIME,
            0x03: self.POLL_INTERVAL,
            0x04: self.POLLING_OFF,
            0x05: self.SET_UP_EVENT_LIST,
            0x10: self.SET_UP_CALL,
            0x11: self.SEND_SS,
            0x12: self.SEND_USSD,
            0x13: self.SEND_SHORT_MESSAGE,
            0x14: self.SEND_DTMF,
            0x15: self.LAUNCH_BROWSER,
            0x20: self.PLAY_TONE,
            0x21: self.DISPLAY_TEXT,
            0x22: self.GET_INKEY,
            0x23: self.GET_INPUT,
            0x24: self.SELECT_ITEM,
            0x25: self.SET_UP_MENU,
            0x26: self.PROVIDE_LOCAL_INFORMATION,
            0x27: self.TIMER_MANAGEMENT,
            0x28: self.SET_UP_IDLE_MODE_TEXT,
            0x30: self.PERFORM_CARD_APDU,
            0x31: self.POWER_ON_CARD,
            0x32: self.POWER_OFF_CARD,
            0x33: self.GET_READER_STATUS,
            0x34: self.RUN_AT_COMMAND,
            0x35: self.LANGUAGE_NOTIFICATION,
            0x40: self.OPEN_CHANNEL,
            0x41: self.CLOSE_CHANNEL,
            0x42: self.RECEIVE_DATA,
            0x43: self.SEND_DATA,
            0x44: self.GET_CHANNEL_STATUS,
            0x45: self.SERVICE_SEARCH,
            0x46: self.GET_SERVICE_INFORMATION,
            0x47: self.DECLARE_SERVICE,
            0x50: self.SET_FRAMES,
            0x51: self.GET_FRAMES_STATUS,
            0x60: self.RETRIEVE_MULTIMEDIA_MESSAGE,
            0x61: self.SUBMIT_MULTIMEDIA_MESSAGE,
            0x62: self.DISPLAY_MULTIMEDIA_MESSAGE,
            0x81: self.End_of_the_proactive_session,
        }

        if self.data[0] != 0xD0:
            # todo
            print("not proactive tag")
            raise Exception
        self.parsed = BER_TLV.from_bytes(self.data)
        self.parsed.constructed_value = TLV_Array.from_bytes(
            self.parsed.value, CAT_COMTLV
        ).get_tlv_list()

    def to_dict(self):
        dic = dict()
        dic = self.parsed.to_dict()
        return dic
    