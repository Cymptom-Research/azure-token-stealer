import logging
from typing import List, Dict

from connection_class import Connection
from impacket.dcerpc.v5 import rrp

HIVE_MAP = {
    "HKLM": rrp.hOpenLocalMachine,
    "HKCU": rrp.hOpenCurrentUser,
    "HKCR": rrp.hOpenClassesRoot,
    "HKU": rrp.hOpenUsers,
    "HKPD": rrp.hOpenPerformanceData,
}


class Registry:
    def __init__(self, reg_connection: Connection):
        self.connection = reg_connection
        self.logger = logging.getLogger(__name__)
        self.winreg = self.connection.connect_pipe("winreg")

    def enum_values(self) -> List[Dict[str, str]]:
        """
        Function that searches for azure credentials in environment_variables by checking the registry path
        'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'

        :return:
        """
        count_registry_values = 0
        found_azure_credentials = False
        res = []
        self.logger.debug("Open registry key SYSTEM\CurrentControlSet\Control\Session Manager\Environment")
        hroot = self.open_key("SYSTEM\CurrentControlSet\Control\Session Manager\Environment")
        variable_to_search = [
            "AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_CLIENT_SECRET", "AZURE_CLIENT_CERTIFICATE_PATH",
            "AZURE_USERNAME",
            "AZURE_PASSWORD"]
        try:
            while True:
                try:
                    val = rrp.hBaseRegEnumValue(self.winreg, hroot, count_registry_values)
                    value_name = str(val["lpValueNameOut"]).rsplit("\x00")[0]
                    if value_name in variable_to_search:
                        value_content = ""
                        for char in val["lpData"][:-2:2]:
                            value_content = value_content + char.decode("utf-8")
                        res.append({value_name: value_content})
                        found_azure_credentials = True
                        count_registry_values = count_registry_values + 1
                    else:
                        count_registry_values = count_registry_values + 1
                except rrp.DCERPCSessionError as e:
                    if str(e).find("No more data is available"):
                        break
                    else:
                        self.logger.error(f"Failed to read registry value {e}")
                        raise
            return res
        except rrp.DCERPCSessionError as e:
            self.logger.error(f"Failed to read registry value")
            raise e
        finally:
            if not found_azure_credentials:
                self.logger.error("Cant find any environment_variables")

    def open_key(self, key_name: str, hroot: rrp.RPC_HKEY = None, hive: str = "HKLM") -> rrp.RPC_HKEY:
        """
                Opens registry key and returns its handle
                :param key_name: key to open
                :param hroot: Root key handle
                :param hive: Hive in a str format. i.e. HKLM, HKCU, HKU, etc.
                :return: handle to the key opened
        """

        # If no root handle specified, open hive
        if not hroot:
            hroot = HIVE_MAP.get(hive)(dce=self.winreg)["phKey"]

        try:
            h_key = rrp.hBaseRegOpenKey(
                self.winreg, hroot, key_name + "\x00", samDesired=rrp.MAXIMUM_ALLOWED
            )
        except rrp.DCERPCException as e:
            raise e

        return h_key["phkResult"]
