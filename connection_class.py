from impacket import smbconnection
from impacket.dcerpc.v5 import transport, rrp


class Connection:

    def __init__(self, username, password, domain, target):
        self.user = username
        self.password = password
        self.domain = domain
        self.target = target
        self.connection: smbconnection.SMBConnection = None
        self.dce: transport.DCERPC_v5 = None

    def connect(self):
        """
        Function preforme login to the target
        :return:
        """
        self.connection = smbconnection.SMBConnection(
            self.target, self.target, sess_port=445
        )
        self.connection.login(
            user=self.user,
            password=self.password,
            domain=self.domain,
        )

    def connect_pipe(self, pipe: str):
        """
        Connects to a remote pipe and returns the handler object
        :param pipe: name of pipe
        :return:
        """
        _pipe = r"ncacn_np:445[\pipe\{}]".format(pipe)
        rpc = transport.DCERPCTransportFactory(_pipe)
        rpc.set_smb_connection(self.connection)
        self.dce = rpc.get_dce_rpc()
        try:
            self.dce.connect()
            self.dce.bind(rrp.MSRPC_UUID_RRP)
        except (transport.DCERPCException, smbconnection.SessionError) as e:
            raise e

        return self.dce
