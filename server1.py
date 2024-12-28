from pymodbus.version import version
from pymodbus.server.sync import StartTcpServer
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSparseDataBlock
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext

import json

# --------------------------------------------------------------------------- #
# this is the test file
# --------------------------------------------------------------------------- #


SERVER_HOST = "localhost"
SERVER_PORT = 5020
SERVER_U_ID = 1


class Setting:
    def __init__(self, path='server_settings.json'):
        with open(path, 'r') as f:
            dicts = json.load(f)
        self.__dict__.update(dicts)


def run_server():
    store = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [17] * 100),
        co=ModbusSequentialDataBlock(0, [17] * 100),
        hr=ModbusSequentialDataBlock(0, [17] * 100),
        ir=ModbusSequentialDataBlock(0, [17] * 100))

    context = ModbusServerContext(slaves=store, single=True)
    identity = ModbusDeviceIdentification()


    settings = Setting()
    StartTcpServer(context, identity=identity, address=(SERVER_HOST, SERVER_PORT),
                   private_key=settings.private_key, public_key=settings.public_key, sm4_key = settings.sm4_key,
                   trusted_key=settings.known_host[0]['public_key'])


if __name__ == '__main__':
    run_server()
