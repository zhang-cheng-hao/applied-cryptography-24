from pymodbus.client.sync import ModbusTcpClient as ModbusClient
import json
import time

SERVER_HOST = "localhost"
SERVER_PORT = 5020
SERVER_U_ID = 1

UNIT = 0x1


# --------------------------------------------------------------------------- #
# this is the test file
# --------------------------------------------------------------------------- #

class Setting:
    def __init__(self, path='client_settings.json'):
        with open(path, 'r') as f:
            dicts = json.load(f)
        self.__dict__.update(dicts)


def run_client():
    settings = Setting()
    client = ModbusClient(SERVER_HOST, port=SERVER_PORT,
                          private_key=settings.private_key, public_key=settings.public_key, sm4_key=settings.sm4_key,
                          trusted_key=settings.known_host[0]['public_key'])
    client.connect()

    rr = client.read_coils(1, 1, unit=UNIT)
    print(rr)
    # print("Reading Coils successfully")

    rq = client.write_coils(1, [True] * 8, unit=UNIT)
    rr = client.read_coils(1, 21, unit=UNIT)
    assert (not rq.isError())  # test that we are not an error
    assert (not rr.isError())  # test that we are not an error
    print("Write to multiple coils and read back successfully")

    rr = client.read_discrete_inputs(0, 8, unit=UNIT)
    assert (not rr.isError())  # test that we are not an error
    print("Read discrete inputs successfully")

    rq = client.write_register(1, 10, unit=UNIT)
    rr = client.read_holding_registers(1, 1, unit=UNIT)
    assert (not rq.isError())  # test that we are not an error
    assert (not rr.isError())  # test that we are not an error
    assert (rr.registers[0] == 10)  # test the expected value
    print("Write to a holding register and read back successfully")

    rq = client.write_registers(1, [10] * 8, unit=UNIT)
    rr = client.read_holding_registers(1, 8, unit=UNIT)
    assert (not rq.isError())  # test that we are not an error
    assert (not rr.isError())  # test that we are not an error
    assert (rr.registers == [10] * 8)  # test the expected value
    print("Write to multiple holding registers and read back successfully")

    rr = client.read_input_registers(1, 8, unit=UNIT)
    assert (not rr.isError())  # test that we are not an error
    print("Read input registers successfully")

    arguments = {
        'read_address': 1,
        'read_count': 8,
        'write_address': 1,
        'write_registers': [20] * 8,
    }
    rq = client.readwrite_registers(unit=UNIT, **arguments)
    rr = client.read_holding_registers(1, 8, unit=UNIT)
    assert (not rq.isError())  # test that we are not an error
    assert (not rr.isError())  # test that we are not an error
    assert (rq.registers == [20] * 8)  # test the expected value
    assert (rr.registers == [20] * 8)  # test the expected value
    print("Read write registeres simulataneously succeed")

    client.close()


if __name__ == "__main__":
    run_client()
