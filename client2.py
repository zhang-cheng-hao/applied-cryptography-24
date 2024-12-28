from pymodbus.client.sync import ModbusTcpClient as ModbusClient
import json

SERVER_HOST = "localhost"
SERVER_PORT = 5021
SERVER_U_ID = 2

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
                          private_key=settings.private_key, public_key=settings.public_key, sm4_key = settings.sm4_key,
                          trusted_key=settings.known_host[0]['public_key'])
    client.connect()

    print("Reading Coils")
    rr = client.read_coils(1, 1, unit=UNIT)
    print(rr)

    print("Write to a Coil and read back")
    rq = client.write_coil(0, True, unit=UNIT)
    rr = client.read_coils(0, 1, unit=UNIT)
    assert(not rq.isError())     # test that we are not an error
    assert(not rr.isError())     # test that we are not an error
    assert(rr.bits[0] == True)          # test the expected value

    print("Write to multiple coils and read back- test 1")
    rq = client.write_coils(1, [True]*8, unit=UNIT)
    rr = client.read_coils(1, 21, unit=UNIT)
    assert(not rq.isError())     # test that we are not an error
    assert(not rr.isError())     # test that we are not an error
    resp = [True]*21


    resp.extend([False]*3)
    assert(rr.bits == resp)         # test the expected value

    print("Write to multiple coils and read back - test 2")
    rq = client.write_coils(1, [False]*8, unit=UNIT)
    rr = client.read_coils(1, 8, unit=UNIT)
    assert(not rq.isError())     # test that we are not an error
    assert(not rr.isError())     # test that we are not an error
    assert(rr.bits == [False]*8)         # test the expected value

    print("Read discrete inputs")
    rr = client.read_discrete_inputs(0, 8, unit=UNIT)
    assert(not rr.isError())     # test that we are not an error

    print("Write to a holding register and read back")
    rq = client.write_register(1, 10, unit=UNIT)
    rr = client.read_holding_registers(1, 1, unit=UNIT)
    assert(not rq.isError())     # test that we are not an error
    assert(not rr.isError())     # test that we are not an error
    assert(rr.registers[0] == 10)       # test the expected value

    print("Write to multiple holding registers and read back")
    rq = client.write_registers(1, [10]*8, unit=UNIT)
    rr = client.read_holding_registers(1, 8, unit=UNIT)
    assert(not rq.isError())     # test that we are not an error
    assert(not rr.isError())     # test that we are not an error
    assert(rr.registers == [10]*8)      # test the expected value

    print("Read input registers")
    rr = client.read_input_registers(1, 8, unit=UNIT)
    assert(not rr.isError())     # test that we are not an error

    arguments = {
        'read_address':    1,
        'read_count':      8,
        'write_address':   1,
        'write_registers': [20]*8,
    }
    print("Read write registeres simulataneously")
    rq = client.readwrite_registers(unit=UNIT, **arguments)
    rr = client.read_holding_registers(1, 8, unit=UNIT)
    assert(not rq.isError())     # test that we are not an error
    assert(not rr.isError())     # test that we are not an error
    assert(rq.registers == [20]*8)      # test the expected value
    assert(rr.registers == [20]*8)      # test the expected value

    client.close()


if __name__ == "__main__":
    run_client()