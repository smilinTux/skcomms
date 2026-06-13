from skcomms.transports.lora.interface import LoRaMeshInterface
from skcomms.transports.lora.meshtastic_iface import MeshtasticInterface


def test_is_a_lora_interface_subclass():
    assert issubclass(MeshtasticInterface, LoRaMeshInterface)


def test_construct_without_meshtastic_dep_is_lazy():
    # constructing must NOT import meshtastic (that happens in start()); so a box
    # without the dep can still import + build the object.
    iface = MeshtasticInterface(device="/dev/ttyUSB0")
    assert iface.info()["backend"] == "meshtastic"
    assert iface.info()["device"] == "/dev/ttyUSB0"
