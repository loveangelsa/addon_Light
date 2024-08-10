# first written by nandflash("저장장치") <github@printk.info> since 2020-06-25
# Second Modify by KT("ktdo79") <ktdo79@gmail.com> since 2022-06-25

# This is a part of EzVille Wallpad Addon for Home Assistant
# Author: Dong SHIN <d0104.shin@gmail.com> 2024-02-15

import socket
import threading
import serial
import paho.mqtt.client as paho_mqt
import paho.mqtt.client as mqtt
import json

import sys
import time
import logging
from logging.handlers import TimedRotatingFileHandler
from collections import defaultdict
import os.path
import re

RS485_DEVICE = {
    "light": {
        "state": {
            "id": 0x0E,
            "cmd": 0x81,
        },
        "last": {},
        "power": {
            "id": 0x0E,
            "cmd": 0x41,
            "ack": 0xC1,
        },
    },
    "thermostat": {
        "state": {
            "id": 0x36,
            "cmd": 0x81,
        },
        "last": {},
        "away": {
            "id": 0x36,
            "cmd": 0x46,
            "ack": 0xC6,
        },
        "target": {
            "id": 0x36,
            "cmd": 0x44,
            "ack": 0xC4,
        },
        "power": {
            "id": 0x36,
            "cmd": 0x43,
            "ack": 0xC3,
        },
    },
    "batch": {
        "state": {"id": 0x33, "cmd": 0x81},
        "press": {"id": 0x33, "cmd": 0x41, "ack": 0xC1},
    },
    "plug": {
        "state": {"id": 0x39, "cmd": 0x81},
        "power": {"id": 0x39, "cmd": 0x41, "ack": 0xC1},
    },
    "gasvalve": {
        "state": {"id": 0x12, "cmd": 0x81},
        "power": {"id": 0x12, "cmd": 0x41, "ack": 0xC1} # 잠그기만 가능
    }
}


DISCOVERY_DEVICE = {
    "ids": [
        "ezville_wallpad",
    ],
    "name": "ezville_wallpad",
    "mf": "EzVille",
    "mdl": "EzVille Wallpad",
    "sw": "loveangelsa/addon_Light/ezville_wallpad",
}

DISCOVERY_PAYLOAD = {
    "light": [
        {
            "_intg": "light",
            "~": "{prefix}/light/{grp}_{rm}_{id}",
            "name": "{prefix}_light_{grp}_{rm}_{id}",
            "opt": True,
            "stat_t": "~/power/state",
            "cmd_t": "~/power/command",
        }
    ],
    "thermostat": [ {
        "_intg": "climate",
        "~": "{prefix}/thermostat/{grp}_{id}",
        "name": "{prefix}_thermostat_{grp}_{id}",
        "mode_stat_t": "~/power/state",
        "temp_stat_t": "~/target/state",
        "temp_cmd_t": "~/target/command",
        "curr_temp_t": "~/current/state",
        "away_stat_t": "~/away/state",
        "away_cmd_t": "~/away/command",
        "modes": [ "off", "heat" ],
        "min_temp": 5,
        "max_temp": 40,
    } ],
    "plug": [
        {
            "_intg": "switch",
            "~": "{prefix}/plug/{idn}/power",
            "name": "{prefix}_plug_{idn}",
            "stat_t": "~/state",
            "cmd_t": "~/command",
            "icon": "mdi:power-plug",
        },
        {
            "_intg": "sensor",
            "~": "{prefix}/plug/{idn}",
            "name": "{prefix}_plug_{idn}_power_usage",
            "stat_t": "~/current/state",
            "unit_of_meas": "W",
        },
    ]
}

STATE_HEADER = {
    prop["state"]["id"]: (device, prop["state"]["cmd"])
    for device, prop in RS485_DEVICE.items()
    if "state" in prop
}

# 제어 명령의 ACK header만 모음
ACK_HEADER = {
    prop[cmd]["id"]: (device, prop[cmd]["ack"])
    for device, prop in RS485_DEVICE.items()
        for cmd, code in prop.items()
            if "ack" in code
}
# KTDO: 제어 명령과 ACK의 Pair 저장

ACK_MAP = defaultdict(lambda: defaultdict(dict))
for device, prop in RS485_DEVICE.items():
    for cmd, code in prop.items():
        if "ack" in code:
            ACK_MAP[code["id"]][code["cmd"]] = code["ack"]

# KTDO: 아래 미사용으로 코멘트 처리
# HEADER_0_STATE = 0xB0
# KTDO: Ezville에서는 가스밸브 STATE Query 코드로 처리
HEADER_0_FIRST = [[0x12, 0x01], [0x12, 0x0F]]
# KTDO: Virtual은 Skip
# header_0_virtual = {}
# KTDO: 아래 미사용으로 코멘트 처리
# HEADER_1_SCAN = 0x5A
header_0_first_candidate = [[[0x33, 0x01], [0x33, 0x0F]], [[0x36, 0x01], [0x36, 0x0F]]]

# human error를 로그로 찍기 위해서 그냥 전부 구독하자
# SUB_LIST = { "{}/{}/+/+/command".format(Options["mqtt"]["prefix"], device) for device in RS485_DEVICE } |\
#           { "{}/virtual/{}/+/command".format(Options["mqtt"]["prefix"], device) for device in VIRTUAL_DEVICE }

serial_queue = {}
serial_ack = {}

last_query = int(0).to_bytes(2, "big")
last_topic_list = {}

mqtt = paho_mqtt.Client(paho_mqtt.CallbackAPIVersion.VERSION2)
mqtt_connected = False

logger = logging.getLogger(__name__)


# KTDO: 수정 완료
class EzVilleSerial:
    def __init__(self):
        self._ser = serial.Serial()
        self._ser.port = Options["serial"]["port"]
        self._ser.baudrate = Options["serial"]["baudrate"]
        self._ser.bytesize = Options["serial"]["bytesize"]
        self._ser.parity = Options["serial"]["parity"]
        self._ser.stopbits = Options["serial"]["stopbits"]

        self._ser.close()
        self._ser.open()

        self._pending_recv = 0

        # 시리얼에 뭐가 떠다니는지 확인
        self.set_timeout(5.0)
        data = self._recv_raw(1)
        self.set_timeout(None)
        if not data:
            logger.critical("no active packet at this serial port!")

    def _recv_raw(self, count=1):
        return self._ser.read(count)

    def recv(self, count=1):
        # serial은 pending count만 업데이트
        self._pending_recv = max(self._pending_recv - count, 0)
        return self._recv_raw(count)

    def send(self, a):
        self._ser.write(a)

    def set_pending_recv(self):
        self._pending_recv = self._ser.in_waiting

    def check_pending_recv(self):
        return self._pending_recv

    def check_in_waiting(self):
        return self._ser.in_waiting

    def set_timeout(self, a):
        self._ser.timeout = a


# KTDO: 수정 완료
class EzVilleSocket:
    def __init__(self, addr, port, capabilities="ALL"):
        self.capabilities = capabilities
        self._soc = socket.socket()
        self._soc.connect((addr, port))

        self._recv_buf = bytearray()
        self._pending_recv = 0

        # 소켓에 뭐가 떠다니는지 확인
        self.set_timeout(5.0)
        data = self._recv_raw(1)
        self.set_timeout(None)
        if not data:
            logger.critical("no active packet at this socket!")

    def _recv_raw(self, count=1):
        return self._soc.recv(count)

    def recv(self, count=1):
        # socket은 버퍼와 in_waiting 직접 관리
        if len(self._recv_buf) < count:
            new_data = self._recv_raw(128)
            self._recv_buf.extend(new_data)
        if len(self._recv_buf) < count:
            return None

        self._pending_recv = max(self._pending_recv - count, 0)

        res = self._recv_buf[0:count]
        del self._recv_buf[0:count]
        return res

    def send(self, a):
        self._soc.sendall(a)

    def set_pending_recv(self):
        self._pending_recv = len(self._recv_buf)

    def check_pending_recv(self):
        return self._pending_recv

    def check_in_waiting(self):
        if len(self._recv_buf) == 0:
            new_data = self._recv_raw(128)
            self._recv_buf.extend(new_data)
        return len(self._recv_buf)

    def set_timeout(self, a):
        self._soc.settimeout(a)


# KTDO: 수정 완료
def init_logger():
    logger.setLevel(logging.INFO)

    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)-8s %(message)s", datefmt="%H:%M:%S"
    )
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)


# KTDO: 수정 완료
def init_logger_file():
    if Options["log"]["to_file"]:
        filename = Options["log"]["filename"]
        os.makedirs(os.path.dirname(filename), exist_ok=True)

        formatter = logging.Formatter(
            fmt="%(asctime)s %(levelname)-8s %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler = TimedRotatingFileHandler(
            os.path.abspath(Options["log"]["filename"]), when="midnight", backupCount=7
        )
        handler.setFormatter(formatter)
        handler.suffix = "%Y%m%d"
        logger.addHandler(handler)


# KTDO: 수정 완료
def init_option(argv):
    # option 파일 선택
    if len(argv) == 1:
        option_file = "./options_standalone.json"
    else:
        option_file = argv[1]

    # configuration이 예전 버전이어도 최대한 동작 가능하도록,
    # 기본값에 해당하는 파일을 먼저 읽고나서 설정 파일로 업데이트 한다.
    global Options

    # 기본값 파일은 .py 와 같은 경로에 있음
    default_file = os.path.join(
        os.path.dirname(os.path.abspath(argv[0])), "config.json"
    )

    with open(default_file, encoding="utf-8") as f:
        config = json.load(f)
        logger.info("addon version %s", config["version"])
        Options = config["options"]
    with open(option_file, encoding="utf-8") as f:
        Options2 = json.load(f)

    # 업데이트
    for k, v in Options.items():
        if isinstance(v, dict) and k in Options2:
            Options[k].update(Options2[k])
            for k2 in Options[k].keys():
                if k2 not in Options2[k].keys():
                    logger.warning(
                        "no configuration value for '%s:%s'! try default value (%s)...",
                        k,
                        k2,
                        Options[k][k2],
                    )
        else:
            if k not in Options2:
                logger.warning(
                    "no configuration value for '%s'! try default value (%s)...",
                    k,
                    Options[k],
                )
            else:
                Options[k] = Options2[k]

    # 관용성 확보
    Options["mqtt"]["server"] = re.sub("[a-z]*://", "", Options["mqtt"]["server"])
    if Options["mqtt"]["server"] == "127.0.0.1":
        logger.warning("MQTT server address should be changed!")

    # internal options
    Options["mqtt"]["_discovery"] = Options["mqtt"]["discovery"]


# KTDO: 수정 완료
def mqtt_discovery(payload):
    """
    Publishes MQTT discovery message for a new device.

    Args:
        payload (dict): The payload containing device information.

    Returns:
        None
    """
    intg = payload.pop("_intg")

    # MQTT 통합구성요소에 등록되기 위한 추가 내용
    payload["device"] = DISCOVERY_DEVICE
    payload["uniq_id"] = payload["name"]

    # discovery에 등록
    topic = f"homeassistant/{intg}/ezville_wallpad/{payload['name']}/config"
    logger.info("Add new device: %s", topic)
    mqtt.publish(topic, json.dumps(payload))


# KTDO: 수정 완료
def mqtt_debug(topics, payload):
    device = topics[2]
    command = topics[3]

    if device == "packet":
        if command == "send":
            # parity는 여기서 재생성
            packet = bytearray.fromhex(payload)
            packet[-2], packet[-1] = serial_generate_checksum(packet)
            packet = bytes(packet)

            logger.info("prepare packet:  {}".format(packet.hex()))
            serial_queue[packet] = time.time()


# KTDO: 수정 완료
def mqtt_device(topics, payload):
    device = topics[1]
    idn = topics[2]
    cmd = topics[3]
    # HA에서 잘못 보내는 경우 체크
    if device not in RS485_DEVICE:
        logger.error("    unknown device!")
        return
    if cmd not in RS485_DEVICE[device]:
        logger.error("    unknown command!")
        return
    if payload == "":
        logger.error("    no payload!")
        return

    # ON, OFF인 경우만 1, 0으로 변환, 복잡한 경우 (fan 등) 는 값으로 받자

    # 오류 체크 끝났으면 serial 메시지 생성
    cmd = RS485_DEVICE[device][cmd]
    packet = None
    if device == "light":
        if payload == "ON":
            payload = 0xF1
            if idn.startswith("1_1_1") or idn.startswith("1_1_2") or idn.startswith("1_2_1"):
                payload = 0xF1 
            else:
                payload = 0x01
        elif payload == "OFF":
            payload = 0x00
        length = 10
        packet = bytearray(length)
        packet[0] = 0xF7
        packet[1] = cmd["id"]
        packet[2] = int(idn.split("_")[0]) << 4 | int(idn.split("_")[1])
        packet[3] = cmd["cmd"]
        packet[4] = 0x03
        packet[5] = int(idn.split("_")[2])
        packet[6] = payload
        packet[7] = 0x00
        packet[8], packet[9] = serial_generate_checksum(packet)
    elif device == "thermostat":
        if payload == "heat":
            payload = 0x01
        elif payload == "off":
            payload = 0x00
        length = 8
        packet = bytearray(length)
        packet[0] = 0xF7
        packet[1] = cmd["id"]
        packet[2] = int(idn.split("_")[0]) << 4 | int(idn.split("_")[1])
        packet[3] = cmd["cmd"]
        packet[4] = 0x01
        packet[5] = int(float(payload))
        packet[6], packet[7] = serial_generate_checksum(packet)
    # TODO : gasvalve, batch, plug
    elif device == "plug":
        length = 8
        packet = bytearray(length)
        packet[0] = 0xF7
        packet[1] = cmd["id"]
        packet[2] = int(idn.split("_")[0]) << 4 | int(idn.split("_")[1])
        packet[3] = cmd["cmd"]
        packet[4] = 0x01
        packet[5] = 0x11 if payload == "ON" else 0x10
        packet[6], packet[7] = serial_generate_checksum(packet)
    if packet:
        packet = bytes(packet)
        serial_queue[packet] = time.time()


# KTDO: 수정 완료
def mqtt_init_discovery():
    # HA가 재시작됐을 때 모든 discovery를 다시 수행한다
    Options["mqtt"]["_discovery"] = Options["mqtt"]["discovery"]
    # KTDO: Virtual Device는 Skip
    #    mqtt_add_virtual()
    for device in RS485_DEVICE:
        RS485_DEVICE[device]["last"] = {}

    global last_topic_list
    last_topic_list = {}


# KTDO: 수정 완료
def mqtt_on_message(mqtt, userdata, msg):
    topics = msg.topic.split("/")
    payload = msg.payload.decode()

    logger.info("recv. from HA:   %s = %s", msg.topic, payload)

    device = topics[1]
    if device == "status":
        if payload == "online":
            mqtt_init_discovery()
    elif device == "debug":
        mqtt_debug(topics, payload)
    else:
        mqtt_device(topics, payload)


# KTDO: 수정 완료
def mqtt_on_connect(mqtt, userdata, flags, rc, properties):
    if rc == 0:
        logger.info("MQTT connect successful!")
        global mqtt_connected
        mqtt_connected = True
    else:
        logger.error("MQTT connection return with:  %s", paho_mqtt.connack_string(rc))

    mqtt_init_discovery()

    topic = "homeassistant/status"
    logger.info("subscribe %s", topic)
    mqtt.subscribe(topic, 0)

    prefix = Options["mqtt"]["prefix"]
    if Options["wallpad_mode"] != "off":
        topic = f"{prefix}/+/+/+/command"
        logger.info("subscribe %s", topic)
        mqtt.subscribe(topic, 0)


# KTDO: 수정 완료
def mqtt_on_disconnect(client, userdata, flags, rc, properties):
    logger.warning("MQTT disconnected! (%s)", rc)
    global mqtt_connected
    mqtt_connected = False


if __name__ == "__main__":
    # configuration 로드 및 로거 설정
    init_logger()
    init_option(sys.argv)
    init_logger_file()
    start_mqtt_loop()

    if Options["serial_mode"] == "sockets":
        for _socket in Options["sockets"]:
            conn = EzVilleSocket(_socket["address"], _socket["port"], _socket["capabilities"])
            init_connect(conn=conn)
            thread = threading.Thread(target=daemon, args=(conn,))
            thread.daemon = True
            thread.start()
        while True:
            time.sleep(10**8)
    elif Options["serial_mode"] == "socket":
        logger.info("initialize socket...")
        conn = EzVilleSocket(Options["socket"]["address"], Options["socket"]["port"])
    else:
        logger.info("initialize serial...")
        conn = EzVilleSerial()
    if Options["serial_mode"] != "sockets":
        init_connect(conn=conn)
        try:
            daemon(conn=conn)
        except:
            logger.exception("addon finished!")
