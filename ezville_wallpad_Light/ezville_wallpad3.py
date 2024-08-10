# first written by nandflash("저장장치") <github@printk.info> since 2020-06-25
# Second Modify by KT("ktdo79") <ktdo79@gmail.com> since 2022-06-25

# This is a part of EzVille Wallpad Addon for Home Assistant
# Author: Dong SHIN <d0104.shin@gmail.com> 2024-02-15

import socket
import threading
import serial
import paho.mqtt.client as paho_mqtt
import json

import sys
import time
import logging
from logging.handlers import TimedRotatingFileHandler
from collections import defaultdict
import os.path
import re

import asyncio
import threading
import telnetlib
import random

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
    'gasvalve': {
        "state": {"id": 0x12', "cmd": 0x81},
        "power": {"id": 0x12', "cmd": 0x41, "ack": 0xC1} # 잠그기만 가능
    },
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
    ],
    "gasvalve": [ {
        "_intg": "switch",
        "~": "ezville/gasvalve_{:0>2d}_{:0>2d}",
        "name": "ezville_gasvalve_{:0>2d}_{:0>2d}",
        "stat_t": "~/power/state",
        "cmd_t": "~/power/command",
        "icon": "mdi:valve"
    } ],
        "batch": [ {
        "_intg": "button",
        "~": "ezville/batch_{:0>2d}_{:0>2d}",
        "name": "ezville_batch-elevator-up_{:0>2d}_{:0>2d}",
        "cmd_t": "~/elevator-up/command",
        "icon": "mdi:elevator-up"
    },
    {
        "_intg": "button",
        "~": "ezville/batch_{:0>2d}_{:0>2d}",
        "name": "ezville_batch-elevator-down_{:0>2d}_{:0>2d}",
        "cmd_t": "~/elevator-down/command",
        "icon": "mdi:elevator-down"
    },
    {
        "_intg": "binary_sensor",
        "~": "ezville/batch_{:0>2d}_{:0>2d}",
        "name": "ezville_batch-groupcontrol_{:0>2d}_{:0>2d}",
        "stat_t": "~/group/state",
        "icon": "mdi:lightbulb-group"
    },
    {
        "_intg": "binary_sensor",
        "~": "ezville/batch_{:0>2d}_{:0>2d}",
        "name": "ezville_batch-outing_{:0>2d}_{:0>2d}",
        "stat_t": "~/outing/state",
        "icon": "mdi:home-circle"
    } ]
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


# LOG 메시지
def log(string):
    date = time.strftime('%Y-%m-%d %p %I:%M:%S', time.localtime(time.time()))
    print('[{}] {}'.format(date, string))
    return

# CHECKSUM 및 ADD를 마지막 4 BYTE에 추가
def checksum(input_hex):
    try:
        input_hex = input_hex[:-4]
        
        # 문자열 bytearray로 변환
        packet = bytes.fromhex(input_hex)
        
        # checksum 생성
        checksum = 0
        for b in packet:
            checksum ^= b
        
        # add 생성
        add = (sum(packet) + checksum) & 0xFF 
        
        # checksum add 합쳐서 return
        return input_hex + format(checksum, '02X') + format(add, '02X')
    except:
        return None

    
config_dir = '/data'

HA_TOPIC = 'ezville'
STATE_TOPIC = HA_TOPIC + '/{}/{}/state'
EW11_TOPIC = 'ew11'
EW11_SEND_TOPIC = EW11_TOPIC + '/send'


# KTDO: 수정 완료
def start_mqtt_loop():
    logger.info("initialize mqtt...")

    mqtt.on_message = mqtt_on_message
    mqtt.on_connect = mqtt_on_connect
    mqtt.on_disconnect = mqtt_on_disconnect

    if Options["mqtt"]["need_login"]:
        mqtt.username_pw_set(Options["mqtt"]["user"], Options["mqtt"]["passwd"])

    try:
        mqtt.connect(Options["mqtt"]["server"], Options["mqtt"]["port"])
    except Exception as e:
        logger.error("MQTT server address/port may be incorrect! (%s)", e)
        sys.exit(1)

    mqtt.loop_start()

    delay = 1
    while not mqtt_connected:
        logger.info("waiting MQTT connected ...")
        time.sleep(delay)
        delay = min(delay * 2, 10)


# KTDO: 수정 완료
def serial_verify_checksum(packet):
    # 모든 byte를 XOR
    # KTDO: 마지막 ADD 빼고 XOR
    checksum = 0
    for b in packet[:-1]:
        checksum ^= b

    # KTDO: ADD 계산
    add = sum(packet[:-1]) & 0xFF

    # parity의 최상위 bit는 항상 0
    # KTDO: EzVille은 아님
    # if checksum >= 0x80: checksum -= 0x80

    # checksum이 안맞으면 로그만 찍고 무시
    # KTDO: ADD 까지 맞아야함.
    if checksum or add != packet[-1]:
        logger.warning(
            "checksum fail! {}, {:02x}, {:02x}".format(packet.hex(), checksum, add)
        )
        return False

    # 정상
    return True


# KTDO: 수정 완료
def serial_generate_checksum(packet):
    # 마지막 제외하고 모든 byte를 XOR
    checksum = 0
    for b in packet[:-1]:
        checksum ^= b

    # KTDO: add 추가 생성
    add = (sum(packet) + checksum) & 0xFF
    return checksum, add


# KTDO: 수정 완료
def serial_new_device(device, packet, idn=None):
    prefix = Options["mqtt"]["prefix"]
    # 조명은 두 id를 조합해서 개수와 번호를 정해야 함
    if device == "light":
        # KTDO: EzVille에 맞게 수정
        grp_id = int(packet[2] >> 4)
        rm_id = int(packet[2] & 0x0F)
        light_count = int(packet[4]) - 1
        for light_id in range(1, light_count + 1):
            payload = DISCOVERY_PAYLOAD[device][0].copy()
            payload["~"] = payload["~"].format(
                prefix=prefix, grp=grp_id, rm=rm_id, id=light_id
            )
            payload["name"] = payload["name"].format(
                prefix=prefix, grp=grp_id, rm=rm_id, id=light_id
            )

            mqtt_discovery(payload)

    elif device == "thermostat":
        # KTDO: EzVille에 맞게 수정
        grp_id = int(packet[2] >> 4)
        room_count = int((int(packet[4]) - 5) / 2)
        
        for id in range(1, room_count + 1):
            payload = DISCOVERY_PAYLOAD[device][0].copy()
            payload["~"] = payload["~"].format(prefix=prefix, grp=grp_id, id=id)
            payload["name"] = payload["name"].format(prefix=prefix, grp=grp_id, id=id)

            mqtt_discovery(payload)

    elif device == "plug":
        # KTDO: EzVille에 맞게 수정
        grp_id = int(packet[2] >> 4)
        plug_count = int(packet[4] / 3)
        for plug_id in range(1, plug_count + 1):
            payload = DISCOVERY_PAYLOAD[device][0].copy()
            payload["~"] = payload["~"].format(prefix=prefix, idn=f"{grp_id}_{plug_id}")
            payload["name"] = payload["name"].format(
                prefix=prefix, idn=f"{grp_id}_{plug_id}"
            )

            mqtt_discovery(payload)

    elif device in DISCOVERY_PAYLOAD:
        for payloads in DISCOVERY_PAYLOAD[device]:
            payload = payloads.copy()

            payload["~"] = payload["~"].format(prefix=prefix, idn=idn)
            payload["name"] = payload["name"].format(prefix=prefix, idn=idn)

            # 실시간 에너지 사용량에는 적절한 이름과 단위를 붙여준다 (단위가 없으면 그래프로 출력이 안됨)
            # KTDO: Ezville에 에너지 확인 쿼리 없음
            if device == "energy":
                payload["name"] = "{}_{}_consumption".format(
                    prefix, ("power", "gas", "water")[idn]
                )
                payload["unit_of_meas"] = ("W", "m³/h", "m³/h")[idn]
                payload["val_tpl"] = (
                    "{{ value }}",
                    "{{ value | float / 100 }}",
                    "{{ value | float / 100 }}",
                )[idn]

            mqtt_discovery(payload)


# KTDO: 수정 완료
def serial_receive_state(device, packet):
    form = RS485_DEVICE[device]["state"]
    last = RS485_DEVICE[device]["last"]
    idn = (packet[1] << 8) | packet[2]
    # 해당 ID의 이전 상태와 같은 경우 바로 무시
    if last.get(idn) == packet:
        return

    # 처음 받은 상태인 경우, discovery 용도로 등록한다.
    if Options["mqtt"]["_discovery"] and not last.get(idn):
        serial_new_device(device, packet, idn)
        last[idn] = True

        # 장치 등록 먼저 하고, 상태 등록은 그 다음 턴에 한다. (난방 상태 등록 무시되는 현상 방지)
        return

    else:
        last[idn] = packet

    # KTDO: 아래 코드로 값을 바로 판별
    prefix = Options["mqtt"]["prefix"]

    if device == "light":
        grp_id = int(packet[2] >> 4)
        rm_id = int(packet[2] & 0x0F)
        light_count = int(packet[4]) - 1

        for light_id in range(1, light_count + 1):
            topic = f"{prefix}/{device}/{grp_id}_{rm_id}_{light_id}/power/state"
            if packet[5 + light_id] & 1:
                value = "ON"
            else:
                value = "OFF"

            if last_topic_list.get(topic) != value:
                logger.debug("publish to HA:   %s = %s (%s)", topic, value, packet.hex())
                mqtt.publish(topic, value)
                last_topic_list[topic] = value
    elif device == "thermostat":
        grp_id = int(packet[2] >> 4)
        room_count = int((int(packet[4]) - 5) / 2)

        for thermostat_id in range(1, room_count + 1):
            if ((packet[6] & 0x1F) >> (room_count - thermostat_id)) & 1:
                value1 = "ON"
            else:
                value1 = "OFF"
            if ((packet[7] & 0x1F) >> (room_count - thermostat_id)) & 1:
                value2 = "ON"
            else:
                value2 = "OFF"
            for sub_topic, value in zip(
                ["mode", "away", "target", "current"],
                [
                    value1,
                    value2,
                    packet[8 + thermostat_id * 2],
                    packet[9 + thermostat_id * 2],
                ],
            ):
                topic = f"{prefix}/{device}/{grp_id}_{thermostat_id}/{sub_topic}/state"
                if last_topic_list.get(topic) != value:
                    logger.debug(
                        "publish to HA:   %s = %s (%s)", topic, value, packet.hex()
                    )
                    mqtt.publish(topic, value)
                    last_topic_list[topic] = value
    elif device == "plug":
        grp_id = int(packet[2] >> 4)
        plug_count = int(packet[4] / 3)
        for plug_id in range(1, plug_count + 1):
            for sub_topic, value in zip(
                ["power", "current"],
                [
                    "ON" if packet[plug_id * 3 + 3] & 0x10 else "OFF",
                    f"{format(packet[plug_id * 3 + 4], 'x')}.{format(packet[plug_id * 3 + 5], 'x')}",
                ],
            ):
                topic = f"{prefix}/{device}/{grp_id}_{plug_id}/{sub_topic}/state"
                if last_topic_list.get(topic) != value:
                    logger.debug(
                        "publish to HA:   %s = %s (%s)", topic, value, packet.hex()
                    )
                    mqtt.publish(topic, value)
                    last_topic_list[topic] = value


# KTDO: 수정 완료
def serial_get_header(conn):
    try:
        # 0x80보다 큰 byte가 나올 때까지 대기
        # KTDO: 시작 F7 찾기
        while True:
            header_0 = conn.recv(1)[0]
            # if header_0 >= 0x80: break
            if header_0 == 0xF7:
                break

        # 중간에 corrupt되는 data가 있으므로 연속으로 0x80보다 큰 byte가 나오면 먼젓번은 무시한다
        # KTDO: 연속 0xF7 무시
        while 1:
            header_1 = conn.recv(1)[0]
            # if header_1 < 0x80: break
            if header_1 != 0xF7:
                break
            header_0 = header_1

        header_2 = conn.recv(1)[0]
        header_3 = conn.recv(1)[0]

    except (OSError, serial.SerialException):
        logger.error("ignore exception!")
        header_0 = header_1 = header_2 = header_3 = 0

    # 헤더 반환
    return header_0, header_1, header_2, header_3


# KTDO: 수정 완료
def serial_ack_command(packet):
    logger.info("ack from device: {} ({:x})".format(serial_ack[packet].hex(), packet))

    # 성공한 명령을 지움
    serial_queue.pop(serial_ack[packet], None)
    serial_ack.pop(packet)


# KTDO: 수정 완료
def serial_send_command(conn):
    # 한번에 여러개 보내면 응답이랑 꼬여서 망함
    cmd = next(iter(serial_queue))
    if conn.capabilities != "ALL" and ACK_HEADER[cmd[1]][0] not in conn.capabilities:
        return
    conn.send(cmd)
    # KTDO: Ezville은 4 Byte까지 확인 필요
    ack = bytearray(cmd[0:4])
    ack[3] = ACK_MAP[cmd[1]][cmd[3]]
    waive_ack = False
    if ack[3] == 0x00:
        waive_ack = True
    ack = int.from_bytes(ack, "big")

    # retry time 관리, 초과했으면 제거
    elapsed = time.time() - serial_queue[cmd]
    if elapsed > Options["rs485"]["max_retry"]:
        logger.error("send to device:  %s max retry time exceeded!", cmd.hex())
        serial_queue.pop(cmd)
        serial_ack.pop(ack, None)
    elif elapsed > 3:
        logger.warning(
            "send to device:  {}, try another {:.01f} seconds...".format(
                cmd.hex(), Options["rs485"]["max_retry"] - elapsed
            )
        )
        serial_ack[ack] = cmd
    elif waive_ack:
        logger.info("waive ack:  %s", cmd.hex())
        serial_queue.pop(cmd)
        serial_ack.pop(ack, None)
    else:
        logger.info("send to device:  %s", cmd.hex())
        serial_ack[ack] = cmd


# KTDO: 수정 완료
def daemon(conn):
    logger.info("start loop ...")
    scan_count = 0
    send_aggressive = False
    while True:
        # 로그 출력
        sys.stdout.flush()

        # 첫 Byte만 0x80보다 큰 두 Byte를 찾음
        header_0, header_1, header_2, header_3 = serial_get_header(conn)
        # KTDO: 패킷단위로 분석할 것이라 합치지 않음.
        # header = (header_0 << 8) | header_1
        # device로부터의 state 응답이면 확인해서 필요시 HA로 전송해야 함
        if header_1 in STATE_HEADER and header_3 in STATE_HEADER[header_1]:
            device = STATE_HEADER[header_1][0]
            header_4 = conn.recv(1)[0]
            data_length = int(header_4)

            # KTDO: packet 생성 위치 변경
            packet = bytes([header_0, header_1, header_2, header_3, header_4])

            # 해당 길이만큼 읽음
            # KTDO: 데이터 길이 + 2 (XOR + ADD) 만큼 읽음
            packet += conn.recv(data_length + 2)

            # checksum 오류 없는지 확인
            # KTDO: checksum 및 ADD 오류 없는지 확인
            if not serial_verify_checksum(packet):
                continue

            # 디바이스 응답 뒤에도 명령 보내봄
            if serial_queue and not conn.check_pending_recv():
                serial_send_command(conn=conn)
                conn.set_pending_recv()
            # 적절히 처리한다
            serial_receive_state(device, packet)

        # KTDO: 이전 명령의 ACK 경우
        elif header_1 in ACK_HEADER and header_3 in ACK_HEADER[header_1]:
            # 한 byte 더 뽑아서, 보냈던 명령의 ack인지 확인
            # header_2 = conn.recv(1)[0]
            # header = (header << 8) | header_2
            header = header_0 << 24 | header_1 << 16 | header_2 << 8 | header_3
            if header in serial_ack:
                serial_ack_command(header)

        # 명령을 보낼 타이밍인지 확인: 0xXX5A 는 장치가 있는지 찾는 동작이므로,
        # 아직도 이러고 있다는건 아무도 응답을 안할걸로 예상, 그 타이밍에 끼어든다.
        # KTDO: EzVille은 표준에 따라 Ack 이후 다음 Request 까지의 시간 활용하여 command 전송
        #       즉 State 확인 후에만 전달
        elif (header_3 == 0x81 or 0x8F or 0x0F) or send_aggressive:
            # if header_1 == HEADER_1_SCAN or send_aggressive:
            scan_count += 1
            if serial_queue and not conn.check_pending_recv():
                serial_send_command(conn=conn)
                conn.set_pending_recv()


# KTDO: 수정 완료
def init_connect(conn):
    dump_time = Options["rs485"]["dump_time"]

    if dump_time > 0:
        if dump_time < 10:
            logger.warning(
                "dump_time is too short! automatically changed to 10 seconds..."
            )
            dump_time = 10

        start_time = time.time()
        logger.warning("packet dump for {} seconds!".format(dump_time))

        conn.set_timeout(2)
        logs = []
        while time.time() - start_time < dump_time:
            try:
                data = conn.recv(128)
            except:
                continue

            if data:
                for b in data:
                    if b == 0xF7 or len(logs) > 500:
                        logger.info("".join(logs))
                        logs = ["{:02X}".format(b)]
                    else:
                        logs.append(",  {:02X}".format(b))
        logger.info("".join(logs))
        logger.warning("dump done.")
        conn.set_timeout(None)


def ezville_loop(config):
    
    # Log 생성 Flag
    debug = config['DEBUG_LOG']
    mqtt_log = config['MQTT_LOG']
    ew11_log = config['EW11_LOG']
    
    # 통신 모드 설정: mixed, socket, mqtt
    comm_mode = config['mode']
    
    # Socket 정보
    SOC_ADDRESS = config['ew11_server']
    SOC_PORT = config['ew11_port']
    
    # EW11 혹은 HA 전달 메시지 저장소
    MSG_QUEUE = Queue()
    
    # EW11에 보낼 Command 및 예상 Acknowledge 패킷 
    CMD_QUEUE = asyncio.Queue()
    
    # State 저장용 공간
    DEVICE_STATE = {}
    
    # 이전에 전달된 패킷인지 판단을 위한 캐쉬
    MSG_CACHE = {}
    
    # MQTT Discovery Que
    DISCOVERY_DELAY = config['discovery_delay']
    DISCOVERY_LIST = []
    
    # EW11 전달 패킷 중 처리 후 남은 짜투리 패킷 저장
    RESIDUE = ''
    
    # 강제 주기적 업데이트 설정 - 매 force_update_period 마다 force_update_duration초간 HA 업데이트 실시
    FORCE_UPDATE = False
    FORCE_MODE = config['force_update_mode']
    FORCE_PERIOD = config['force_update_period']
    FORCE_DURATION = config['force_update_duration']
    
    # Command를 EW11로 보내는 방식 설정 (동시 명령 횟수, 명령 간격 및 재시도 횟수)
    CMD_INTERVAL = config['command_interval']
    CMD_RETRY_COUNT = config['command_retry_count']
    FIRST_WAITTIME = config['first_waittime']
    RANDOM_BACKOFF = config['random_backoff']
    
    # State 업데이트 루프 / Command 실행 루프 / Socket 통신으로 패킷 받아오는 루프 / Restart 필요한지 체크하는 루프의 Delay Time 설정
    STATE_LOOP_DELAY = config['state_loop_delay']
    COMMAND_LOOP_DELAY = config['command_loop_delay']
    SERIAL_RECV_DELAY = config['serial_recv_delay']
    RESTART_CHECK_DELAY = config['restart_check_delay']
    
    # EW11에 설정된 BUFFER SIZE
    EW11_BUFFER_SIZE = config['ew11_buffer_size']
    
    # EW11 동작상태 확인용 메시지 수신 시간 체크 주기 및 체크용 시간 변수
    EW11_TIMEOUT = config['ew11_timeout']
    last_received_time = time.time()
    
    # EW11 재시작 확인용 Flag
    restart_flag = False
  
    # MQTT Integration 활성화 확인 Flag - 단, 사용을 위해서는 MQTT Integration에서 Birth/Last Will Testament 설정 및 Retain 설정 필요
    MQTT_ONLINE = False
    
    # Addon 정상 시작 Flag
    ADDON_STARTED = False
 
    # Reboot 이후 안정적인 동작을 위한 제어 Flag
    REBOOT_CONTROL = config['reboot_control']
    REBOOT_DELAY = config['reboot_delay']

    # 시작 시 인위적인 Delay 필요시 사용
    startup_delay = 0
  

    # MQTT 통신 연결 Callback
    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            log('[INFO] MQTT Broker 연결 성공')
            # Socket인 경우 MQTT 장치의 명령 관련과 MQTT Status (Birth/Last Will Testament) Topic만 구독
            if comm_mode == 'socket':
                client.subscribe([(HA_TOPIC + '/#', 0), ('homeassistant/status', 0)])
            # Mixed인 경우 MQTT 장치 및 EW11의 명령/수신 관련 Topic 과 MQTT Status (Birth/Last Will Testament) Topic 만 구독
            elif comm_mode == 'mixed':
                client.subscribe([(HA_TOPIC + '/#', 0), (EW11_TOPIC + '/recv', 0), ('homeassistant/status', 0)])
            # MQTT 인 경우 모든 Topic 구독
            else:
                client.subscribe([(HA_TOPIC + '/#', 0), (EW11_TOPIC + '/recv', 0), (EW11_TOPIC + '/send', 1), ('homeassistant/status', 0)])
        else:
            errcode = {1: 'Connection refused - incorrect protocol version',
                       2: 'Connection refused - invalid client identifier',
                       3: 'Connection refused - server unavailable',
                       4: 'Connection refused - bad username or password',
                       5: 'Connection refused - not authorised'}
            log(errcode[rc])
         
        
    # MQTT 메시지 Callback
    def on_message(client, userdata, msg):
        nonlocal MSG_QUEUE
        nonlocal MQTT_ONLINE
        nonlocal startup_delay
        
        if msg.topic == 'homeassistant/status':
            # Reboot Control 사용 시 MQTT Integration의 Birth/Last Will Testament Topic은 바로 처리
            if REBOOT_CONTROL:
                status = msg.payload.decode('utf-8')
                
                if status == 'online':
                    log('[INFO] MQTT Integration 온라인')
                    MQTT_ONLINE = True
                    if not msg.retain:
                        log('[INFO] MQTT Birth Message가 Retain이 아니므로 정상화까지 Delay 부여')
                        startup_delay = REBOOT_DELAY
                elif status == 'offline':
                    log('[INFO] MQTT Integration 오프라인')
                    MQTT_ONLINE = False
        # 나머지 topic은 모두 Queue에 보관
        else:
            MSG_QUEUE.put(msg)
 

    # MQTT 통신 연결 해제 Callback
    def on_disconnect(client, userdata, rc):
        log('INFO: MQTT 연결 해제')
        pass


    # MQTT message를 분류하여 처리
    async def process_message():
        # MSG_QUEUE의 message를 하나씩 pop
        nonlocal MSG_QUEUE
        nonlocal last_received_time
        
        stop = False
        while not stop:
            if MSG_QUEUE.empty():
                stop = True
            else:
                msg = MSG_QUEUE.get()
                topics = msg.topic.split('/')

                if topics[0] == HA_TOPIC and topics[-1] == 'command':
                    await HA_process(topics, msg.payload.decode('utf-8'))
                elif topics[0] == EW11_TOPIC and topics[-1] == 'recv':
                    # Que에서 확인된 시간 기준으로 EW11 Health Check함.
                    last_received_time = time.time()

                    await EW11_process(msg.payload.hex().upper())
                   
    
    # EW11 전달된 메시지 처리
    async def EW11_process(raw_data):
        nonlocal DISCOVERY_LIST
        nonlocal RESIDUE
        nonlocal MSG_CACHE
        nonlocal DEVICE_STATE       
        
        raw_data = RESIDUE + raw_data
        
        if ew11_log:
            log('[SIGNAL] receved: {}'.format(raw_data))
        
        k = 0
        cors = []
        msg_length = len(raw_data)
        while k < msg_length:
            # F7로 시작하는 패턴을 패킷으로 분리
            if raw_data[k:k + 2] == 'F7':
                # 남은 데이터가 최소 패킷 길이를 만족하지 못하면 RESIDUE에 저장 후 종료
                if k + 10 > msg_length:
                    RESIDUE = raw_data[k:]
                    break
                else:
                    data_length = int(raw_data[k + 8:k + 10], 16)
                    packet_length = 10 + data_length * 2 + 4 
                    
                    # 남은 데이터가 예상되는 패킷 길이보다 짧으면 RESIDUE에 저장 후 종료
                    if k + packet_length > msg_length:
                        RESIDUE = raw_data[k:]
                        break
                    else:
                        packet = raw_data[k:k + packet_length]
                        
                # 분리된 패킷이 Valid한 패킷인지 Checksum 확인                
                if packet != checksum(packet):
                    k+=1
                    continue
                else:
                    STATE_PACKET = False
                    ACK_PACKET = False
                    
                    # STATE 패킷인지 확인
                    if packet[2:4] in STATE_HEADER and packet[6:8] in STATE_HEADER[packet[2:4]][1]:
                        STATE_PACKET = True
                    # ACK 패킷인지 확인
                    elif packet[2:4] in ACK_HEADER and packet[6:8] in ACK_HEADER[packet[2:4]][1]:
                        ACK_PACKET = True
                    
                    if STATE_PACKET or ACK_PACKET:
                        # MSG_CACHE에 없는 새로운 패킷이거나 FORCE_UPDATE 실행된 경우만 실행
                        if MSG_CACHE.get(packet[0:10]) != packet[10:] or FORCE_UPDATE:
                            name = STATE_HEADER[packet[2:4]][0]                                           
                            if name == 'thermostat':
                                # room 갯수
                                rc = int((int(packet[8:10], 16) - 5) / 2)
                                # room의 조절기 수 (현재 하나 뿐임)
                                src = 1
                                
                                onoff_state = bin(int(packet[12:14], 16))[2:].zfill(8)
                                away_state = bin(int(packet[14:16], 16))[2:].zfill(8)
                                
                                for rid in range(1, rc + 1):
                                    discovery_name = '{}_{:0>2d}_{:0>2d}'.format(name, rid, src)
                                    
                                    if discovery_name not in DISCOVERY_LIST:
                                        DISCOVERY_LIST.append(discovery_name)
                                    
                                        payload = DISCOVERY_PAYLOAD[name][0].copy()
                                        payload['~'] = payload['~'].format(rid, src)
                                        payload['name'] = payload['name'].format(rid, src)
                                   
                                        # 장치 등록 후 DISCOVERY_DELAY초 후에 State 업데이트
                                        await mqtt_discovery(payload)
                                        await asyncio.sleep(DISCOVERY_DELAY)
                                    
                                    setT = str(int(packet[16 + 4 * rid:18 + 4 * rid], 16))
                                    curT = str(int(packet[18 + 4 * rid:20 + 4 * rid], 16))
                                    
                                    if onoff_state[8 - rid ] == '1':
                                        onoff = 'heat'
                                    # 외출 모드는 off로 
                                    elif onoff_state[8 - rid] == '0' and away_state[8 - rid] == '1':
                                        onoff = 'off'
#                                    elif onoff_state[8 - rid] == '0' and away_state[8 - rid] == '0':
#                                        onoff = 'off'
#                                    else:
#                                        onoff = 'off'

                                    await update_state(name, 'power', rid, src, onoff)
                                    await update_state(name, 'curTemp', rid, src, curT)
                                    await update_state(name, 'setTemp', rid, src, setT)
                                    
                                # 직전 처리 State 패킷은 저장
                                if STATE_PACKET:
                                    MSG_CACHE[packet[0:10]] = packet[10:]
                                else:
                                    # Ack 패킷도 State로 저장
                                    MSG_CACHE['F7361F810F'] = packet[10:]
                                    
                            elif name == 'gasvalve':
                                # Gas Value는 하나라서 강제 설정
                                rid = 1
                                # Gas Value는 하나라서 강제 설정
                                spc = 1 
                                
                                discovery_name = '{}_{:0>2d}_{:0>2d}'.format(name, rid, spc)
                                    
                                if discovery_name not in DISCOVERY_LIST:
                                    DISCOVERY_LIST.append(discovery_name)
                                    
                                    payload = DISCOVERY_PAYLOAD[name][0].copy()
                                    payload['~'] = payload['~'].format(rid, spc)
                                    payload['name'] = payload['name'].format(rid, spc)
                                   
                                    # 장치 등록 후 DISCOVERY_DELAY초 후에 State 업데이트
                                    await mqtt_discovery(payload)
                                    await asyncio.sleep(DISCOVERY_DELAY)                                

                                onoff = 'ON' if int(packet[12:14], 16) == 1 else 'OFF'
                                        
                                await update_state(name, 'power', rid, spc, onoff)
                                
                                # 직전 처리 State 패킷은 저장
                                if STATE_PACKET:
                                    MSG_CACHE[packet[0:10]] = packet[10:]
                            
                            # 일괄차단기 ACK PACKET은 상태 업데이트에 반영하지 않음
                            elif name == 'batch' and STATE_PACKET:
                                # 일괄차단기는 하나라서 강제 설정
                                rid = 1
                                # 일괄차단기는 하나라서 강제 설정
                                sbc = 1
                                
                                discovery_name = '{}_{:0>2d}_{:0>2d}'.format(name, rid, sbc)
                                
                                if discovery_name not in DISCOVERY_LIST:
                                    DISCOVERY_LIST.append(discovery_name)
                                    
                                    for payload_template in DISCOVERY_PAYLOAD[name]:
                                        payload = payload_template.copy()
                                        payload['~'] = payload['~'].format(rid, sbc)
                                        payload['name'] = payload['name'].format(rid, sbc)
                                   
                                        # 장치 등록 후 DISCOVERY_DELAY초 후에 State 업데이트
                                        await mqtt_discovery(payload)
                                        await asyncio.sleep(DISCOVERY_DELAY)           

                                # 일괄 차단기는 버튼 상태 변수 업데이트
                                states = bin(int(packet[12:14], 16))[2:].zfill(8)
                                        
                                ELEVDOWN = states[2]                                        
                                ELEVUP = states[3]
                                GROUPON = states[5]
                                OUTING = states[6]
                                                                    
                                grouponoff = 'ON' if GROUPON == '1' else 'OFF'
                                outingonoff = 'ON' if OUTING == '1' else 'OFF'
                                
                                #ELEVDOWN과 ELEVUP은 직접 DEVICE_STATE에 저장
                                elevdownonoff = 'ON' if ELEVDOWN == '1' else 'OFF'
                                elevuponoff = 'ON' if ELEVUP == '1' else 'OFF'
                                DEVICE_STATE['batch_01_01elevator-up'] = elevuponoff
                                DEVICE_STATE['batch_01_01elevator-down'] = elevdownonoff
                                    
                                # 일괄 조명 및 외출 모드는 상태 업데이트
                                await update_state(name, 'group', rid, sbc, grouponoff)
                                await update_state(name, 'outing', rid, sbc, outingonoff)
                                
                                MSG_CACHE[packet[0:10]] = packet[10:]
                                                                                    
                RESIDUE = ''
                k = k + packet_length
                
            else:
                k+=1
                
    
    # MQTT Discovery로 장치 자동 등록
    async def mqtt_discovery(payload):
        intg = payload.pop('_intg')

        # MQTT 통합구성요소에 등록되기 위한 추가 내용
        payload['device'] = DISCOVERY_DEVICE
        payload['uniq_id'] = payload['name']

        # Discovery에 등록
        topic = 'homeassistant/{}/ezville_wallpad/{}/config'.format(intg, payload['name'])
        log('[INFO] 장치 등록:  {}'.format(topic))
        mqtt_client.publish(topic, json.dumps(payload))

    
    # 장치 State를 MQTT로 Publish
    async def update_state(device, state, id1, id2, value):
        nonlocal DEVICE_STATE

        deviceID = '{}_{:0>2d}_{:0>2d}'.format(device, id1, id2)
        key = deviceID + state
        
        if value != DEVICE_STATE.get(key) or FORCE_UPDATE:
            DEVICE_STATE[key] = value
            
            topic = STATE_TOPIC.format(deviceID, state)
            mqtt_client.publish(topic, value.encode())
                    
            if mqtt_log:
                log('[LOG] ->> HA : {} >> {}'.format(topic, value))

        return

    
    # HA에서 전달된 메시지 처리        
    async def HA_process(topics, value):
        nonlocal CMD_QUEUE

        device_info = topics[1].split('_')
        device = device_info[0]
        
        if mqtt_log:
            log('[LOG] HA ->> : {} -> {}'.format('/'.join(topics), value))

        if device in RS485_DEVICE:
            key = topics[1] + topics[2]
            idx = int(device_info[1])
            sid = int(device_info[2])
            cur_state = DEVICE_STATE.get(key)
            
            if value == cur_state:
                pass
            
            else:
                if device == 'thermostat':                        
                    if topics[2] == 'power':
                        if value == 'heat':
                            
                            sendcmd = checksum('F7' + RS485_DEVICE[device]['power']['id'] + '1' + str(idx) + RS485_DEVICE[device]['power']['cmd'] + '01010000')
                            recvcmd = 'F7' + RS485_DEVICE[device]['power']['id'] + '1' + str(idx) + RS485_DEVICE[device]['power']['ack']
                            statcmd = [key, value]
                           
                            await CMD_QUEUE.put({'sendcmd': sendcmd, 'recvcmd': recvcmd, 'statcmd': statcmd})
                        
                        # Thermostat는 외출 모드를 Off 모드로 연결
                        elif value == 'off':
 
                            sendcmd = checksum('F7' + RS485_DEVICE[device]['away']['id'] + '1' + str(idx) + RS485_DEVICE[device]['away']['cmd'] + '01010000')
                            recvcmd = 'F7' + RS485_DEVICE[device]['away']['id'] + '1' + str(idx) + RS485_DEVICE[device]['away']['ack']
                            statcmd = [key, value]
                           
                            await CMD_QUEUE.put({'sendcmd': sendcmd, 'recvcmd': recvcmd, 'statcmd': statcmd})
                        
#                        elif value == 'off':
#                        
#                            sendcmd = checksum('F7' + RS485_DEVICE[device]['power']['id'] + '1' + str(idx) + RS485_DEVICE[device]['power']['cmd'] + '01000000')
#                            recvcmd = 'F7' + RS485_DEVICE[device]['power']['id'] + '1' + str(idx) + RS485_DEVICE[device]['power']['ack']
#                            statcmd = [key, value]
#                           
#                            await CMD_QUEUE.put({'sendcmd': sendcmd, 'recvcmd': recvcmd, 'statcmd': statcmd})                    
                                               
                        if debug:
                            log('[DEBUG] Queued ::: sendcmd: {}, recvcmd: {}, statcmd: {}'.format(sendcmd, recvcmd, statcmd))
                                    
                    elif topics[2] == 'setTemp':                            
                        value = int(float(value))
   
                        sendcmd = checksum('F7' + RS485_DEVICE[device]['target']['id'] + '1' + str(idx) + RS485_DEVICE[device]['target']['cmd'] + '01' + "{:02X}".format(value) + '0000')
                        recvcmd = 'F7' + RS485_DEVICE[device]['target']['id'] + '1' + str(idx) + RS485_DEVICE[device]['target']['ack']
                        statcmd = [key, str(value)]

                        await CMD_QUEUE.put({'sendcmd': sendcmd, 'recvcmd': recvcmd, 'statcmd': statcmd})
                               
                        if debug:
                            log('[DEBUG] Queued ::: sendcmd: {}, recvcmd: {}, statcmd: {}'.format(sendcmd, recvcmd, statcmd))

#                    elif device == 'Fan':
#                        if topics[2] == 'power':
#                            sendcmd = DEVICE_LISTS[device][idx].get('command' + value)
#                            recvcmd = DEVICE_LISTS[device][idx].get('state' + value) if value == 'ON' else [
#                                DEVICE_LISTS[device][idx].get('state' + value)]
#                            QUEUE.append({'sendcmd': sendcmd, 'recvcmd': recvcmd, 'count': 0})
#                            if debug:
#                                log('[DEBUG] Queued ::: sendcmd: {}, recvcmd: {}'.format(sendcmd, recvcmd))
#                        elif topics[2] == 'speed':
#                            speed_list = ['LOW', 'MEDIUM', 'HIGH']
#                            if value in speed_list:
#                                index = speed_list.index(value)
#                                sendcmd = DEVICE_LISTS[device][idx]['CHANGE'][index]
#                                recvcmd = [DEVICE_LISTS[device][idx]['stateON'][index]]
#                                QUEUE.append({'sendcmd': sendcmd, 'recvcmd': recvcmd, 'count': 0})
#                                if debug:
#                                    log('[DEBUG] Queued ::: sendcmd: {}, recvcmd: {}'.format(sendcmd, recvcmd))

                elif device == 'gasvalve':
                    # 가스 밸브는 ON 제어를 받지 않음
                    if value == 'OFF':
                        sendcmd = checksum('F7' + RS485_DEVICE[device]['power']['id'] + '0' + str(idx) + RS485_DEVICE[device]['power']['cmd'] + '0100' + '0000')
                        recvcmd = ['F7' + RS485_DEVICE[device]['power']['id'] + '1' + str(idx) + RS485_DEVICE[device]['power']['ack']]
                        statcmd = [key, value]

                        await CMD_QUEUE.put({'sendcmd': sendcmd, 'recvcmd': recvcmd, 'statcmd': statcmd})
                               
                        if debug:
                            log('[DEBUG] Queued ::: sendcmd: {}, recvcmd: {}, statcmd: {}'.format(sendcmd, recvcmd, statcmd))
                                
                elif device == 'batch':
                    # Batch는 Elevator 및 외출/그룹 조명 버튼 상태 고려 
                    elup_state = '1' if DEVICE_STATE.get(topics[1] + 'elevator-up') == 'ON' else '0'
                    eldown_state = '1' if DEVICE_STATE.get(topics[1] + 'elevator-down') == 'ON' else '0'
                    out_state = '1' if DEVICE_STATE.get(topics[1] + 'outing') == 'ON' else '0'
                    group_state = '1' if DEVICE_STATE.get(topics[1] + 'group') == 'ON' else '0'

                    cur_state = DEVICE_STATE.get(key)

                    # 일괄 차단기는 4가지 모드로 조절               
                    if topics[2] == 'elevator-up':
                        elup_state = '1'
                    elif topics[2] == 'elevator-down':
                        eldown_state = '1'
# 그룹 조명과 외출 모드 설정은 테스트 후에 추가 구현                                                
#                    elif topics[2] == 'group':
#                        group_state = '1'
#                    elif topics[2] == 'outing':
#                        out_state = '1'
                            
                    CMD = '{:0>2X}'.format(int('00' + eldown_state + elup_state + '0' + group_state + out_state + '0', 2))
                    
                    # 일괄 차단기는 state를 변경하여 제공해서 월패드에서 조작하도록 해야함
                    # 월패드의 ACK는 무시
                    sendcmd = checksum('F7' + RS485_DEVICE[device]['state']['id'] + '0' + str(idx) + RS485_DEVICE[device]['state']['cmd'] + '0300' + CMD + '000000')
                    recvcmd = 'NULL'
                    statcmd = [key, 'NULL']
                    
                    await CMD_QUEUE.put({'sendcmd': sendcmd, 'recvcmd': recvcmd, 'statcmd': statcmd})
                    
                    if debug:
                        log('[DEBUG] Queued ::: sendcmd: {}, recvcmd: {}, statcmd: {}'.format(sendcmd, recvcmd, statcmd))
  
                                                
    # HA에서 전달된 명령을 EW11 패킷으로 전송
    async def send_to_ew11(send_data):
            
        for i in range(CMD_RETRY_COUNT):
            if ew11_log:
                log('[SIGNAL] 신호 전송: {}'.format(send_data))
                        
            if comm_mode == 'mqtt':
                mqtt_client.publish(EW11_SEND_TOPIC, bytes.fromhex(send_data['sendcmd']))
            else:
                nonlocal soc
                try:
                    soc.sendall(bytes.fromhex(send_data['sendcmd']))
                except OSError:
                    soc.close()
                    soc = initiate_socket(soc)
                    soc.sendall(bytes.fromhex(send_data['sendcmd']))
            if debug:                     
                log('[DEBUG] Iter. No.: ' + str(i + 1) + ', Target: ' + send_data['statcmd'][1] + ', Current: ' + DEVICE_STATE.get(send_data['statcmd'][0]))
             
            # Ack나 State 업데이트가 불가한 경우 한번만 명령 전송 후 Return
            if send_data['statcmd'][1] == 'NULL':
                return
      
            # FIRST_WAITTIME초는 ACK 처리를 기다림 (초당 30번 데이터가 들어오므로 ACK 못 받으면 후속 처리 시작)
            if i == 0:
                await asyncio.sleep(FIRST_WAITTIME)
            # 이후에는 정해진 간격 혹은 Random Backoff 시간 간격을 주고 ACK 확인
            else:
                if RANDOM_BACKOFF:
                    await asyncio.sleep(random.randint(0, int(CMD_INTERVAL * 1000))/1000)    
                else:
                    await asyncio.sleep(CMD_INTERVAL)
              
            if send_data['statcmd'][1] == DEVICE_STATE.get(send_data['statcmd'][0]):
                return

        if ew11_log:
            log('[SIGNAL] {}회 명령을 재전송하였으나 수행에 실패했습니다.. 다음의 Queue 삭제: {}'.format(str(CMD_RETRY_COUNT),send_data))
            return
        
                                                
    # EW11 동작 상태를 체크해서 필요시 리셋 실시
    async def ew11_health_loop():        
        while True:
            timestamp = time.time()
        
            # TIMEOUT 시간 동안 새로 받은 EW11 패킷이 없으면 재시작
            if timestamp - last_received_time > EW11_TIMEOUT:
                log('[WARNING] {} {} {}초간 신호를 받지 못했습니다. ew11 기기를 재시작합니다.'.format(timestamp, last_received_time, EW11_TIMEOUT))
                try:
                    await reset_EW11()
                    
                    restart_flag = True

                except:
                    log('[ERROR] 기기 재시작 오류! 기기 상태를 확인하세요.')
            else:
                log('[INFO] EW11 연결 상태 문제 없음')
            await asyncio.sleep(EW11_TIMEOUT)        

                                                
    # Telnet 접속하여 EW11 리셋        
    async def reset_EW11(): 
        ew11_id = config['ew11_id']
        ew11_password = config['ew11_password']
        ew11_server = config['ew11_server']

        ew11 = telnetlib.Telnet(ew11_server)

        ew11.read_until(b'login:')
        ew11.write(ew11_id.encode('utf-8') + b'\n')
        ew11.read_until(b'password:')
        ew11.write(ew11_password.encode('utf-8') + b'\n')
        ew11.write('Restart'.encode('utf-8') + b'\n')
        ew11.read_until(b'Restart..')
        
        log('[INFO] EW11 리셋 완료')
        
        # 리셋 후 60초간 Delay
        await asyncio.sleep(60)
        
    
    def initiate_socket():
        # SOCKET 통신 시작
        log('[INFO] Socket 연결을 시작합니다')
            
        retry_count = 0
        while True:
            try:
                soc = socket.socket()
                soc.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                connect_socket(soc)
                return soc
            except ConnectionRefusedError as e:
                log('[ERROR] Server에서 연결을 거부합니다. 재시도 예정 (' + str(retry_count) + '회 재시도)')
                time.sleep(1)
                retry_count += 1
                continue
             
            
    def connect_socket(socket):
        socket.connect((SOC_ADDRESS, SOC_PORT))
    

    async def serial_recv_loop():
        nonlocal soc
        nonlocal MSG_QUEUE
        
        class MSG:
            topic = ''
            payload = bytearray()
        
        msg = MSG()
        
        while True:
            try:
                # EW11 버퍼 크기만큼 데이터 받기
                DATA = soc.recv(EW11_BUFFER_SIZE)
                msg.topic = EW11_TOPIC + '/recv'
                msg.payload = DATA   
                
                MSG_QUEUE.put(msg)
                
            except OSError:
                soc.close()
                soc = initiate_socket(soc)
         
            await asyncio.sleep(SERIAL_RECV_DELAY) 
        
        
    async def state_update_loop():
        nonlocal force_target_time
        nonlocal force_stop_time
        nonlocal FORCE_UPDATE
        
        while True:
            await process_message()                    
            
            timestamp = time.time()
            
            # 정해진 시간이 지나면 FORCE 모드 발동
            if timestamp > force_target_time and not FORCE_UPDATE and FORCE_MODE:
                force_stop_time = timestamp + FORCE_DURATION
                FORCE_UPDATE = True
                log('[INFO] 상태 강제 업데이트 실시')
                
            # 정해진 시간이 지나면 FORCE 모드 종료    
            if timestamp > force_stop_time and FORCE_UPDATE and FORCE_MODE:
                force_target_time = timestamp + FORCE_PERIOD
                FORCE_UPDATE = False
                log('[INFO] 상태 강제 업데이트 종료')
                
            # STATE_LOOP_DELAY 초 대기 후 루프 진행
            await asyncio.sleep(STATE_LOOP_DELAY)
            
            
    async def command_loop():
        nonlocal CMD_QUEUE
        
        while True:
            if not CMD_QUEUE.empty():
                send_data = await CMD_QUEUE.get()
                await send_to_ew11(send_data)               
            
            # COMMAND_LOOP_DELAY 초 대기 후 루프 진행
            await asyncio.sleep(COMMAND_LOOP_DELAY)    
 

    # EW11 재실행 시 리스타트 실시
    async def restart_control():
        nonlocal mqtt_client
        nonlocal restart_flag
        nonlocal MQTT_ONLINE
        
        while True:
            if restart_flag or (not MQTT_ONLINE and ADDON_STARTED and REBOOT_CONTROL):
                if restart_flag:
                    log('[WARNING] EW11 재시작 확인')
                elif not MQTT_ONLINE and ADDON_STARTED and REBOOT_CONTROL:
                    log('[WARNING] 동작 중 MQTT Integration Offline 변경')
                
                # Asyncio Loop 획득
                loop = asyncio.get_event_loop()
                
                # MTTQ 및 socket 연결 종료
                log('[WARNING] 모든 통신 종료')
                mqtt_client.loop_stop()
                if comm_mode == 'mixed' or comm_mode == 'socket':
                    nonlocal soc
                    soc.close()
                       
                # flag 원복
                restart_flag = False
                MQTT_ONLINE = False

                # asyncio loop 종료
                log('[WARNING] asyncio loop 종료')
                loop.stop()
            
            # RESTART_CHECK_DELAY초 마다 실행
            await asyncio.sleep(RESTART_CHECK_DELAY)

        
    # MQTT 통신
    from paho.mqtt.enums import CallbackAPIVersion
    mqtt_client = mqtt.Client(client_id='mqtt_ezville', callback_api_version=CallbackAPIVersion.VERSION1)
    mqtt_client.username_pw_set(config['mqtt_id'], config['mqtt_password'])
    mqtt_client.on_connect = on_connect
    mqtt_client.on_disconnect = on_disconnect
    mqtt_client.on_message = on_message
    mqtt_client.connect_async(config['mqtt_server'])
    
    # asyncio loop 획득 및 EW11 오류시 재시작 task 등록
    loop = asyncio.get_event_loop()
    loop.create_task(restart_control())
        
    # Discovery 및 강제 업데이트 시간 설정
    force_target_time = time.time() + FORCE_PERIOD
    force_stop_time = force_target_time + FORCE_DURATION
    

    while True:
        # MQTT 통신 시작
        mqtt_client.loop_start()
        # MQTT Integration의 Birth/Last Will Testament를 기다림 (1초 단위)
        while not MQTT_ONLINE and REBOOT_CONTROL:
            log('[INFO] Waiting for MQTT connection')
            time.sleep(1)
        
        # socket 통신 시작       
        if comm_mode == 'mixed' or comm_mode == 'socket':
            soc = initiate_socket()  

        log('[INFO] 장치 등록 및 상태 업데이트를 시작합니다')

        tasklist = []
 
        # 필요시 Discovery 등의 지연을 위해 Delay 부여 
        time.sleep(startup_delay)      
  
        # socket 데이터 수신 loop 실행
        if comm_mode == 'socket':
            tasklist.append(loop.create_task(serial_recv_loop()))
        # EW11 패킷 기반 state 업데이트 loop 실행
        tasklist.append(loop.create_task(state_update_loop()))
        # Home Assistant 명령 실행 loop 실행
        tasklist.append(loop.create_task(command_loop()))
        # EW11 상태 체크 loop 실행
        tasklist.append(loop.create_task(ew11_health_loop()))
        
        # ADDON 정상 시작 Flag 설정
        ADDON_STARTED = True
        loop.run_forever()
        
        # 이전 task는 취소
        log('[INFO] 이전 실행 Task 종료')
        for task in tasklist:
            task.cancel()

        ADDON_STARTED = False
        
        # 주요 변수 초기화    
        MSG_QUEUE = Queue()
        CMD_QUEUE = asyncio.Queue()
        DEVICE_STATE = {}
        MSG_CACHE = {}
        DISCOVERY_LIST = []
        RESIDUE = ''



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
            
    with open(config_dir + '/options.json') as file:
        CONFIG = json.load(file)
        ezville_loop(CONFIG)
