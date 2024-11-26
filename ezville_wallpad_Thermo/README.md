# 이지빌 월패드 RS485 Add-on (조명/난방 조회/제어 지원)

## 설정

### mode:
#### `serial_mode` (serial / socket)
* serial: USB to RS485 혹은 TTL to RS485를 이용하는 경우
* socket: EW11을 이용하는 경우

#### `entrance_mode` (off / minimal / full)
* full: 현관 스위치가 없거나 연결을 끊은 경우, 이 애드온이 완전한 현관 스위치로 동작합니다.
* new: 디스플레이가 달린 신형 현관스위치인 경우 full 대신 new로 설정해야 할 수 있습니다.
* minimal: 현관 스위치가 있는 상황에서, 엘리베이터 호출이 필요한 경우만 강제로 끼워넣습니다 (nodejs 애드온과 거의 같은 방식). 성공률이 매우 낮아서 수십 초 이상 걸리는 경우도 있습니다. max\_retry를 적절히 설정하세요.
    * 신형 현관스위치 지원하지 않음
* off: 현관 스위치 관련 기능을 비활성화 합니다. 일반적인 월패드 애드온으로만 동작합니다.

#### wallpad\_mode (on / off)
* on: 일반적인 월패드 애드온 기능
* off: 기존 애드온과 함께 쓰고 싶을 때. 이게 정상동작하는지 아직 테스트되지 않음

#### `intercom_mode` (on / off)
* on: 가상의 인터폰을 추가합니다. 현관문을 열거나, 공동현관 초인종이 울렸을때 공동현관을 열 수 있습니다.
* off: 인터폰 추가 기능을 비활성화합니다.

### serial: (serial\_mode 가 serial 인 경우)

#### `port`
* Supervisor -> System -> HARDWARE 버튼을 눌러 serial에 적혀있는 장치 이름을 확인해서 적어주세요.
* USB to RS485를 쓰신다면 /dev/ttyUSB0, TTL to RS485를 쓰신다면 /dev/ttyAMA0 일 가능성이 높습니다.
* 단, 윈도우 환경이면 COM6 과 같은 형태의 이름을 가지고 있습니다.

#### baudrate, bytesize, parity, stopbits (기본값 9600, 8, E, 1)
* 기본값으로 두시면 됩니다.
* 사용 가능한 parity: E, O, N, M, S (Even, Odd, None, Mark, Space)

### socket: (serial\_mode 가 socket 인 경우)

#### `address`
* EW11의 IP를 적어주세요.

#### port (기본값: 8899)
* EW11의 포트 번호를 변경하셨다면 변경한 포트 번호를 적어주세요.

### MQTT:

#### `server`
* MQTT broker (Mosquitto)의 IP를 적어주세요. 일반적으로 HA가 돌고있는 서버의 IP와 같습니다.

#### port (기본값: 1883)
* Mosquitto의 포트 번호를 변경하셨다면 변경한 포트 번호를 적어주세요.

#### `need_login`
* Mosquitto에 login이 필요하도록 설정하셨으면 (anonymous: false) true로 수정해 주세요.

#### user, passwd
* need\_login이 true인 경우 Mosquitto의 아이디와 비밀번호를 적어주세요.

#### discovery (true / false)
* false로 변경하면 HA에 장치를 자동으로 등록하지 않습니다. 필요한 경우만 변경하세요.

#### prefix (기본값: sds)
* MQTT topic의 시작 단어를 변경합니다. 기본값으로 두시면 됩니다.

### rs485:
#### max\_retry (기본값: 20)
* 실행한 명령에 대한 성공 응답을 받지 못했을 때, 몇 초 동안 재시도할지 설정합니다. 특히 "minimal" 모드인 경우 큰 값이 필요하지만, 예상치 못한 타이밍에 동작하는 상황을 막으려면 적절한 값을 설정하세요.

#### early\_response (기본값: 2)
* 현관 스위치로써 월패드에게 응답하는 타이밍을 조절합니다. 0~2. 특히 "minimal" 모드의 성공률에 약간 영향이 있습니다 (큰 기대는 하지 마세요).

#### dump\_time (기본값: 0)
* 0보다 큰 값을 설정하면, 애드온이 시작하기 전에 입력한 시간(초) 동안 log로 RS485 패킷 덤프를 출력합니다.
* SerialPortMon으로 RS485를 관찰하는 것과 같은 기능입니다.
* 버그/수정 제보 등 패킷 덤프가 필요할 때만 사용하세요.

#### intercom\_header (기본값: A45A)
* 평상시 RS485 덤프에서 A15A, A25A, A35A, A45A, A55A, A65A 중 한 가지가 보여야 intercom\_mode 를 사용할 수 있습니다.
* 보이는 패킷을 입력해 주세요.

### log:
#### to\_file (true / false)
* false로 설정하면 로그를 파일로 남기지 않습니다.
* 로그는 매일 자정에 새 파일로 저장되며, 기존 로그는 파일명에 날짜를 붙여 7개까지 보관됩니다.

#### filename (기본값: /share/sds\_wallpad.log)
* 로그를 남길 경로와 파일 이름을 지정합니다.
