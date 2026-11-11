import sys
from pathlib import Path

# Добавляем путь к папке server в пути поиска модулей:
sys.path.append(str(Path(__file__).resolve().parent.parent / "server"))

import grpc
import telemetry_pb2
import telemetry_pb2_grpc


def run():
    with grpc.insecure_channel('localhost:50051') as channel:
        stub = telemetry_pb2_grpc.TelemetryServiceStub(channel)
        request = telemetry_pb2.TelemetryBatch(host_id="test-endpoint-win10", schema_version="1.0")

        event1 = request.events.add()
        event1.sequence_id = 2
        event1.type = telemetry_pb2.PROCESS_EVENT_TYPE_START
        event1.bin_data.image_path = "WINWORD.EXE"
        event1.all_ids.pid = 1000
        event1.all_ids.process_uid = "word-guid-1"

        event2 = request.events.add()
        event2.sequence_id = 3
        event2.type = telemetry_pb2.PROCESS_EVENT_TYPE_START
        event2.bin_data.image_path = "cmd.exe"
        event2.all_ids.pid = 2000
        event2.all_ids.process_uid = "cmd-guid-2"
        event2.all_ids.parent_process_uid = "word-guid-1"



        response = stub.SendTelemetry(request)

        print(f"Ответ сервера: status={response.status}, ack_seq={response.ack_sequence_id}")
        print(f"Команды Active Response (Kill PIDs): {list(response.kill_process_uids)}")

if __name__ == "__main__":
    run()