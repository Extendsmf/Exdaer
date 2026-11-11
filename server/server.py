import grpc
import json
import threading
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
import logging
import telemetry_pb2
import telemetry_pb2_grpc

from engine.engine import DetectionEngine
from engine.models import ProcessNode
from engine.rules import OfficeSpawnShellRule, SuspiciousEncodedCommandRule



EXPECTED_SCHEMA_VERSION = "1.0"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def proto_to_node(event: telemetry_pb2.ProcessEvent) -> ProcessNode:
    return ProcessNode(
        guid=event.all_ids.process_uid,
        pid=event.all_ids.pid,
        image=event.bin_data.image_path,
        command_line=event.bin_data.command_line,
        timestamp=datetime.fromtimestamp(event.timestamp_epoch_ms / 1000.0, tz=timezone.utc),
        user=event.usr_context.username,
        parent_guid=event.all_ids.parent_process_uid or None,
    )

class TelemetryServer(telemetry_pb2_grpc.TelemetryServiceServicer):

    def __init__(self):
        self.engines: dict[str, DetectionEngine] = {}
        self.lock = threading.Lock()
    
    def _get_or_create_engine(self, host_id: str) -> DetectionEngine:
        with self.lock:
            if host_id not in self.engines:
                engine = DetectionEngine()
                engine.register_rule(OfficeSpawnShellRule())
                engine.register_rule(SuspiciousEncodedCommandRule())
                self.engines[host_id] = engine

            return self.engines[host_id]


    def SendTelemetry(self, request, context):

        engine = self._get_or_create_engine(request.host_id)


        if request.schema_version != EXPECTED_SCHEMA_VERSION: # Проверка версии схемы .proto
            return telemetry_pb2.IngestResponse( # Если версия не та, то возврачаем ответ с ошибкой
                status=telemetry_pb2.INGEST_STATUS_CODE_VERSION_MISMATCH,
                ack_sequence_id = 0,
                error_message = f'Error: unsupported schema version: {request.schema_version}. Expected schema version: {EXPECTED_SCHEMA_VERSION}',
                kill_process_uids = [],
            )

        if request.dropped_events_count > 0: # Если очередь событий переполнена, пишем предупреждение в логи
            logging.warning(f'Host {request.host_id} lost {request.dropped_events_count} bucause of buffer overflow')

        alerts = []
        kill_process_uids = []
        max_seq = 0
        for event in request.events: # Ищем максимальный sequense_id, чтобы в ответе указать, до какого ивента мы все обработали
            node = proto_to_node(event)
            alerts.extend(engine.process_event(node))
            max_seq = max(event.sequence_id, max_seq)

        if alerts:
            with open("alerts.jsonl", "a", encoding="utf-8") as f:
                for alert in alerts:
                    kill_process_uids.append(alert.process.guid)

                    f.write(json.dumps(alert.to_dict()) + "\n")

                    chain = " -> ".join([f"{p.image_name} (PID: {p.pid})" for p in alert.lineage])
                    print(f"[!] ALERT TRIGGERED: {alert.rule_name}")
                    print(f"[-] Severity: {alert.severity} | MITRE: {alert.mitre_technique}")
                    print(f"[-] Description: {alert.description}")
                    print(f"[-] Target: {alert.process.image_name} (PID: {alert.process.pid}, User: {alert.process.user})")
                    print(f"[-] Lineage: {chain}\n")

        return telemetry_pb2.IngestResponse(
            status=telemetry_pb2.INGEST_STATUS_CODE_OK,
            ack_sequence_id = max_seq,
            error_message = "",
            kill_process_uids = kill_process_uids,
        )



def serve():
    server = grpc.server(ThreadPoolExecutor(max_workers=10))
    telemetry_pb2_grpc.add_TelemetryServiceServicer_to_server(TelemetryServer(), server)
    server.add_insecure_port("[::]:50051")
    server.start()
    logging.info("XDR Telemetry Server started on port 50051...")
    server.wait_for_termination()

if __name__ == "__main__":
    serve()
    print("Сервер запущен")




