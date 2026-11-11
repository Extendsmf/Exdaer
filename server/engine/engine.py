from .rules import BaseRule
from .models import Alert, ProcessNode
from .tree import ProcessTree

class DetectionEngine:
    def __init__(self):
        self.tree = ProcessTree()
        self.rules: list[BaseRule] = []
        self.seen_alerts: set[tuple[str, str]] = set()

    def register_rule(self, rule: BaseRule) -> None:
        self.rules.append(rule)

    def process_event(self, node: ProcessNode) -> list[Alert]:
        try:
            alerts = []
            self.tree.add_process(node)
    
            nodes_to_check = [node] + node.children
            for target in nodes_to_check:
                for rule in self.rules:
                    alert = rule.check(target, self.tree)
                    if alert:
                        alert_key = (alert.rule_name, alert.process.guid)
                        if alert_key in self.seen_alerts:
                            continue
                        self.seen_alerts.add(alert_key)
                        alerts.append(alert)
        except Exception as e:
                print(f"[DEBUG ERROR in rule]: {e}")

        return alerts