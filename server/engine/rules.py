from abc import ABC, abstractmethod
from .models import ProcessNode, Alert
from .tree import ProcessTree
import re
import base64
import binascii

class BaseRule(ABC):
    name: str
    severity: str
    mitre_technique: str
    description: str

    @abstractmethod
    def check(self, node: ProcessNode, tree: ProcessTree) -> Alert | None:
            
        pass


class OfficeSpawnShellRule(BaseRule):
    name = "MALICIOUS_EXECUTION"
    severity="CRITICAL"
    mitre_technique="T1059"
    description = "Abuse of built-in system shells or scripting interpreters to execute unauthorized or malicious code"

    shells = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
    office_apps = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}

    def check(self, node: ProcessNode, tree: ProcessTree) -> Alert | None:
        if node.image_name.lower() in self.shells:
            if node.parent and node.parent.image_name.lower() in self.office_apps:
                lineage = tree.get_lineage(node.guid)
                alert = Alert(self.name, self.severity, self.mitre_technique, self.description, node, lineage)
                return alert
        
        return None

def extract_and_decode_powershell(command_line: str) -> str | None:
    pattern = re.compile(r"-(?:encodedcommand|enc|e)\b\s+([A-Za-z0-9+/=]+)" , re.IGNORECASE)
    match = pattern.search(command_line)
    raw_b64 = match.group(1)
    if len(raw_b64) > 100_000:
        return None
    try: 
        missing_padding = len(raw_b64) % 4
        if missing_padding != 0:
            raw_b64 += "=" * (4 - missing_padding)
        decoded_b64 = base64.b64decode(raw_b64)
        return decoded_b64.decode('utf-16le', errors='ignore')
    except (binascii.Error, ValueError):
        return None


class SuspiciousEncodedCommandRule(BaseRule):
    name = "SUSPICIOUS_ENCODED_POWERSHELL"
    severity="HIGH"
    mitre_technique="T1059.001 / T1027"
    description = "detection of obfuscated PowerShell commands with characteristics of loaders"

    CRADLE_KEYWORDS = {"iex", "invoke-expression", "downloadstring", "downloadfile", "webclient", "invoke-webrequest", "iwr"}

    def check(self, node: ProcessNode, tree: ProcessTree) -> Alert | None:
        if not (node.image_name.lower() in {"powershell.exe", "pwsh.exe"}):
            return None
        if not node.command_line:
            return None

        decoded = extract_and_decode_powershell(node.command_line)

        if not decoded:
            return None
        if any(keyword in decoded.lower() for keyword in self.CRADLE_KEYWORDS):
            full_description = f"{self.description} | Payload: {decoded[:120]}..."
            alert = Alert(self.name, self.severity, self.mitre_technique, full_description, node, tree.get_lineage(node.guid))
            return alert


class SuspiciousTmpExecutionRule(BaseRule):
    name = "SUSPICIOUS_EXECUTION_FROM_TMP"
    severity="HIGH"
    mitre_technique="T1059 / T1036"
    description = "Execution of binary or script from a world-writable temporary directory (/tmp, /dev/shm, /var/tmp)"

    TMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")
    INTERPRETERS = {"bash", "sh", "dash", "zsh", "python", "python3", "perl", "php"}


    def check(self, node: ProcessNode, tree: ProcessTree) -> Alert | None:
        is_script_in_tmp = (
            node.image_name.lower() in self.INTERPRETERS 
            and any(d in node.command_line.lower() for d in self.TMP_DIRS)
        )

        is_direct_tmp_exec = node.image.lower().startswith(self.TMP_DIRS)

        if  is_direct_tmp_exec or is_script_in_tmp:
            alert = Alert(self.name, self.severity, self.mitre_technique, self.description, node, tree.get_lineage(node.guid))
            return alert
        else:
            return None

    
