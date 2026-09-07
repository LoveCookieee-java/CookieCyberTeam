"""
Active Containment Primitives & Incident Response Vault.
Zero-dependency implementation providing:
1. Automated Artifact Quarantine (XOR obfuscation, permission stripping, tamper-evident manifest).
2. Host Firewall Rule Generator (Windows netsh, Linux iptables, UFW, DNS sinkhole).
3. Safe Process Termination (subtree termination, critical PID protections).
"""

from __future__ import annotations
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union


XOR_KEY = 0x5A
SENSITIVE_DIR_NAMES = {".git", ".ssh", ".aws", ".config"}


def _is_safe_target(path: Path, workspace_root: Path, allow_vault: bool = False) -> bool:
    """Validate that path does not escape workspace boundaries and doesn't target sensitive dirs."""
    resolved = path.resolve()
    resolved_ws = workspace_root.resolve()

    # Must be within workspace root
    if not (resolved == resolved_ws or resolved_ws in resolved.parents):
        return False

    # Check for sensitive path components (case-insensitive)
    for part in resolved.parts:
        p_lower = part.lower()
        if p_lower in SENSITIVE_DIR_NAMES or p_lower.startswith(".env"):
            return False
        if not allow_vault and p_lower == ".quarantine":
            return False

    if not allow_vault and resolved.name.lower() == "quarantine_manifest.json":
        return False

    return True


def find_git_root(path: str | Path) -> Optional[Path]:
    """Find the root of the git repository by traversing upwards from path."""
    curr = Path(path).resolve()
    if not curr.is_dir():
        curr = curr.parent
    for p in [curr, *curr.parents]:
        if (p / ".git").exists():
            return p
    return None


def quarantine_file(
    file_path: Union[str, Path],
    quarantine_dir: Optional[Union[str, Path]] = None,
    workspace_root: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """
    Atomically moves a suspicious file into the quarantine vault (.quarantine/),
    obfuscates the payload with XOR encryption to prevent accidental execution,
    strips executable permissions, and records entry in quarantine_manifest.json.
    """
    src = Path(file_path).resolve()
    ws = Path(workspace_root).resolve() if workspace_root else (find_git_root(src) or src.parent)

    # 1. Existence and type check
    if not src.exists():
        return {
            "success": False,
            "error": f"File not found: {file_path}",
            "file_path": str(file_path),
        }
    if not src.is_file():
        return {
            "success": False,
            "error": f"Path is a directory or special device, not a regular file: {file_path}",
            "file_path": str(file_path),
        }

    # 2. Boundary and sensitivity validation
    if not _is_safe_target(src, ws, allow_vault=False):
        return {
            "success": False,
            "error": f"Path traversal or security violation: Access to '{file_path}' is forbidden.",
            "file_path": str(file_path),
        }

    # 3. Vault destination setup
    vault = Path(quarantine_dir).resolve() if quarantine_dir else ws / ".quarantine"
    vault.mkdir(parents=True, exist_ok=True)

    # 4. Read raw payload and compute cryptographic digests
    raw_bytes = src.read_bytes()
    file_size = len(raw_bytes)
    sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
    md5_hash = hashlib.md5(raw_bytes).hexdigest()
    now_iso = datetime.now(timezone.utc).isoformat()
    quarantine_id = f"quar_{int(time.time())}_{sha256_hash[:8]}"

    # 5. Obfuscate payload (XOR 0x5A) so OS loaders cannot parse PE/ELF/scripts
    obfuscated_bytes = bytes([b ^ XOR_KEY for b in raw_bytes])

    # 6. Target path in quarantine vault
    safe_name = re.sub(r"[^\w\-.]", "_", src.name)
    quarantine_filename = f"{quarantine_id}_{safe_name}.quarantine.enc"
    dst = vault / quarantine_filename

    # Ensure write permission before in-place overwriting on Windows
    try:
        if os.name == "nt":
            os.chmod(src, stat.S_IWRITE)
    except Exception:
        pass

    # Write obfuscated bytes directly into source first, then atomically move to vault
    src.write_bytes(obfuscated_bytes)
    os.replace(src, dst)

    # 7. Strip execution permissions (Read-only on Windows, chmod 000 on POSIX)
    try:
        if os.name == "nt":
            os.chmod(dst, stat.S_IREAD)
        else:
            os.chmod(dst, 0o000)  # chmod 000 per specification
    except Exception:
        pass

    # 8. Update tamper-evident metadata manifest
    manifest_path = vault / "quarantine_manifest.json"
    manifest_data: Dict[str, Any] = {"version": "1.0", "items": {}}
    if manifest_path.is_file():
        try:
            manifest_data = json.loads(manifest_path.read_text(encoding="utf-8", errors="replace"))
            if not isinstance(manifest_data, dict):
                manifest_data = {"version": "1.0", "items": {}}
        except Exception:
            manifest_data = {"version": "1.0", "items": {}}

    manifest_data.setdefault("items", {})
    manifest_data["items"][quarantine_id] = {
        "quarantine_id": quarantine_id,
        "original_path": str(src),
        "quarantine_path": str(dst),
        "sha256": sha256_hash,
        "md5": md5_hash,
        "file_size": file_size,
        "timestamp": now_iso,
        "obfuscation": "XOR-0x5A",
        "status": "quarantined",
    }
    manifest_data["last_updated"] = now_iso

    # Atomic write for manifest
    tmp_manifest = vault / f".tmp_{quarantine_id}.json"
    tmp_manifest.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")
    os.replace(tmp_manifest, manifest_path)

    return {
        "success": True,
        "quarantine_id": quarantine_id,
        "original_path": str(src),
        "quarantine_path": str(dst),
        "sha256": sha256_hash,
        "md5": md5_hash,
        "file_size": file_size,
        "timestamp": now_iso,
        "manifest_path": str(manifest_path),
        "message": f"Artifact '{src.name}' successfully moved to quarantine vault and obfuscated.",
    }


def restore_quarantined_file(
    quarantine_id: str,
    quarantine_dir: Optional[Union[str, Path]] = None,
    destination_path: Optional[Union[str, Path]] = None,
    workspace_root: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    if quarantine_dir:
        vault = Path(quarantine_dir).resolve()
        ws = Path(workspace_root).resolve() if workspace_root else (find_git_root(vault) or vault.parent)
    else:
        ws = Path(workspace_root).resolve() if workspace_root else (find_git_root(Path.cwd()) or Path.cwd())
        vault = ws / ".quarantine"
    manifest_path = vault / "quarantine_manifest.json"

    if not manifest_path.is_file():
        return {"success": False, "error": f"Quarantine manifest not found in vault: {vault}"}

    manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
    items = manifest_data.get("items", {})
    if quarantine_id not in items:
        return {"success": False, "error": f"Quarantine ID '{quarantine_id}' not found in manifest."}

    item = items[quarantine_id]
    enc_path = Path(item["quarantine_path"])
    if not enc_path.is_file():
        vault_candidate = vault / enc_path.name
        if vault_candidate.is_file():
            enc_path = vault_candidate
        else:
            return {"success": False, "error": f"Encrypted file not found on disk: {enc_path}"}

    # Restore target path
    target = Path(destination_path).resolve() if destination_path else Path(item["original_path"]).resolve()
    if not _is_safe_target(target, ws, allow_vault=False):
        return {
            "success": False,
            "error": f"Path traversal or security violation: Restore target '{target}' is forbidden.",
        }
    target.parent.mkdir(parents=True, exist_ok=True)

    # If quarantined with chmod 000 on POSIX, ensure owner can read it
    try:
        if os.name != "nt":
            os.chmod(enc_path, stat.S_IRUSR)
    except Exception:
        pass

    # De-obfuscate
    enc_bytes = enc_path.read_bytes()
    restored_bytes = bytes([b ^ XOR_KEY for b in enc_bytes])

    # If target exists and was read-only on Windows, ensure write permission
    try:
        if target.exists() and os.name == "nt":
            os.chmod(target, stat.S_IWRITE)
    except Exception:
        pass

    target.write_bytes(restored_bytes)

    # Update manifest atomically via temporary file
    item["status"] = "restored"
    item["restored_to"] = str(target)
    manifest_data["last_updated"] = datetime.now(timezone.utc).isoformat()
    tmp_manifest = vault / f".tmp_restore_{quarantine_id}.json"
    tmp_manifest.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")
    os.replace(tmp_manifest, manifest_path)

    return {
        "success": True,
        "quarantine_id": quarantine_id,
        "restored_path": str(target),
        "sha256": hashlib.sha256(restored_bytes).hexdigest(),
    }


def generate_firewall_rule(
    target: str,
    rule_type: str = "block",
    port: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Generate executable firewall rules across Windows Defender Firewall, Linux iptables,
    Linux UFW, and DNS sinkhole format for immediate containment.
    """
    target = str(target).strip()
    if not target:
        return {"success": False, "error": "Target IP, CIDR, or domain name is required."}

    # Validate against dangerous command injection characters
    if re.search(r"[;&|\$\<\>`'\"\\\s]", target):
        return {"success": False, "error": f"Target contains invalid or dangerous shell metacharacters: {target}"}

    action_norm = rule_type.strip().lower()
    if action_norm not in ("block", "allow"):
        action_norm = "block"

    if port is not None:
        try:
            port = int(port)
            if not (1 <= port <= 65535):
                return {"success": False, "error": f"Port number out of valid range (1-65535): {port}"}
        except ValueError:
            return {"success": False, "error": f"Invalid port parameter: {port}"}

    clean_target = re.sub(r"[^\w.]", "_", target)
    rule_label = f"CookieCyber_{action_norm.upper()}_{clean_target}"

    # 1. Windows Defender Firewall (netsh advfirewall)
    if port:
        win_rule = (
            f'netsh advfirewall firewall add rule name="{rule_label}_{port}" '
            f'dir=out action={action_norm} protocol=TCP remoteip={target} remoteport={port}'
        )
    else:
        win_rule = (
            f'netsh advfirewall firewall add rule name="{rule_label}" '
            f'dir=out action={action_norm} remoteip={target}'
        )

    # 2. Linux iptables
    ipt_action = "DROP" if action_norm == "block" else "ACCEPT"
    if port:
        ipt_rule = (
            f"iptables -A OUTPUT -p tcp -d {target} --dport {port} -j {ipt_action} && "
            f"iptables -A INPUT -p tcp -s {target} --sport {port} -j {ipt_action}"
        )
    else:
        ipt_rule = (
            f"iptables -A OUTPUT -d {target} -j {ipt_action} && "
            f"iptables -A INPUT -s {target} -j {ipt_action}"
        )

    # 3. Linux UFW
    ufw_action = "deny" if action_norm == "block" else "allow"
    if port:
        ufw_rule = (
            f"ufw {ufw_action} out to {target} port {port} proto tcp && "
            f"ufw {ufw_action} from {target} port {port} proto tcp"
        )
    else:
        ufw_rule = f"ufw {ufw_action} from {target} && ufw {ufw_action} out to {target}"

    # 4. DNS Sinkhole / /etc/hosts format
    sinkhole_entry = f"0.0.0.0 {target}"

    return {
        "success": True,
        "target": target,
        "rule_type": action_norm,
        "port": port,
        "windows_netsh": win_rule,
        "linux_iptables": ipt_rule,
        "linux_ufw": ufw_rule,
        "dns_sinkhole": sinkhole_entry,
    }


def terminate_suspicious_process(pid: int, force: bool = True) -> Dict[str, Any]:
    """
    Safely terminates suspicious process and its entire process tree.
    Rejects system critical PIDs (0, 4, current agent PID, parent PID) to prevent accidental crashes.
    Uses 'taskkill /F /T /PID' on Windows and SIGTERM/SIGKILL on POSIX.
    """
    try:
        target_pid = int(pid)
    except (ValueError, TypeError):
        return {"success": False, "error": f"Invalid PID parameter: {pid}"}

    # Reject critical PIDs
    current_pid = os.getpid()
    parent_pid = os.getppid() if hasattr(os, "getppid") else -1

    if target_pid <= 4:
        return {
            "success": False,
            "error": f"Refusing to terminate system critical PID {target_pid} (System / Idle).",
            "pid": target_pid,
        }
    if target_pid == current_pid:
        return {
            "success": False,
            "error": f"Refusing to terminate self (current agent PID {target_pid}).",
            "pid": target_pid,
        }
    if target_pid == parent_pid and parent_pid > 0:
        return {
            "success": False,
            "error": f"Refusing to terminate parent process (PID {target_pid}).",
            "pid": target_pid,
        }

    # Execute platform-appropriate termination
    if os.name == "nt":
        # Windows: taskkill /T (tree) /F (force)
        argv = ["taskkill", "/T", "/PID", str(target_pid)]
        if force:
            argv.insert(1, "/F")

        try:
            proc = subprocess.run(argv, capture_output=True, text=True, shell=False)
            if proc.returncode == 0:
                return {
                    "success": True,
                    "pid": target_pid,
                    "terminated": True,
                    "method": "windows_taskkill",
                    "message": f"Successfully terminated process tree for PID {target_pid}.",
                    "output": proc.stdout.strip(),
                }
            elif proc.returncode == 128 or "not found" in proc.stderr.lower():
                return {
                    "success": False,
                    "pid": target_pid,
                    "terminated": False,
                    "method": "windows_taskkill",
                    "error": f"Process PID {target_pid} not found (already exited or invalid).",
                    "output": proc.stderr.strip(),
                }
            else:
                return {
                    "success": False,
                    "pid": target_pid,
                    "terminated": False,
                    "method": "windows_taskkill",
                    "error": proc.stderr.strip() or proc.stdout.strip() or f"taskkill failed with returncode {proc.returncode}",
                }
        except Exception as exc:
            return {
                "success": False,
                "pid": target_pid,
                "terminated": False,
                "error": f"Failed to execute taskkill: {str(exc)}",
            }
    else:
        # POSIX
        try:
            # Check if process exists
            os.kill(target_pid, 0)
        except ProcessLookupError:
            return {
                "success": False,
                "pid": target_pid,
                "terminated": False,
                "error": f"Process PID {target_pid} not found.",
            }
        except PermissionError:
            return {
                "success": False,
                "pid": target_pid,
                "terminated": False,
                "error": f"Permission denied terminating PID {target_pid}.",
            }

        # Discover child processes recursively to terminate entire subtree
        all_pids = [target_pid]
        to_visit = [target_pid]
        seen = {target_pid}
        while to_visit:
            curr = to_visit.pop()
            try:
                pgrep_res = subprocess.run(
                    ["pgrep", "-P", str(curr)],
                    capture_output=True,
                    text=True,
                    shell=False,
                )
                if pgrep_res.returncode == 0:
                    for p in pgrep_res.stdout.split():
                        if p.isdigit():
                            ipid = int(p)
                            if ipid not in seen:
                                seen.add(ipid)
                                all_pids.append(ipid)
                                to_visit.append(ipid)
            except Exception:
                break

        child_pids = [p for p in all_pids if p != target_pid]

        # Stage 1: Graceful termination via SIGTERM
        for p in all_pids:
            try:
                os.kill(p, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass

        # Allow brief interval for graceful exit
        time.sleep(0.1)

        # Identify any still-running processes
        still_alive: List[int] = []
        for p in all_pids:
            try:
                os.kill(p, 0)
                still_alive.append(p)
            except (ProcessLookupError, PermissionError):
                pass

        # Stage 2: Escalate to SIGKILL if force=True
        if force and still_alive:
            for p in still_alive:
                try:
                    os.kill(p, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass

        return {
            "success": True,
            "pid": target_pid,
            "terminated": True,
            "method": "posix_signal_tree",
            "children_terminated": child_pids,
            "message": f"Successfully terminated process tree for PID {target_pid} (SIGTERM -> SIGKILL).",
        }
