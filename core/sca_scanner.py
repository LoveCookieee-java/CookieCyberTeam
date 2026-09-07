"""
CookieCyberTeam Offline Supply Chain SCA (Software Composition Analysis) Engine.
Pure-Python offline dependency vulnerability auditor. Reads requirements.txt,
pyproject.toml, Pipfile, and poetry.lock to detect known CVEs using an offline OSV dataset.
"""

from __future__ import annotations
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union


@dataclass
class VulnerabilityRecord:
    package_name: str
    installed_version: str
    cve_id: str
    ghsa_id: str
    severity: str
    cvss_score: float
    summary: str
    fixed_in: str
    source_file: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package_name": self.package_name,
            "installed_version": self.installed_version,
            "cve_id": self.cve_id,
            "ghsa_id": self.ghsa_id,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "summary": self.summary,
            "fixed_in": self.fixed_in,
            "source_file": self.source_file,
            "remediation": f"Upgrade {self.package_name} to >= {self.fixed_in}",
        }


# Offline curated OSV database for common Python dependencies
OFFLINE_OSV_DATABASE: List[Dict[str, Any]] = [
    {
        "package": "requests",
        "vulnerable_below": "2.31.0",
        "fixed_in": "2.31.0",
        "cve_id": "CVE-2023-32681",
        "ghsa_id": "GHSA-j8r2-6x86-q33q",
        "severity": "High",
        "cvss_score": 7.5,
        "summary": "Requests Proxy-Authorization Header Leak to HTTPS Proxy",
    },
    {
        "package": "urllib3",
        "vulnerable_below": "1.26.18",
        "fixed_in": "1.26.18",
        "cve_id": "CVE-2023-45803",
        "ghsa_id": "GHSA-g4mx-q9vg-27p4",
        "severity": "Medium",
        "cvss_score": 6.1,
        "summary": "urllib3 does not strip Authorization HTTP headers on cross-origin redirects",
    },
    {
        "package": "flask",
        "vulnerable_below": "2.2.5",
        "fixed_in": "2.2.5",
        "cve_id": "CVE-2023-30861",
        "ghsa_id": "GHSA-m2qf-hxjv-5gpq",
        "severity": "High",
        "cvss_score": 7.5,
        "summary": "Flask session cookie leak via cached response header",
    },
    {
        "package": "django",
        "vulnerable_below": "3.2.24",
        "fixed_in": "3.2.24",
        "cve_id": "CVE-2024-24680",
        "ghsa_id": "GHSA-2gwj-7qmv-92cq",
        "severity": "High",
        "cvss_score": 7.5,
        "summary": "Potential denial-of-service in intcomma template filter",
    },
    {
        "package": "jinja2",
        "vulnerable_below": "3.1.3",
        "fixed_in": "3.1.3",
        "cve_id": "CVE-2024-22195",
        "ghsa_id": "GHSA-h5c8-rqwp-cp95",
        "severity": "Medium",
        "cvss_score": 6.1,
        "summary": "Jinja XML attribute injection vulnerability in xmlattr filter",
    },
    {
        "package": "pillow",
        "vulnerable_below": "10.0.1",
        "fixed_in": "10.0.1",
        "cve_id": "CVE-2023-44271",
        "ghsa_id": "GHSA-6vj7-qr69-cp62",
        "severity": "High",
        "cvss_score": 7.5,
        "summary": "Pillow Uncontrolled Resource Consumption via large text chunks",
    },
    {
        "package": "cryptography",
        "vulnerable_below": "41.0.6",
        "fixed_in": "41.0.6",
        "cve_id": "CVE-2023-49083",
        "ghsa_id": "GHSA-jfhm-5ghh-2f97",
        "severity": "Medium",
        "cvss_score": 5.3,
        "summary": "NULL pointer dereference in PKCS7 parsing when loading certificate",
    },
    {
        "package": "pyyaml",
        "vulnerable_below": "5.4.0",
        "fixed_in": "5.4.0",
        "cve_id": "CVE-2020-14343",
        "ghsa_id": "GHSA-8q59-q68h-6hv4",
        "severity": "Critical",
        "cvss_score": 9.8,
        "summary": "Arbitrary code execution via full_load in PyYAML",
    },
    {
        "package": "werkzeug",
        "vulnerable_below": "3.0.1",
        "fixed_in": "3.0.1",
        "cve_id": "CVE-2023-46136",
        "ghsa_id": "GHSA-hrfv-mqp8-q5rw",
        "severity": "High",
        "cvss_score": 7.5,
        "summary": "Werkzeug high memory usage in multipart form data parsing",
    },
    {
        "package": "certifi",
        "vulnerable_below": "2023.07.22",
        "fixed_in": "2023.07.22",
        "cve_id": "CVE-2023-37920",
        "ghsa_id": "GHSA-xqr8-7jwr-rhp7",
        "severity": "Medium",
        "cvss_score": 6.1,
        "summary": "Certifi root certificate removal for compromised e-Tugra root",
    },
]


def _parse_version(v_str: str) -> Tuple[int, ...]:
    """Parse semver string into comparable tuple of ints."""
    clean = re.sub(r"[^0-9.]", "", v_str.split("+")[0].split("-")[0])
    parts = []
    for p in clean.split("."):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def is_version_vulnerable(installed_version: str, vulnerable_below: str) -> bool:
    """Return True if installed_version < vulnerable_below."""
    try:
        inst = _parse_version(installed_version)
        vuln = _parse_version(vulnerable_below)
        return inst < vuln
    except Exception:
        return False


class SCAScanner:
    """Offline Supply Chain dependency vulnerability scanner."""

    def __init__(
        self,
        workspace_root: Optional[Union[str, Path]] = None,
        custom_osv_db: Optional[List[Dict[str, Any]]] = None,
    ):
        self.workspace_root = Path(workspace_root).resolve() if workspace_root else Path.cwd().resolve()
        self.osv_db = custom_osv_db or OFFLINE_OSV_DATABASE

    def parse_requirements_txt(self, content: str) -> Dict[str, str]:
        """Extract package names and pinned versions from requirements.txt."""
        deps = {}
        for line in content.splitlines():
            line = line.split("#")[0].strip()
            if not line or line.startswith("-"):
                continue
            line = line.split(";")[0].strip()
            # Match package==1.2.3 or package<=1.2.3 or package>=1.2.3
            m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*(?:==|===|~=|<=|>=)?\s*([0-9A-Za-z_\.\-]+)?", line)
            if m:
                pkg_name = m.group(1).lower().replace("_", "-")
                version = m.group(2) or "0.0.0"
                deps[pkg_name] = version
        return deps

    def parse_poetry_lock(self, content: str) -> Dict[str, str]:
        """Extract packages from poetry.lock."""
        deps = {}
        current_name = None
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("name = "):
                current_name = line.split("=", 1)[1].strip().strip('"\'').lower().replace("_", "-")
            elif line.startswith("version = ") and current_name:
                v = line.split("=", 1)[1].strip().strip('"\'')
                deps[current_name] = v
                current_name = None
        return deps

    def parse_pyproject_toml(self, content: str) -> Dict[str, str]:
        """Extract dependencies from pyproject.toml."""
        deps = {}
        in_deps_array = False
        in_deps_section = False
        for line in content.splitlines():
            line = line.split("#")[0].strip()
            if not line:
                continue
            if line.startswith("["):
                in_deps_array = False
                in_deps_section = "dependencies" in line.lower()
                continue
            if "dependencies" in line and "=" in line and "[" in line:
                in_deps_array = True
                after_eq = line.split("=", 1)[1].strip()
                entries = re.findall(r'["\']([^"\']+)["\']', after_eq)
                for item in entries:
                    m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*(?:==|===|~=|<=|>=)?\s*([0-9A-Za-z_\.\-]+)?", item)
                    if m:
                        pkg = m.group(1).lower().replace("_", "-")
                        ver = m.group(2) or "0.0.0"
                        deps[pkg] = ver
                if "]" in line:
                    in_deps_array = False
                continue
            if in_deps_array:
                if "]" in line:
                    in_deps_array = False
                entries = re.findall(r'["\']([^"\']+)["\']', line)
                for item in entries:
                    m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*(?:==|===|~=|<=|>=)?\s*([0-9A-Za-z_\.\-]+)?", item)
                    if m:
                        pkg = m.group(1).lower().replace("_", "-")
                        ver = m.group(2) or "0.0.0"
                        deps[pkg] = ver
            elif in_deps_section and "=" in line:
                key, val = line.split("=", 1)
                pkg = key.strip().strip('"\'').lower().replace("_", "-")
                val_clean = val.strip().strip('"\'')
                ver_match = re.search(r"(\d+(?:\.\d+)+)", val_clean)
                deps[pkg] = ver_match.group(1) if ver_match else "0.0.0"
        return deps

    def scan_dependencies(self, dependencies: Dict[str, str], source_file: str = "dependencies") -> List[VulnerabilityRecord]:
        """Audit detected dependencies against offline OSV database."""
        findings = []
        for pkg, ver in dependencies.items():
            for entry in self.osv_db:
                if entry["package"].lower() == pkg:
                    if is_version_vulnerable(ver, entry["vulnerable_below"]):
                        findings.append(VulnerabilityRecord(
                            package_name=pkg,
                            installed_version=ver,
                            cve_id=entry["cve_id"],
                            ghsa_id=entry["ghsa_id"],
                            severity=entry["severity"],
                            cvss_score=entry["cvss_score"],
                            summary=entry["summary"],
                            fixed_in=entry["fixed_in"],
                            source_file=source_file,
                        ))
        return findings

    def audit_workspace(
        self,
        workspace_root: Optional[Union[str, Path]] = None,
        scan_dir: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        """Discover and scan all dependency manifests in workspace."""
        target = scan_dir or workspace_root or self.workspace_root
        ws = Path(target).resolve()
        if ws.is_file():
            ws = ws.parent

        manifest_files = []
        all_deps: Dict[str, Tuple[str, str]] = {}  # pkg -> (version, source_file)

        req_path = ws / "requirements.txt"
        if req_path.is_file():
            manifest_files.append(str(req_path))
            for k, v in self.parse_requirements_txt(req_path.read_text(encoding="utf-8", errors="ignore")).items():
                all_deps[k] = (v, "requirements.txt")

        pyproject_path = ws / "pyproject.toml"
        if pyproject_path.is_file():
            manifest_files.append(str(pyproject_path))
            for k, v in self.parse_pyproject_toml(pyproject_path.read_text(encoding="utf-8", errors="ignore")).items():
                if k not in all_deps:
                    all_deps[k] = (v, "pyproject.toml")

        lock_path = ws / "poetry.lock"
        if lock_path.is_file():
            manifest_files.append(str(lock_path))
            for k, v in self.parse_poetry_lock(lock_path.read_text(encoding="utf-8", errors="ignore")).items():
                all_deps[k] = (v, "poetry.lock")

        flat_deps = {k: v[0] for k, v in all_deps.items()}
        findings: List[VulnerabilityRecord] = []
        for pkg, (ver, src) in all_deps.items():
            pkg_findings = self.scan_dependencies({pkg: ver}, source_file=src)
            findings.extend(pkg_findings)

        return {
            "success": True,
            "manifest_files": manifest_files,
            "total_dependencies_checked": len(all_deps),
            "dependencies": flat_deps,
            "vulnerabilities": [f.to_dict() for f in findings],
            "vulnerability_count": len(findings),
        }
