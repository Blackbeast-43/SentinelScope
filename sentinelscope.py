#!/usr/bin/env python3

import os
import platform
import socket
import subprocess
import datetime
import json
import hashlib
from pathlib import Path

import psutil

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


# ==========================================================
# SENTINELSCOPE CONFIGURATION
# ==========================================================

TOOL_NAME = "SentinelScope"
VERSION = "1.0.0"

AUTHOR = "ADHITHYAN SAJI KUMAR"
GITHUB = "https://github.com/Blackbeast-43"

console = Console()


# Ports that deserve review if exposed
RISKY_PORTS = {
    21: ("FTP", "MEDIUM"),
    23: ("Telnet", "HIGH"),
    445: ("SMB", "MEDIUM"),
    1433: ("Microsoft SQL Server", "MEDIUM"),
    3306: ("MySQL", "MEDIUM"),
    3389: ("Remote Desktop", "MEDIUM"),
    5432: ("PostgreSQL", "MEDIUM"),
    5900: ("VNC", "MEDIUM"),
    6379: ("Redis", "HIGH"),
    9200: ("Elasticsearch", "MEDIUM"),
    11211: ("Memcached", "HIGH"),
}


# Ports that may deserve investigation for outbound connections.
# These DO NOT automatically mean malware.
REVIEW_REMOTE_PORTS = {
    1337,
    4444,
    5555,
    6666,
    6667,
    31337,
}


WINDOWS_SYSTEM_PROCESSES = {
    "svchost.exe",
    "lsass.exe",
    "csrss.exe",
    "services.exe",
    "winlogon.exe",
    "smss.exe",
    "wininit.exe",
}


# ==========================================================
# UI
# ==========================================================

def banner():

    console.clear()

    title = Text()

    title.append(
        "SENTINELSCOPE\n",
        style="bold bright_cyan"
    )

    title.append(
        "Endpoint Vulnerability & Threat Assessment\n",
        style="bold white"
    )

    title.append(
        f"Version {VERSION}\n",
        style="dim"
    )

    title.append(
        f"Created by {AUTHOR}",
        style="bold green"
    )

    console.print(
        Panel(
            title,
            border_style="bright_cyan",
            padding=(1, 4)
        )
    )

    console.print(
        "[dim]"
        "Defensive endpoint security assessment tool. "
        "Findings are indicators and should be manually verified."
        "[/dim]\n"
    )


def pause():

    console.input(
        "\n[dim]Press ENTER to return to the menu...[/dim]"
    )


# ==========================================================
# GENERAL HELPERS
# ==========================================================

def run_command(command):

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10
        )

        return (
            result.returncode,
            result.stdout.strip(),
            result.stderr.strip()
        )

    except Exception:

        return 1, "", ""


def get_process_name(pid):

    if pid is None:
        return "Unknown"

    try:

        return psutil.Process(pid).name()

    except Exception:

        return "Unknown"


def calculate_hash(file_path):

    try:

        path = Path(file_path)

        if not path.exists():
            return None

        # Avoid hashing massive files
        if path.stat().st_size > 100 * 1024 * 1024:
            return "Skipped (>100MB)"

        sha256 = hashlib.sha256()

        with open(path, "rb") as file:

            while True:

                data = file.read(1024 * 1024)

                if not data:
                    break

                sha256.update(data)

        return sha256.hexdigest()

    except Exception:

        return None


def create_finding(
    severity,
    title,
    evidence,
    recommendation
):

    return {
        "severity": severity,
        "title": title,
        "evidence": evidence,
        "recommendation": recommendation
    }


def display_findings(findings, title):

    table = Table(title=title)

    table.add_column(
        "Severity",
        width=10
    )

    table.add_column(
        "Finding"
    )

    table.add_column(
        "Evidence"
    )

    table.add_column(
        "Recommendation"
    )

    if not findings:

        console.print(
            Panel(
                "[green]"
                "No indicators matched the current detection rules."
                "[/green]",
                title=title
            )
        )

        return

    priority = {
        "CRITICAL": 5,
        "HIGH": 4,
        "MEDIUM": 3,
        "LOW": 2,
        "INFO": 1
    }

    findings.sort(
        key=lambda x: priority.get(
            x["severity"],
            0
        ),
        reverse=True
    )

    colors = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "green"
    }

    for item in findings:

        style = colors.get(
            item["severity"],
            "white"
        )

        table.add_row(
            f"[{style}]{item['severity']}[/]",
            item["title"],
            item["evidence"],
            item["recommendation"]
        )

    console.print(table)


# ==========================================================
# SYSTEM INFORMATION
# ==========================================================

def system_information():

    memory = psutil.virtual_memory()

    boot_time = datetime.datetime.fromtimestamp(
        psutil.boot_time()
    )

    information = {

        "hostname":
            socket.gethostname(),

        "operating_system":
            platform.system(),

        "release":
            platform.release(),

        "architecture":
            platform.machine(),

        "python_version":
            platform.python_version(),

        "cpu_count":
            psutil.cpu_count(),

        "memory_gb":
            round(
                memory.total / (1024 ** 3),
                2
            ),

        "boot_time":
            str(boot_time)
    }

    table = Table(
        title="System Information"
    )

    table.add_column(
        "Property",
        style="cyan"
    )

    table.add_column(
        "Value"
    )

    for key, value in information.items():

        table.add_row(
            key.replace("_", " ").title(),
            str(value)
        )

    console.print(table)

    return information


# ==========================================================
# FIREWALL CHECK
# ==========================================================

def check_firewall():

    operating_system = platform.system()

    # Windows
    if operating_system == "Windows":

        code, output, error = run_command(
            [
                "netsh",
                "advfirewall",
                "show",
                "allprofiles",
                "state"
            ]
        )

        if code == 0:

            if "ON" in output.upper():

                return True

        return False


    # Linux
    elif operating_system == "Linux":

        # UFW
        code, output, error = run_command(
            [
                "ufw",
                "status"
            ]
        )

        if code == 0:

            if "Status: active" in output:

                return True


        # firewalld
        code, output, error = run_command(
            [
                "firewall-cmd",
                "--state"
            ]
        )

        if code == 0:

            if "running" in output.lower():

                return True


        # iptables
        code, output, error = run_command(
            [
                "iptables",
                "-S"
            ]
        )

        if code == 0 and output:

            return True


    return False


# ==========================================================
# LISTENING PORTS
# ==========================================================

def get_listening_ports():

    listeners = []

    try:

        connections = psutil.net_connections(
            kind="inet"
        )

    except Exception:

        return listeners


    for connection in connections:

        if connection.status != psutil.CONN_LISTEN:
            continue

        if not connection.laddr:
            continue

        try:

            ip = connection.laddr.ip
            port = connection.laddr.port

        except Exception:

            continue


        listeners.append({

            "ip": ip,

            "port": port,

            "pid": connection.pid,

            "process":
                get_process_name(
                    connection.pid
                )
        })


    return listeners


# ==========================================================
# SECURITY / VULNERABILITY SCAN
# ==========================================================

def vulnerability_scan():

    findings = []


    # --------------------------
    # Firewall
    # --------------------------

    if check_firewall():

        findings.append(

            create_finding(
                "INFO",
                "Host firewall detected",
                "Firewall appears to be active.",
                "Keep the firewall enabled and review inbound rules."
            )
        )

    else:

        findings.append(

            create_finding(
                "MEDIUM",
                "Firewall could not be confirmed",
                "SentinelScope could not verify an active host firewall.",
                "Verify Windows Defender Firewall, UFW, firewalld or another firewall."
            )
        )


    # --------------------------
    # Exposed services
    # --------------------------

    listeners = get_listening_ports()


    for item in listeners:

        port = item["port"]

        if port not in RISKY_PORTS:
            continue


        service, severity = RISKY_PORTS[
            port
        ]


        # Listening on every interface
        exposed = (
            item["ip"] == "0.0.0.0"
            or
            item["ip"] == "::"
        )


        if not exposed:

            severity = "LOW"


        findings.append(

            create_finding(

                severity,

                f"{service} service detected",

                (
                    f"{item['process']} "
                    f"(PID {item['pid']}) "
                    f"listening on "
                    f"{item['ip']}:{port}"
                ),

                (
                    "Confirm that this service is required. "
                    "Restrict access using firewall rules."
                )
            )
        )


    # --------------------------
    # Linux SSH
    # --------------------------

    if platform.system() == "Linux":

        ssh_config = Path(
            "/etc/ssh/sshd_config"
        )

        if ssh_config.exists():

            try:

                content = ssh_config.read_text(
                    errors="ignore"
                ).lower()


                if (
                    "permitrootlogin yes"
                    in content
                ):

                    findings.append(

                        create_finding(

                            "HIGH",

                            "SSH root login enabled",

                            "PermitRootLogin yes",

                            (
                                "Disable direct root SSH login "
                                "and use sudo with named accounts."
                            )
                        )
                    )


                if (
                    "passwordauthentication yes"
                    in content
                ):

                    findings.append(

                        create_finding(

                            "MEDIUM",

                            "SSH password authentication enabled",

                            "PasswordAuthentication yes",

                            (
                                "Consider SSH key authentication "
                                "where appropriate."
                            )
                        )
                    )

            except Exception:

                pass


    # --------------------------
    # Windows SMBv1
    # --------------------------

    if platform.system() == "Windows":

        command = [

            "powershell",

            "-NoProfile",

            "-Command",

            (
                "(Get-WindowsOptionalFeature "
                "-Online "
                "-FeatureName SMB1Protocol "
                "-ErrorAction SilentlyContinue).State"
            )
        ]


        code, output, error = run_command(
            command
        )


        if (
            code == 0
            and
            "enabled" in output.lower()
        ):

            findings.append(

                create_finding(

                    "HIGH",

                    "SMBv1 enabled",

                    "Windows SMB1Protocol is enabled.",

                    (
                        "Disable SMBv1 unless a documented "
                        "legacy requirement exists."
                    )
                )
            )


    display_findings(
        findings,
        "Security / Vulnerability Indicators"
    )

    return findings


# ==========================================================
# PROCESS THREAT SCAN
# ==========================================================

def suspicious_process_location(path):

    if not path:
        return False


    path = path.lower()


    if platform.system() == "Windows":

        suspicious_locations = [

            "\\appdata\\local\\temp\\",

            "\\windows\\temp\\",

            "\\users\\public\\",

            "\\downloads\\"
        ]


    else:

        suspicious_locations = [

            "/tmp/",

            "/var/tmp/",

            "/dev/shm/"
        ]


    return any(
        location in path
        for location in suspicious_locations
    )


def process_scan():

    findings = []


    for process in psutil.process_iter(

        [
            "pid",
            "name",
            "exe",
            "username"
        ]
    ):

        try:

            data = process.info

            name = (
                data["name"]
                or
                "Unknown"
            )

            executable = (
                data["exe"]
                or
                ""
            )


            # -------------------
            # Suspicious location
            # -------------------

            if (
                executable
                and
                suspicious_process_location(
                    executable
                )
            ):

                severity = "MEDIUM"


                if (
                    platform.system()
                    == "Windows"
                    and
                    name.lower()
                    in WINDOWS_SYSTEM_PROCESSES
                ):

                    severity = "HIGH"


                file_hash = calculate_hash(
                    executable
                )


                findings.append(

                    create_finding(

                        severity,

                        (
                            "Process running from "
                            "review-worthy location"
                        ),

                        (
                            f"{name} "
                            f"(PID {data['pid']})\n"
                            f"{executable}\n"
                            f"SHA256: {file_hash}"
                        ),

                        (
                            "Verify the executable's source, "
                            "signature and expected location."
                        )
                    )
                )


            # ---------------------------------------
            # Windows system-process impersonation
            # ---------------------------------------

            if (
                platform.system()
                == "Windows"
                and
                name.lower()
                in WINDOWS_SYSTEM_PROCESSES
                and
                executable
            ):

                windows_directory = os.environ.get(
                    "WINDIR",
                    "C:\\Windows"
                )

                expected = (
                    windows_directory
                    + "\\System32\\"
                ).lower()


                if not executable.lower().startswith(
                    expected
                ):

                    findings.append(

                        create_finding(

                            "HIGH",

                            (
                                "Windows system process "
                                "outside System32"
                            ),

                            (
                                f"{name} "
                                f"(PID {data['pid']})\n"
                                f"{executable}"
                            ),

                            (
                                "Investigate the executable "
                                "and validate its digital signature."
                            )
                        )
                    )


        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied
        ):

            continue


    display_findings(
        findings,
        "Process Threat Indicators"
    )

    return findings


# ==========================================================
# NETWORK THREAT SCAN
# ==========================================================

def network_scan():

    findings = []

    table = Table(
        title="Active Network Connections"
    )

    table.add_column("Process")

    table.add_column("PID")

    table.add_column("Local")

    table.add_column("Remote")

    table.add_column("Status")


    try:

        connections = psutil.net_connections(
            kind="inet"
        )

    except Exception:

        connections = []


    displayed = 0


    for connection in connections:

        if not connection.raddr:
            continue


        try:

            local = (
                f"{connection.laddr.ip}:"
                f"{connection.laddr.port}"
            )

            remote = (
                f"{connection.raddr.ip}:"
                f"{connection.raddr.port}"
            )

            remote_port = (
                connection.raddr.port
            )

        except Exception:

            continue


        process = get_process_name(
            connection.pid
        )


        if displayed < 25:

            table.add_row(

                process,

                str(
                    connection.pid
                    or
                    ""
                ),

                local,

                remote,

                connection.status
            )

            displayed += 1


        # Review-worthy remote ports
        if (

            connection.status
            == psutil.CONN_ESTABLISHED

            and

            remote_port
            in REVIEW_REMOTE_PORTS
        ):

            findings.append(

                create_finding(

                    "MEDIUM",

                    (
                        "Connection using "
                        "review-worthy remote port"
                    ),

                    (
                        f"{process} "
                        f"(PID {connection.pid}) "
                        f"-> {remote}"
                    ),

                    (
                        "Validate the destination and "
                        "process. Port number alone "
                        "does not prove malicious activity."
                    )
                )
            )


    console.print(table)


    display_findings(
        findings,
        "Network Threat Indicators"
    )


    return findings


# ==========================================================
# PERSISTENCE SCAN
# ==========================================================

def windows_persistence_scan():

    findings = []

    entries = []


    try:

        import winreg

    except ImportError:

        return findings, entries


    registry_locations = [

        (
            winreg.HKEY_CURRENT_USER,
            (
                "Software\\Microsoft\\Windows\\"
                "CurrentVersion\\Run"
            )
        ),

        (
            winreg.HKEY_LOCAL_MACHINE,
            (
                "Software\\Microsoft\\Windows\\"
                "CurrentVersion\\Run"
            )
        )
    ]


    for hive, key_path in registry_locations:

        try:

            key = winreg.OpenKey(
                hive,
                key_path
            )

            index = 0


            while True:

                try:

                    name, value, data_type = (
                        winreg.EnumValue(
                            key,
                            index
                        )
                    )

                    entries.append(
                        {
                            "name": name,
                            "command": str(value)
                        }
                    )


                    if suspicious_process_location(
                        str(value)
                    ):

                        findings.append(

                            create_finding(

                                "MEDIUM",

                                (
                                    "Startup entry points "
                                    "to review-worthy location"
                                ),

                                (
                                    f"{name}: {value}"
                                ),

                                (
                                    "Verify that the startup "
                                    "entry is authorized."
                                )
                            )
                        )


                    index += 1


                except OSError:

                    break


        except OSError:

            continue


    return findings, entries


def linux_persistence_scan():

    findings = []

    entries = []


    # -----------------------
    # User crontab
    # -----------------------

    code, output, error = run_command(
        [
            "crontab",
            "-l"
        ]
    )


    if code == 0:

        for line in output.splitlines():

            line = line.strip()

            if (
                not line
                or
                line.startswith("#")
            ):

                continue


            entries.append(
                {
                    "name": "User Cron",
                    "command": line
                }
            )


            lower = line.lower()


            if (

                "/tmp/" in lower

                or

                "/dev/shm/" in lower

            ):

                findings.append(

                    create_finding(

                        "MEDIUM",

                        "Review-worthy cron entry",

                        line,

                        (
                            "Verify that the scheduled "
                            "command is authorized."
                        )
                    )
                )


    # -----------------------
    # Desktop autostart
    # -----------------------

    autostart_directory = (
        Path.home()
        /
        ".config"
        /
        "autostart"
    )


    if autostart_directory.exists():

        for file in (
            autostart_directory.glob(
                "*.desktop"
            )
        ):

            entries.append(
                {
                    "name": "Desktop Autostart",
                    "command": str(file)
                }
            )


    return findings, entries


def persistence_scan():

    if platform.system() == "Windows":

        findings, entries = (
            windows_persistence_scan()
        )


    elif platform.system() == "Linux":

        findings, entries = (
            linux_persistence_scan()
        )


    else:

        findings = []

        entries = []


    table = Table(
        title="Persistence / Startup Entries"
    )

    table.add_column(
        "Type"
    )

    table.add_column(
        "Command / Location"
    )


    for item in entries[:30]:

        table.add_row(
            item["name"],
            item["command"]
        )


    console.print(table)


    display_findings(
        findings,
        "Persistence Threat Indicators"
    )


    return {
        "entries": entries,
        "findings": findings
    }


# ==========================================================
# FULL SCAN
# ==========================================================

def full_scan():

    console.print(
        "[bold cyan]"
        "Running full SentinelScope assessment..."
        "[/bold cyan]\n"
    )


    report = {

        "tool":
            TOOL_NAME,

        "version":
            VERSION,

        "author":
            AUTHOR,

        "date":
            str(
                datetime.datetime.now()
            ),

        "system":
            system_information(),

        "vulnerability_findings":
            vulnerability_scan(),

        "process_findings":
            process_scan(),

        "network_findings":
            network_scan(),

        "persistence":
            persistence_scan()
    }


    reports_directory = Path(
        "reports"
    )

    reports_directory.mkdir(
        exist_ok=True
    )


    timestamp = (
        datetime.datetime.now()
        .strftime(
            "%Y%m%d_%H%M%S"
        )
    )


    report_file = (

        reports_directory

        /

        f"sentinelscope_{timestamp}.json"
    )


    report_file.write_text(

        json.dumps(
            report,
            indent=4
        ),

        encoding="utf-8"
    )


    console.print(
        "\n[bold green]"
        "Security assessment complete."
        "[/bold green]"
    )


    console.print(
        f"\nReport saved to:\n"
        f"[cyan]{report_file}[/cyan]"
    )


# ==========================================================
# ABOUT
# ==========================================================

def about():

    console.print(

        Panel(

            (
                f"[bold cyan]"
                f"{TOOL_NAME} v{VERSION}"
                f"[/bold cyan]\n\n"

                f"Created by: "
                f"[bold green]"
                f"{AUTHOR}"
                f"[/bold green]\n\n"

                f"GitHub:\n"
                f"{GITHUB}\n\n"

                "SentinelScope is a defensive "
                "endpoint-security assessment tool.\n\n"

                "Current capabilities:\n"
                "• System inventory\n"
                "• Security misconfiguration checks\n"
                "• Listening-service detection\n"
                "• Suspicious-process indicators\n"
                "• Network connection analysis\n"
                "• Persistence/startup analysis\n"
                "• SHA-256 hashing\n"
                "• JSON security reporting"
            ),

            title="About SentinelScope",

            border_style="cyan"
        )
    )


# ==========================================================
# MAIN MENU
# ==========================================================

def menu():

    while True:

        banner()


        console.print(
            "[bold cyan]1.[/bold cyan] "
            "System Information"
        )

        console.print(
            "[bold cyan]2.[/bold cyan] "
            "Vulnerability / Misconfiguration Scan"
        )

        console.print(
            "[bold cyan]3.[/bold cyan] "
            "Suspicious Process Scan"
        )

        console.print(
            "[bold cyan]4.[/bold cyan] "
            "Network Threat Scan"
        )

        console.print(
            "[bold cyan]5.[/bold cyan] "
            "Persistence / Startup Scan"
        )

        console.print(
            "[bold cyan]6.[/bold cyan] "
            "Full Security Assessment"
        )

        console.print(
            "[bold cyan]7.[/bold cyan] "
            "About"
        )

        console.print(
            "[bold red]0.[/bold red] "
            "Exit\n"
        )


        choice = console.input(
            "[bold green]"
            "SentinelScope > "
            "[/bold green]"
        )


        banner()


        if choice == "1":

            system_information()


        elif choice == "2":

            vulnerability_scan()


        elif choice == "3":

            process_scan()


        elif choice == "4":

            network_scan()


        elif choice == "5":

            persistence_scan()


        elif choice == "6":

            full_scan()


        elif choice == "7":

            about()


        elif choice == "0":

            console.print(
                "[cyan]"
                "Thank you for using SentinelScope."
                "[/cyan]"
            )

            break


        else:

            console.print(
                "[red]"
                "Invalid selection."
                "[/red]"
            )


        if choice != "0":

            pause()


# ==========================================================
# START
# ==========================================================

if __name__ == "__main__":

    try:

        menu()

    except KeyboardInterrupt:

        console.print(
            "\n[yellow]"
            "SentinelScope terminated."
            "[/yellow]"
        )
