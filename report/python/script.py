import os
import requests
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from datetime import datetime
from rich import print
from rich.panel import Panel
from rich.console import Console, Group
from rich.table import Table
from collections import defaultdict
from zoneinfo import ZoneInfo

API_URL = os.environ['API_URL'] + "/api/sessions"
API_KEY = os.environ['API_KEY']
OUTPUT_FILE = os.environ['OUTPUT_FILE']
LIMIT = 10

console = Console(record=True, width=175)

def current_time_est():
    est = ZoneInfo("EST")
    return datetime.now(est).strftime("%Y-%m-%d %H:%M:%S %Z")


@dataclass
class Auth:
    ID: int
    SessionID: str
    Success: bool
    Username: str
    Password: str
    Timestamp: str


@dataclass
class InputCommand:
    ID: int
    SessionID: str
    Timestamp: str
    Realm: Optional[str]
    Success: bool
    Input: str


@dataclass
class Download:
    ID: int
    SessionID: str
    Timestamp: str
    Url: str
    Outfile: str
    Shasum: Optional[str]

@dataclass
class TtyLog:
    ID: str
    SessionID: str
    Log: str
    Size: int


@dataclass
class Session:
    ID: str
    StartTime: str
    EndTime: str
    Ip: str
    TermSize: Optional[str]
    Auths: List[Auth] = field(default_factory=list)
    Downloads: List[Download] = field(default_factory=list)
    Inputs: List[InputCommand] = field(default_factory=list)
    TtyLogs: List[TtyLog] = field(default_factory=list)

def parse_datetime(date_str):
    timezone_map = {
        "EST": "-05:00",
        "EDT": "-04:00",
    }

    for abbrev, offset in timezone_map.items():
        if abbrev in date_str:
            date_str = date_str.replace(abbrev, offset)
            break

    return datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S %z")

def fetch_sessions() -> List[Session]:
    sessions = []
    offset = 0
    session_ids = set()

    while True:
        params = {
            "limit": LIMIT,
            "offset": offset,
            "include_failed_logins": "true"
        }
        headers = {
            "accept": "application/json",
            "Authorization": API_KEY
        }
        print(f"Fetching sessions from offset {offset}...")
        response = requests.get(API_URL, headers=headers, params=params)
        if response.status_code != 200:
            raise ValueError(f"Failed to fetch sessions: {response.text}")
        data = response.json()

        for sess_data in data.get("sessions", []):
            session = Session(
                ID=sess_data["ID"],
                StartTime=sess_data["StartTime"],
                EndTime=sess_data["EndTime"],
                Ip=sess_data["Ip"],
                TermSize=sess_data.get("TermSize"),
                Auths=[Auth(**auth) for auth in sess_data.get("Auths", [])],
                Downloads=[Download(**download) for download in sess_data.get("Downloads", [])],
                Inputs=[InputCommand(**input_cmd) for input_cmd in sess_data.get("Inputs", [])],
                TtyLogs=[TtyLog(**tty_log) for tty_log in sess_data.get("Ttylogs", [])]
            )
            session.Inputs = [input_cmd for input_cmd in session.Inputs if input_cmd.Success]
            if session.ID in session_ids:
                raise ValueError(f"Duplicate session ID: {session.ID}")
            session_ids.add(session.ID)
            sessions.append(session)

        if data.get('total_size', 0) == 0:
            break
        offset += LIMIT

    return sessions

def process_sessions(sessions: List[Session]):
    if not sessions:
        console.print("No sessions found.", style="bold red")
        return

    # General statistics
    total_sessions = len(sessions)
    total_ips = len(set(s.Ip for s in sessions))
    start_times = [parse_datetime(s.StartTime) for s in sessions]
    first_session = min(start_times).strftime("%Y-%m-%d %H:%M:%S %Z")
    last_session = max(start_times).strftime("%Y-%m-%d %H:%M:%S %Z")
    total_downloads = sum(len(s.Downloads) for s in sessions)

    # IP statistics
    ip_sessions = defaultdict(list)
    for session in sessions:
        ip_sessions[session.Ip].append(session)

    # List of each IP and number of sessions
    ip_list = [(ip, len(sessions)) for ip, sessions in ip_sessions.items()]
    ip_list_str = "\n".join([f" - {ip}: {count} sessions" for ip, count in ip_list])

    # Create panel for current time
    current_time = current_time_est()
    current_time_panel = Panel(
        f"[bold]Since :[/bold] {current_time}",
        title="Honeypot Report",
        border_style="red"
    )

    console.print(current_time_panel)

    # Create panel for general statistics
    general_stats = f"""[bold]Total Sessions:[/bold] {total_sessions}
[bold]Total Distinct IPs:[/bold] {total_ips}
[bold]First Session Time:[/bold] {first_session}
[bold]Last Session Time:[/bold] {last_session}
[bold]Total Downloads:[/bold] {total_downloads}

[bold]IP Addresses and Session Counts:[/bold]
{ip_list_str}
"""
    general_panel = Panel(general_stats, title="", border_style="green")

    # Create table for all downloads
    if total_downloads > 0:
        download_table = Table(title="All Downloads", show_header=True, header_style="bold cyan")
        download_table.add_column("Session ID")
        download_table.add_column("URL")
        download_table.add_column("Outfile")

        for session in sessions:
            for download in session.Downloads:
                download_table.add_row(
                    session.ID, download.Url, download.Outfile,
                )

        general_panel = Panel(Group(general_panel, download_table), title="General Statistics", border_style="green")
        console.print(general_panel)
    else:
        console.print(general_panel)

    # For each IP
    for ip, sessions in ip_sessions.items():
        num_sessions = len(sessions)
        num_failed_logins = sum(len([auth for auth in session.Auths if not auth.Success]) for session in sessions)
        num_successful_logins = sum(len([auth for auth in session.Auths if auth.Success]) for session in sessions)
        num_commands_run = sum(len(session.Inputs) for session in sessions)
        num_downloads = sum(len(session.Downloads) for session in sessions)
        num_ttys = sum(len(session.TtyLogs) for session in sessions)



        # Build IP panel header
        ip_panel_header = f"""[bold]IP Address:[/bold] {ip}
[bold]Number of Sessions:[/bold] {num_sessions}
[bold]Number of Failed Logins:[/bold] {num_failed_logins}
[bold]Number of Successful Logins:[/bold] {num_successful_logins}
[bold]Number of Commands Run:[/bold] {num_commands_run}
[bold]Number of Downloads:[/bold] {num_downloads}
[bold]Number of TTY Logs:[/bold] {num_ttys}
"""

        if len(sessions) > 0:
            earliest_session = min(parse_datetime(s.StartTime) for s in sessions).strftime("%Y-%m-%d %H:%M:%S %Z")
            latest_session = max(parse_datetime(s.StartTime) for s in sessions).strftime("%Y-%m-%d %H:%M:%S %Z")
            ip_panel_header += f"""[bold]Earliest Session:[/bold] {earliest_session}
[bold]Latest Session:[/bold] {latest_session}
"""

        # Build credentials table
        credentials_counter = {}
        for session in sessions:
            for auth in session.Auths:
                key = f"{auth.Username}:{auth.Password}"
                if key not in credentials_counter:
                    credentials_counter[key] = {'count': 0, 'success': auth.Success}
                credentials_counter[key]['count'] += 1
                # Handle mixed success statuses
                if credentials_counter[key]['success'] != auth.Success:
                    credentials_counter[key]['success'] = None  # Indeterminate

        # Separate credentials into failed and successful lists
        failed_credentials = []
        successful_credentials = []

        for creds, info in credentials_counter.items():
            if info['success'] is None or not info['success']:
                failed_credentials.append(f"[red]{creds}[/red]")
            elif info['success']:
                successful_credentials.append(f"[green]{creds}[/green]")

        # Prepare failed credentials output with ellipsis if necessary
        if len(failed_credentials) > 5:
            failed_display = ", ".join(failed_credentials[:5])
            failed_display += f", ...({len(failed_credentials) - 5} more)"
        else:
            failed_display = ", ".join(failed_credentials)

        # Prepare successful credentials output
        successful_display = ", ".join(successful_credentials)

        # Create the combined panel
        auth_attempts_panel = Panel(
            f"Failed Credentials: {failed_display if failed_display else '[red]None[/red]'}\n"
            f"Successful Credentials: {successful_display if successful_display else '[green]None[/green]'}",
            title="Auth Attempts",
            border_style="cyan",
        )

        # Create table for all commands for the IP
        commands_table = Table(title="Commands", show_header=True, header_style="bold cyan")
        commands_table.add_column("Session ID")
        commands_table.add_column("Timestamp", style="dim")
        commands_table.add_column("Command")
        for session in sessions:
            for cmd in session.Inputs:
                commands_table.add_row(session.ID, cmd.Timestamp, cmd.Input)

        # Create a table for all TTY logs
        tty_table = Table(title="TTY Logs", show_header=True, header_style="bold cyan")
        tty_table.add_column("Session ID")
        tty_table.add_column("Log")
        for session in sessions:
            for tty_log in session.TtyLogs:
                tty_table.add_row(session.ID, tty_log.Log)

        # Combine IP panel components
        ip_panel_contents = [ip_panel_header, auth_attempts_panel]
        if num_commands_run > 0:
            ip_panel_contents.append(commands_table)
        if num_ttys > 0:
            ip_panel_contents.append(tty_table)
        ip_panel = Panel(Group(*ip_panel_contents), border_style="yellow", title=f"IP Address: {ip}")
        console.print(ip_panel)

def main():
    sessions = fetch_sessions()
    process_sessions(sessions)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as html_file:
        html_file.write(console.export_html())


if __name__ == "__main__":
    main()

