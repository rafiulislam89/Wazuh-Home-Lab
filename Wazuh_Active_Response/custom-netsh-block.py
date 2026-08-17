#!/usr/bin/env python3
# Custom Active Response for Windows: block/unblock an attacker IP with netsh.
# Based on Wazuh's official custom-ar template (implements the key handshake).
# Reads the IP from data.win.eventdata.ipAddress, because Windows 4625
# events do not populate the standard srcip field.

import os
import sys
import json
import subprocess
import datetime

if os.name == 'nt':
    LOG_FILE = "C:\\Program Files (x86)\\ossec-agent\\active-response\\active-responses.log"
else:
    LOG_FILE = "/var/ossec/logs/active-responses.log"

ADD_COMMAND = 0
DELETE_COMMAND = 1
CONTINUE_COMMAND = 2
ABORT_COMMAND = 3

OS_SUCCESS = 0
OS_INVALID = -1


class message:
    def __init__(self):
        self.alert = ""
        self.command = 0


def write_debug_file(ar_name, msg):
    with open(LOG_FILE, mode="a") as log_file:
        log_file.write(
            str(datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')) +
            " " + ar_name + ": " + msg + "\n"
        )


def read_json_message():
    """Read STDIN until a complete JSON object has arrived.

    Not readline(): execd does not always send a trailing newline,
    which makes readline() block forever on the delete message.
    Stops as soon as the buffer parses as valid JSON.
    """
    buf = ""
    while True:
        ch = sys.stdin.read(1)
        if ch == "":          # pipe closed
            break
        buf += ch
        if ch == "}":
            try:
                json.loads(buf)
                break         # complete object
            except ValueError:
                pass          # nested brace, keep reading
    return buf


def extract_ip(params):
    """Get the attacker IP from an active-response message.

    'add' carries the full alert. 'delete' may carry either a keys list
    or the original alert again, depending on execd, so try both.
    """
    keys = params.get("keys")
    if keys:
        return keys[0]

    try:
        return params["alert"]["data"]["win"]["eventdata"]["ipAddress"]
    except (KeyError, TypeError):
        return None


def run_netsh(argv, args):
    netsh_path = os.path.join(
        os.environ.get("SystemRoot", "C:\\Windows"),
        "System32", "netsh.exe"
    )
    try:
        result = subprocess.run(
            [netsh_path] + args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        write_debug_file(argv[0],
            "netsh rc=" + str(result.returncode) +
            " out=" + result.stdout.strip())
        return result.returncode
    except Exception as e:
        write_debug_file(argv[0], "netsh EXCEPTION: " + str(e))
        return OS_INVALID


def setup_and_check_message(argv):
    msg = message()
    input_str = read_json_message()

    # Log the full incoming message. The Wazuh AR decoder parses this
    # line to generate rule 657 on the manager. Without it, the response
    # runs but never appears as an alert.
    write_debug_file(argv[0], input_str.strip())

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
        msg.command = OS_INVALID
        return msg

    msg.alert = data

    command = data.get("command")
    if command == "add":
        msg.command = ADD_COMMAND
    elif command == "delete":
        msg.command = DELETE_COMMAND
    else:
        msg.command = OS_INVALID
        write_debug_file(argv[0], 'Not valid command: ' + str(command))

    return msg


def send_keys_and_check_message(argv, keys):
    keys_msg = json.dumps({
        "version": 1,
        "origin": {"name": argv[0], "module": "active-response"},
        "command": "check_keys",
        "parameters": {"keys": keys}
    })

    write_debug_file(argv[0], keys_msg)
    print(keys_msg)
    sys.stdout.flush()

    input_str = read_json_message()

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
        return OS_INVALID

    action = data.get("command")
    if action == "continue":
        return CONTINUE_COMMAND
    elif action == "abort":
        return ABORT_COMMAND

    write_debug_file(argv[0], "Invalid value of 'command'")
    return OS_INVALID


def main(argv):
    write_debug_file(argv[0], "Started")

    msg = setup_and_check_message(argv)

    if msg.command < 0:
        os._exit(OS_INVALID)

    params = msg.alert.get("parameters", {})
    ip = extract_ip(params)

    if not ip:
        write_debug_file(argv[0],
            "No IP found. parameters: " + str(list(params.keys())))
        os._exit(OS_INVALID)

    rule_name = "WAZUH_BLOCK_" + ip

    if msg.command == ADD_COMMAND:
        action = send_keys_and_check_message(argv, [ip])

        if action != CONTINUE_COMMAND:
            if action == ABORT_COMMAND:
                write_debug_file(argv[0], "Aborted")
                os._exit(OS_SUCCESS)
            write_debug_file(argv[0], "Invalid command")
            os._exit(OS_INVALID)

        run_netsh(argv, [
            "advfirewall", "firewall", "add", "rule",
            "name=" + rule_name, "dir=in", "action=block", "remoteip=" + ip
        ])
        write_debug_file(argv[0], "BLOCKED " + ip)

    elif msg.command == DELETE_COMMAND:
        run_netsh(argv, [
            "advfirewall", "firewall", "delete", "rule",
            "name=" + rule_name
        ])
        write_debug_file(argv[0], "UNBLOCKED " + ip)

    else:
        write_debug_file(argv[0], "Invalid command")

    write_debug_file(argv[0], "Ended")
    os._exit(OS_SUCCESS)


if __name__ == "__main__":
    main(sys.argv)