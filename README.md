# CalderaAgent

A lightweight Go implant for [MITRE Caldera](https://github.com/mitre/caldera) purple‑team adversary emulation.  The agent beacons to a Caldera server, pulls task instructions, executes them in an isolated process group (so EDR kill‑tree actions don’t terminate the agent), and returns rich telemetry so blue teams can measure prevention vs detection.

---

## Features

| Capability                | Notes                                                                                     |   |
| ------------------------- | ----------------------------------------------------------------------------------------- | - |
| **Detached execution**    | Uses `setsid` (Linux) so child process termination doesn’t propagate to the agent.        |   |
| **Timeout watchdog**      | Each instruction honours the `timeout` field and returns exit‑code `124` if exceeded.     |   |
| **Blocked‑by‑EDR flag**   | If the child receives `SIGKILL`, the agent reports `status = 1` for accurate SOC scoring. |   |
| **Verbose debugging**     | Run with `CG_DEBUG=1` to print beacon traffic and execution traces.                       |   |

---

## Quick start

```bash
# clone your fork
git clone https://github.com/Bhanunamikaze/CalderaAgent.git
cd CalderaAgent

# build for the local platform
CGO_ENABLED=0 go build -o agent CalderaAgent.go

# run (replace URL with your Caldera server)
./agent https://caldera‑server:8888
```

### Cross‑compile examples

```bash
# Linux x64 (default)
go build -o agent-linux CalderaAgent.go

# Windows x64
GOOS=windows GOARCH=amd64 go build -o agent.exe CalderaAgent.go
```

---

## Usage

```
Usage: ./agent <C2 URL>
```

Once launched, the agent will beacon every `sleep` seconds, execute abilities, and post results back to `/beacon`.

---

## Telemetry schema

| Field       | Description                                                 |
| ----------- | ----------------------------------------------------------- |
| `exit_code` | Native process exit code (or 124 on timeout).               |
| `status`    | 0 = executed / runtime error, 1 = blocked by EDR (SIGKILL). |
| `pid`       | Child PID for reference in EDR logs.                        |

---

## TODO 
- Windows Code Execution

## License

This project is released under the MIT License.  See `LICENSE` for full text.
