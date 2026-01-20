# Test script for WinDbg MCP Server
# Sends MCP JSON-RPC messages via stdin and reads responses

$serverPath = "E:\Projects\windbg\target\release\windbg-mcp-server.exe"

# Start the server process
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $serverPath
$psi.Arguments = "--permissive"
$psi.UseShellExecute = $false
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.CreateNoWindow = $true

$process = [System.Diagnostics.Process]::Start($psi)

# Give it a moment to start
Start-Sleep -Milliseconds 500

function Send-McpMessage {
    param([string]$json)

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $header = "Content-Length: $($bytes.Length)`r`n`r`n"

    $process.StandardInput.Write($header)
    $process.StandardInput.Write($json)
    $process.StandardInput.Flush()

    Write-Host ">>> Sent: $json" -ForegroundColor Cyan
}

function Read-McpResponse {
    param([int]$timeoutMs = 10000)

    $response = ""
    $startTime = Get-Date

    # Read Content-Length header
    $headerLine = ""
    while ($true) {
        if (((Get-Date) - $startTime).TotalMilliseconds -gt $timeoutMs) {
            Write-Host "Timeout waiting for response" -ForegroundColor Red
            return $null
        }

        $char = $process.StandardOutput.Read()
        if ($char -eq -1) { continue }

        $headerLine += [char]$char
        if ($headerLine.EndsWith("`r`n`r`n")) { break }
    }

    # Parse content length
    if ($headerLine -match "Content-Length:\s*(\d+)") {
        $contentLength = [int]$matches[1]

        # Read the JSON body
        $buffer = New-Object char[] $contentLength
        $read = 0
        while ($read -lt $contentLength) {
            $chunk = $process.StandardOutput.Read($buffer, $read, $contentLength - $read)
            if ($chunk -gt 0) { $read += $chunk }
        }

        $response = [string]::new($buffer)
        Write-Host "<<< Received: $response" -ForegroundColor Green
        return $response | ConvertFrom-Json
    }

    return $null
}

try {
    Write-Host "=== Testing WinDbg MCP Server ===" -ForegroundColor Yellow
    Write-Host ""

    # 1. Initialize
    Write-Host "1. Sending initialize request..." -ForegroundColor Yellow
    $initRequest = @{
        jsonrpc = "2.0"
        id = 1
        method = "initialize"
        params = @{
            protocolVersion = "2024-11-05"
            capabilities = @{}
            clientInfo = @{
                name = "test-client"
                version = "1.0"
            }
        }
    } | ConvertTo-Json -Depth 10 -Compress

    Send-McpMessage $initRequest
    $initResponse = Read-McpResponse
    Write-Host ""

    # 2. Send initialized notification
    Write-Host "2. Sending initialized notification..." -ForegroundColor Yellow
    $initializedNotification = @{
        jsonrpc = "2.0"
        method = "notifications/initialized"
    } | ConvertTo-Json -Compress

    Send-McpMessage $initializedNotification
    Start-Sleep -Milliseconds 200
    Write-Host ""

    # 3. List tools
    Write-Host "3. Listing available tools..." -ForegroundColor Yellow
    $listToolsRequest = @{
        jsonrpc = "2.0"
        id = 2
        method = "tools/list"
    } | ConvertTo-Json -Compress

    Send-McpMessage $listToolsRequest
    $toolsResponse = Read-McpResponse

    if ($toolsResponse.result.tools) {
        Write-Host "Available tools:" -ForegroundColor Magenta
        foreach ($tool in $toolsResponse.result.tools) {
            Write-Host "  - $($tool.name): $($tool.description)" -ForegroundColor White
        }
    }
    Write-Host ""

    # 4. Attach to NewWorld process (PID 25052)
    Write-Host "4. Attaching to NewWorld process (PID 25052)..." -ForegroundColor Yellow
    $attachRequest = @{
        jsonrpc = "2.0"
        id = 3
        method = "tools/call"
        params = @{
            name = "attach_process"
            arguments = @{
                pid = 25052
                non_invasive = $true
            }
        }
    } | ConvertTo-Json -Depth 10 -Compress

    Send-McpMessage $attachRequest
    $attachResponse = Read-McpResponse
    Write-Host ""

    # Extract session_id from response
    $sessionId = $null
    if ($attachResponse.result.content) {
        $content = $attachResponse.result.content[0].text | ConvertFrom-Json
        if ($content.data.session_id) {
            $sessionId = $content.data.session_id
            Write-Host "Session ID: $sessionId" -ForegroundColor Magenta
        }
    }

    if ($sessionId) {
        # 5. List threads
        Write-Host "5. Listing threads..." -ForegroundColor Yellow
        $threadsRequest = @{
            jsonrpc = "2.0"
            id = 4
            method = "tools/call"
            params = @{
                name = "list_threads"
                arguments = @{
                    session_id = $sessionId
                }
            }
        } | ConvertTo-Json -Depth 10 -Compress

        Send-McpMessage $threadsRequest
        $threadsResponse = Read-McpResponse
        Write-Host ""

        # 6. List modules
        Write-Host "6. Listing modules..." -ForegroundColor Yellow
        $modulesRequest = @{
            jsonrpc = "2.0"
            id = 5
            method = "tools/call"
            params = @{
                name = "list_modules"
                arguments = @{
                    session_id = $sessionId
                }
            }
        } | ConvertTo-Json -Depth 10 -Compress

        Send-McpMessage $modulesRequest
        $modulesResponse = Read-McpResponse
        Write-Host ""

        # 7. Get registers
        Write-Host "7. Getting registers..." -ForegroundColor Yellow
        $regsRequest = @{
            jsonrpc = "2.0"
            id = 6
            method = "tools/call"
            params = @{
                name = "get_registers"
                arguments = @{
                    session_id = $sessionId
                }
            }
        } | ConvertTo-Json -Depth 10 -Compress

        Send-McpMessage $regsRequest
        $regsResponse = Read-McpResponse
        Write-Host ""

        # 8. Execute a command
        Write-Host "8. Executing '|' command (process info)..." -ForegroundColor Yellow
        $execRequest = @{
            jsonrpc = "2.0"
            id = 7
            method = "tools/call"
            params = @{
                name = "execute"
                arguments = @{
                    session_id = $sessionId
                    command = "|"
                }
            }
        } | ConvertTo-Json -Depth 10 -Compress

        Send-McpMessage $execRequest
        $execResponse = Read-McpResponse
        Write-Host ""

        # 9. Detach
        Write-Host "9. Detaching from process..." -ForegroundColor Yellow
        $detachRequest = @{
            jsonrpc = "2.0"
            id = 8
            method = "tools/call"
            params = @{
                name = "detach"
                arguments = @{
                    session_id = $sessionId
                }
            }
        } | ConvertTo-Json -Depth 10 -Compress

        Send-McpMessage $detachRequest
        $detachResponse = Read-McpResponse
    }

    Write-Host ""
    Write-Host "=== Test Complete ===" -ForegroundColor Yellow

} finally {
    # Clean up
    if (!$process.HasExited) {
        $process.Kill()
    }
    $process.Dispose()
}
