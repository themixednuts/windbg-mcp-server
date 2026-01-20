# Simple test - send one message and capture all output
$serverPath = "E:\Projects\windbg\target\release\windbg-mcp-server.exe"

# The MCP initialize request
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

$bytes = [System.Text.Encoding]::UTF8.GetBytes($initRequest)
$message = "Content-Length: $($bytes.Length)`r`n`r`n$initRequest"

Write-Host "Sending message:" -ForegroundColor Yellow
Write-Host $message -ForegroundColor Cyan
Write-Host ""

# Use echo to send message and capture output
$result = $message | & $serverPath --permissive 2>&1

Write-Host "Output:" -ForegroundColor Yellow
$result | ForEach-Object { Write-Host $_ }
