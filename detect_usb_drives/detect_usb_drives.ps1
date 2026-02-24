# Define the log name and event ID for USB device insertion
$logName = "Microsoft-Windows-DriverFrameworks-UserMode/Operational"
$eventId = 2003

# Check if the log is enabled and has records
if (Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue) {
    Write-Host "Querying event log: $logName for Event ID: $eventId..."
    
    try {
        # Query the event log for the specified Event ID
        $usbEvents = Get-WinEvent -FilterHashTable @{LogName=$logName; ID=$eventId} | Select-Object TimeCreated, Message, Id, LevelDisplayName
        
        if ($usbEvents) {
            Write-Host "Found $($usbEvents.Count) USB device insertion events:"
            $usbEvents | Format-Table TimeCreated, Id, LevelDisplayName, @{Name="Device ID"; Expression={$_.Message -Match 'Device\s+ID:\s+(.*?)\s+' | Out-Null; $Matches[1]}}
        } else {
            Write-Host "No USB device insertion events (Event ID 2003) found in the log."
        }
    } catch {
        Write-Error "An error occurred while retrieving events: $_. Ensure you are running PowerShell as an Administrator."
    }
} else {
    Write-Warning "The log '$logName' is not enabled or does not exist. Please enable it first."
}
