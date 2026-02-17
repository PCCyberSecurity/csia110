# Define the path to your computer list and output CSV file
$ComputersFile = "computers.txt"
$OutputFile = "ComputerInventory.csv"

# Get computer names from the text file
$Computers = Get-Content -Path $ComputersFile

# Create an empty array to store inventory data
$InventoryReport = @()

foreach ($Computer in $Computers) {
    if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet)) {
        Write-Host "ERROR: $Computer is unreachable" -ForegroundColor Red
        continue
    }

    try {
        # Use Invoke-Command to run scripts on remote computers
        $InventoryData = Invoke-Command -ComputerName $Computer -ScriptBlock {
            # Gather specific information using CIM cmdlets (recommended over WMI)
            $OS = Get-CimInstance -ClassName Win32_OperatingSystem
            $CPU = Get-CimInstance -ClassName Win32_Processor
            $Disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" | Measure-Object -Property Size -Sum
            $Memory = Get-CimInstance -ClassName CIM_PhysicalMemory | Measure-Object -Property Capacity -Sum

            # Create a custom object with the desired properties
            [PSCustomObject]@{
                ComputerName = $env:COMPUTERNAME
                Manufacturer = (Get-CimInstance Win32_ComputerSystem).Manufacturer
                Model        = (Get-CimInstance Win32_ComputerSystem).Model
                SerialNumber = (Get-CimInstance Win32_BIOS).SerialNumber
                OperatingSystem = $OS.Caption
                OSVersion    = $OS.Version
                CPUName      = $CPU.Name
                TotalMemoryGB = [math]::Round($Memory.Sum / 1GB, 2)
                TotalDiskGB  = [math]::Round($Disk.Sum / 1GB, 2)
            }
        }
        $InventoryReport += $InventoryData
        Write-Host "SUCCESS: Data collected from $Computer" -ForegroundColor Green

    } catch {
        Write-Host "ERROR: Could not retrieve info from $Computer. Check permissions/remoting." -ForegroundColor Red
        Write-Error $_.Exception.Message
    }
}

# Export the collected data to a CSV file
$InventoryReport | Export-Csv -Path $OutputFile -NoTypeInformation

Write-Host "Inventory report saved to $OutputFile" -ForegroundColor Cyan
