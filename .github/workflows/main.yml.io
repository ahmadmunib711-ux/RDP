name: RDP

on:
  workflow_dispatch:

jobs:
  secure-rdp:
    runs-on: windows-latest
    timeout-minutes: 3600

    steps:
      - name: Configure Core RDP Settings
        run: |
          # Enable Remote Desktop and disable Network Level Authentication (if needed)
          Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" `
            -Name "fDenyTSConnections" -Value 0 -Force
          Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
            -Name "UserAuthentication" -Value 0 -Force
          Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
            -Name "SecurityLayer" -Value 0 -Force

      - name: Setup Tailscale
        run: |
          $tsIP = ""
          $retries = 0
          while (-not $tsIP -and $retries -lt 10) {
            $tsIP = & "${env:ProgramFiles}\Tailscale\tailscale.exe" ip -4
            Start-Sleep -Seconds 5
            $retries++
          }

          if (-not $tsIP) {
            Write-Error "Tailscale IP not assigned. Exiting."
            exit 1
          }

          echo "TAILSCALE_IP=$tsIP" >> $env:GITHUB_ENV

      - name: Configure Windows Firewall for RDP
        run: |
          # Remove any existing rule with the same name to avoid duplication
          netsh advfirewall firewall delete rule name="RDP-Tailscale"

          # For testing, allow any incoming connection on port 3389
          netsh advfirewall firewall add rule name="RDP-Tailscale" `
            dir=in action=allow protocol=TCP localport=3389

          # (Optional) Restart the Remote Desktop service to ensure changes take effect
          Restart-Service -Name TermService -Force

      - name: Create RDP User with Secure Password
        run: |
          Add-Type -AssemblyName System.Security
          $charSet = @(
            ([char[]](65..90))   # A-Z
            ([char[]](97..122))  # a-z
            ([char[]](48..57))   # 0-9
            ([char[]](33..47) + [char[]](58..64) + [char[]](91..96) + [char[]](123..126))  # Special characters
          )
          $Upper = ([char[]](65..90))
          $Lower = ([char[]](97..122))
          $Number = ([char[]](48..57))
          $Special = ([char[]](33..47) + [char[]](58..64) + [char[]](91..96) + [char[]](123..126))

          # Generate a strong random password (you can adjust length)
          $password = (Get-Random -Count 16 -InputObject ($charSet | ForEach-Object { $_ })) -join ''
          # Ensure at least one of each type (optional enhancement)
          $password = (Get-Random -Count 1 -Input $Upper) + (Get-Random -Count 1 -Input $Lower) + (Get-Random -Count 1 -Input $Number) + (Get-Random -Count 1 -Input $Special) + (Get-Random -Count 12 -InputObject $charSet)

          net user RDP $password /add
          net localgroup Administrators RDP /add

          echo "RDP_CREDS=RDP:$password" >> $env:GITHUB_ENV

      - name: Verify RDP Accessibility
        run: |
          Write-Host "Tailscale IP: $env:TAILSCALE_IP"

          # Test connectivity using Test-NetConnection against the Tailscale IP on port 3389
          $testResult = Test-NetConnection -ComputerName $env:TAILSCALE_IP -Port 3389
          if (-not $testResult.TcpTestSucceeded) {
            Write-Error "TCP connection to RDP port 3389 failed"
            exit 1
          }

          Write-Host "TCP connectivity successful!"

      - name: Maintain Connection
        run: |
          Write-Host "*** RDP ACCESS ***"
          Write-Host "Address: $env:TAILSCALE_IP"
          Write-Host "Username: RDP"
          Write-Host "Password: $($env:RDP_CREDS.Split(':')[1])"  # Securely print only password part

          # Keep runner active indefinitely (or until manually cancelled)
          while ($true) {
            Start-Sleep -Seconds 60
          }

