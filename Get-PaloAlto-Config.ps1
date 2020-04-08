# Get Palo Alto or Panorama config and write to file. 
######################
#                    #
#     User Setup     #
#                    #
######################

# Comma seperated list of IP's and API keys.
$IPvanFirewall = "x.x.x.x, x.x.x.x"
$APIkeyFirwall = "key", "key"

# Location to write config files.
$ConfigFilePath = "c:\temp\"

#$DebugPreference


# 
# Palo Alto Firewall Class
# First attempt as a class in powershell. - Dear Lord have mercy.
# 
# Every query to the device is written as a property of the object. API calls that don't have a method can use the PowerAlto method
#
class PaloAltoFirewall {
    [string]$HostIP
    [string]$APIkey #Hidden maken?
    [string]$PANVersion
    [string]$Model
    [string]$Serial

    PaloAltoFirewall([string]$HostIP, [string]$APIkey) {
        $this.HostIP = $HostIP
        $this.APIkey = $APIkey
    }

    [object]PowerAlto ($CMD) {
        $ReqeustURI = "https://" + $this.HostIP + $CMD + '&key=' + $this.APIkey
        $Result = Invoke-RestMethod -Method Get -Uri $ReqeustURI

        switch ( $Result.response.status ) {
            'success' { return $Result      }
            'error'   { return $false; exit } # Dit kan vast netter.
            default   { return $false; exit }
        }
        return $false
    }

    [boolean]TestConnection () {
        $Result = $this.PowerAlto("/api/?type=version")
        if ( $Result ) {
            $this.Model = $Result.response.result.model
            $this.Serial = $Result.response.result.serial
            $this.PANVersion = $Result.response.result.'sw-version'
            return $true
         } else {
            return $false
         }
    }

    [object]GetARP () {
        $Result = $this.PowerAlto("/api/?type=op&cmd=<show><arp><entry name = 'all'/></arp></show>")
        if ( $Result ) {
            if( Get-Member -inputobject $this -name "ARP" -Membertype NoteProperty ){
                $this.ARP = $Result.response.result.entries.entry
            } else {
                $this | Add-Member -NotePropertyName ARP -NotePropertyValue $Result.response.result.entries.entry
            }
            return $Result.response.result.entries.entry
        } else {
            return $false
        }
    }

    [object]GetGlobalCountFilter () {
        $Result = $this.PowerAlto( "/api/?type=op&cmd=<show><counter><global><filter><delta>yes</delta><packet-filter>yes</packet-filter></filter></global></counter></show>" )
        if ( $Result ) {
            if( Get-Member -inputobject $this -name "GlobalCounterFilter" -Membertype NoteProperty ){
                $this.GlobalCounterFilter = $Result.response.result.global.counters.entry
            } else {
                $this | Add-Member -NotePropertyName GlobalCounterFilter -NotePropertyValue $Result.response.result.global.counters.entry
            }                
            return $Result.response.result.global.counters.entry
        } else {
            return $false
        }
    }

    [object]GetSessionInfo () {
        $Result = $this.PowerAlto( "/api/?type=op&cmd=<show><session><info></info></session></show>" )
        if ( $Result ) {
            if( Get-Member -inputobject $this -name "SessionInfo" -Membertype NoteProperty ){
                $this.SessionInfo = $Result.response.result
            } else {
                $this | Add-Member -NotePropertyName SessionInfo -NotePropertyValue $Result.response.result
            }                
            return $Result.response.result
        } else {
            return $false
        }
    }
    
    [object]GetConfig () {
        $Result = $this.PowerAlto( "/api/?type=op&cmd=<show><config><running></running></config></show>" )
        if ( $Result ) {
            if( Get-Member -inputobject $this -name "SessionInfo" -Membertype NoteProperty ){
                $this.SessionInfo = $Result.response.result
            } else {
                $this | Add-Member -NotePropertyName SessionInfo -NotePropertyValue $Result.response.result
            }                
            return $Result.response.result
        } else {
            return $false
        }
    }

    [boolean]GetBaseLine () {
        $this.GetSessionInfo()
        $this.TestConnection()
        $this.GetARP()
        $this.GetGlobalCountFilter()
        return $true
    }
    
}

######################
#                    #
# Functie declaratie #
#                    #
######################

## Invoke-Rest kent geen -IgnoreInvalidSSL flag, disable SSL-check.
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Ssl3, [Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12

######################
#                    #
#        Setup       #
#                    #
######################

$FirewallObjecten = @()
$i = 0
if ( $IPvanFirewall.Count -eq $APIkeyFirwall.Count ) {
    $IPvanFirewall | ForEach-Object {        
        $FirewallObjecten += New-Object PaloAltoFireWall($IPvanFirewall[$i], $APIkeyFirwall[$i])
        $i++
    }
} else {
    write-host "Amount of firewall IP's and API's are not equal." -BackgroundColor Red
    exit
}

######################
#                    #
#        Main        #
#                    #
######################

$FirewallObjecten | ForEach-Object {
    $dump = ""
    if ( $_.TestConnection() ) {
        "Connected."
        $dump = $_.GetConfig()

        if (-not [string]::IsNullOrEmpty($dump)) {
            $file = "$($ConfigFilePath)$($dump.config.devices.entry.deviceconfig.system.hostname) $((Get-Date).ToString("yyyyMMdd")).txt"            
            $dump.config.OuterXml | Out-File $file
            Write-Host "$($dump.config.devices.entry.deviceconfig.system.hostname): config weggeschreven."
        } else {
            Write-Host "No config received." -BackgroundColor Red
        }
    } else {
        write-host "No connection to IP: $($_.HostIP)." -BackgroundColor Yellow
    }
}
