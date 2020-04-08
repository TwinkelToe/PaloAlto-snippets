######################
#                    #
#     User Setup     #
#                    #
######################


# Comma seperated list of IP's and API keys.
$IPvanFirewall = "x.x.x.x, x.x.x.x"
$APIkeyFirwall = "key", "key"

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
        $Result = $this.PowerAlto( "/api/?type=op&cmd=<show><counter><global><filter><severity>drop</severity></filter></global></counter></show>" )
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
    
    [object]GetThreatLog () {
        
        $Result = $this.PowerAlto( "/api/?type=log&log-type=threat&query=(severity geq medium) and ( subtype neq flood ) and ( subtype neq scan ) and ( receive_time geq '" + $(Get-Date(Get-Date).Adddays(-7)).ToString("yyyy/MM/dd HH:mm:ss") + "' )" )
        $job = $result.response.result.job

        if ( $job ) {
            Start-Sleep -Seconds 5
            $Result = $this.PowerAlto( "/api/?type=log&action=get&job-id=" + $job )
            if (  $result.response.status -eq 'success' ) {
                Write-Host "Succes"
            }
        }
        if ( $Result ) {
            if( Get-Member -inputobject $this -name "Threatlog" -Membertype NoteProperty ){
                $this.SessionInfo = $Result.response.result
            } else {
                $this | Add-Member -NotePropertyName Threatlog -NotePropertyValue $Result.response.result
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

## Invoke-Rest kent geen -IgnoreInvalidSSL flag, disable SSL-check voor dit script.
function DisableSSLCheck {
Add-Type @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            ServicePointManager.ServerCertificateValidationCallback += 
                delegate
                (
                    Object obj, 
                    X509Certificate certificate, 
                    X509Chain chain, 
                    SslPolicyErrors errors
                )
                {
                    return true;
                };
        }
    }
"@
 
    [ServerCertificateValidationCallback]::Ignore();
    
}

######################
#                    #
#        Setup       #
#                    #
######################
DisableSSLCheck;

$FirewallObjecten = @()
$i = 0
if ( $IPvanFirewall.Count -eq $APIkeyFirwall.Count ) {
    $IPvanFirewall | ForEach-Object {        
        $FirewallObjecten += New-Object PaloAltoFireWall($IPvanFirewall[$i], $APIkeyFirwall[$i])
        $i++
    }
    $FirewallObjecten | ForEach-Object {
        $dump = $_.TestConnection()
    }
} else {
    "Leer tellen"
    exit
}

######################
#                    #
#        Main        #
#                    #
######################

$FirewallObjecten | ForEach-Object {

    $_.GetThreatLog()
}

$EntrySum = $FirewallObjecten[1].Threatlog.log.logs.entry + $FirewallObjecten[0].Threatlog.log.logs.entry

$EntrySum | Select-Object -Property threatid -Unique
#$EntrySum | Group-Object dst | Sort-Object -Property count -Descending
#$EntrySum | Group-Object threatid | Sort-Object -Property count -Descending
