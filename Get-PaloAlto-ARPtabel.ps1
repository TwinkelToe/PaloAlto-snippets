# Query the Palo Alto ARP-tabel and print to screen. 
# Made because the Palo Alto was not properly updating its ARP-tabel (PAN-71829)
######################
#                    #
#     User Setup     #
#                    #
######################

# Comma seperated list of IP's and API keys.
$IPvanFirewall = "x.x.x.x, x.x.x.x"
$APIkeyFirwall = "key", "key"


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
        $dump
        $dump = $_.GetConfig()
        $dump
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

#Query ARP-tabel
DO {
    start-sleep -Seconds 5
    $FirewallObjecten | ForEach-Object {
        if ( $_.TestConnection() ) {
            "Connected."
            $_.GetBaseLine()
            $a = Get-Date;
            $a = $a.ToShortDateString() + ' ' + $a.ToShortTimeString();
            $_.ARP | ForEach-Object {
                if ( $_.status.trim() -ne 'i' ) { #s = static, i = incomplete, c = complete, e = expiring | advies is c
                    $NotConnected = $a + ' | Interface: ' + $_.interface + " | Status: " + $_.status;
                    Write-Output $NotConnected
                }
            }    
        } else {
            "Not connected to IP: " + $_.HostIP
        }
    }
} while ( $true )