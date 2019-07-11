function Invoke-NmapParse 
{
  [cmdletbinding()]
  Param (
    [Parameter( Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
  [string] $scanfile)


  $ErrorActionPreference = 'SilentlyContinue'
  #$ErrorActionPreference = 'Continue'

  #Import-Module -Name .\Get-Cert.ps1

  function Get-Cert
  {
    Param ($ip,$Port)
    $TCPClient = New-Object -TypeName System.Net.Sockets.TCPClient
    try
    {
      $TcpSocket = New-Object -TypeName Net.Sockets.TcpClient -ArgumentList ($ip, $Port)
      $tcpstream = $TcpSocket.GetStream()
      $Callback = {
        param($sender,$cert,$chain,$errors) return $true
      }
      $SSLStream = New-Object -TypeName System.Net.Security.SSLStream -ArgumentList @($tcpstream, $true, $Callback)
      try
      {
        $SSLStream.AuthenticateAsClient($ip)
        $Certificate = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList ($SSLStream.RemoteCertificate)
      }
      finally
      {
        $SSLStream.Dispose()
      }
    }
    finally
    {
      $TCPClient.Dispose()
    }
    return $Certificate
  }

  #get-cert -ip 134.173.53.186 -Port 443

  <#
      sudo nmap -sSVC -A -O -T 4 -p- -Pn -iL targets.txt -oA scan-name
  #>

  #[xml] $scan = Get-Content -Path C:\Users\daveh\Documents\Client-Work\DiscFinServ\slovenia\no-ping-disfinserv-full-tcp.xml
  [xml] $scan = Get-Content -Path $scanfile
  $cmdline = $scan.nmaprun.args

  write-host -BackgroundColor White -ForegroundColor Black "The NMAP scan command Line: " $cmdline "`n"
  $hosts = $scan.SelectNodes('//host')

  $list = @()
  $hosts | ForEach-Object -Process {
    $_.address | ForEach-Object -Process {
      if ( $_.addrtype -eq 'ipv4') 
      {
        $hostip = New-Object -TypeName psobject 
        $hostip | Add-Member -MemberType NoteProperty -Name ip -Value $_.addr
      }
    }
    $_.ports | ForEach-Object -Process {
      $_.port | ForEach-Object -Process {
        $val = New-Object -TypeName psobject 
        $val | Add-Member -MemberType NoteProperty -Name Host -Value $hostip.ip
        $val | Add-Member -MemberType NoteProperty -Name Proto -Value $_.protocol
        $val | Add-Member -MemberType NoteProperty -Name Port -Value $_.portid
        $val | Add-Member -MemberType NoteProperty -Name State -Value $_.state.state
        $val | Add-Member -MemberType NoteProperty -Name Service -Value ($_.service.name + ' '+ $_.service.tunnel)
        $val | Add-Member -MemberType NoteProperty -Name Servicedesc -Value $_.service.product
        if ($val.proto -ne '' ) 
        {
          $list += $val
        }
      }
    }
  }

  #Output everything with an 'open' port
  $list |
  Where-Object -FilterScript {
    $_.state -eq 'open'
  } |
  Format-Table -AutoSize 

  $list |
  ConvertTo-Csv -Delimiter ':' -NoTypeInformation |
  Out-File -FilePath everything.csv

  #How many live hosts
  $numhosts = $list.host|Get-Unique
  Write-Host -ForegroundColor black -BackgroundColor White 'Number of LIVE hosts for this scan' $numhosts.Count "`n"


  #Filter for services, only not by port, this example is for services that have an SSL certificate associated.
  $ssllist = $list |
  Where-Object -FilterScript {
    $_.state -eq 'open'
  } |
  Where-Object -FilterScript {
    ($_.service -like '*ssl*') -or ($_.service -like '*wbt*') -or ($_.service -like '*tls*') -or ($_.service -like '*https*')
  } |
  Select-Object -Property host, port
  Write-Host -ForegroundColor black -BackgroundColor white -Object "SSL Servers/Services `n"
  
  $ssllist | Format-Table -AutoSize
  $ssllist |
  ConvertTo-Csv -Delimiter ':' -NoTypeInformation |
  Out-File -FilePath ssl-hosts-services.csv
  $replace = Get-Content ./ssl-hosts-services.csv
  $replace = $replace -replace '[""]',''
  Set-Content -Path ./ssl-hosts-services.csv -Value $replace


  #RDP server list
  $rdphosts = $list |
  Where-Object -FilterScript {
    ($_.service -like '*wbt*')
  } |
  Select-Object -Property host, port
  if ($rdphosts -ne $null) 
  {
    Write-Host -ForegroundColor black -BackgroundColor white -Object "RDP Servers/Services `n"
  }
  $rdphosts | Format-Table -AutoSize

  $rdphosts |
  ConvertTo-Csv -Delimiter ':' -NoTypeInformation |
  Out-File -FilePath rdp-hosts.csv
  $replace = Get-Content ./rdp-hosts.csv
  $replace = $replace -replace '[""]',''
  Set-Content -Path ./rdp-hosts.csv -Value $replace

  #ssh server list
  $sshhosts = $list |
  Where-Object -FilterScript {
    ($_.service -like '*ssh*')
  } |
  Select-Object -Property host, port
  if ($sshhosts -ne $null) 
  {
    Write-Host -ForegroundColor black -BackgroundColor white -Object "SSH Servers/Services `n"
  }
  $sshhosts | Format-Table -AutoSize

  $sshhosts |
  ConvertTo-Csv -Delimiter ':' -NoTypeInformation |
  Out-File -FilePath ssh-hosts.csv
  $replace = Get-Content ./ssh-hosts.csv
  $replace = $replace -replace '[""]',''
  Set-Content -Path ./ssh-hosts.csv -Value $replace

  #ftp server list
  $ftphosts = $list |
  Where-Object -FilterScript {
    ($_.service -like '*ftp*')
  } |
  Select-Object -Property host, port
  if ($ftphosts -ne $null) 
  {
    Write-Host -ForegroundColor white -BackgroundColor red -Object "FTP Servers/Services `n"
  }
  $ftphosts | Format-Table -AutoSize

  $ftphosts |
  ConvertTo-Csv -Delimiter ':' -NoTypeInformation |
  Out-File -FilePath ftp-hosts.csv
  $replace = Get-Content ./ftp-hosts.csv
  $replace = $replace -replace '[""]',''
  Set-Content -Path ./ftp-hosts.csv -Value $replace

  #telnet server list
  $telnethosts = $list |
  Where-Object -FilterScript {
    ($_.service -like '*telnet*')
  } |
  Select-Object -Property host, port
  if ($telnethosts -ne $null) 
  {
    Write-Host -ForegroundColor white -BackgroundColor red -Object "TELNET Servers/Services `n"
  }
  $telnethosts | Format-Table -AutoSize

  $telnethosts |
  ConvertTo-Csv -Delimiter ':' -NoTypeInformation |
  Out-File -FilePath telnet-hosts.csv
  $replace = Get-Content ./telnet-hosts.csv
  $replace = $replace -replace '[""]',''
  Set-Content -Path ./telnet-hosts.csv -Value $replace
  
  #evalutate SSL certificates
  $certlist = @()
  $ssllist | ForEach-Object -Process {
    $cert = Get-Cert -ip $_.host -Port $_.port
    $val = New-Object -TypeName psobject 
    $val | Add-Member -MemberType NoteProperty -Name Host -Value $_.host
    $val | Add-Member -MemberType NoteProperty -Name Port -Value $_.port
    $val | Add-Member -MemberType NoteProperty -Name NotBefore -Value $cert.notbefore
    $val | Add-Member -MemberType NoteProperty -Name NotAfter -Value $cert.notafter
    $val | Add-Member -MemberType NoteProperty -Name IsValid -Value $cert.verify()
    $val | Add-Member -MemberType NoteProperty -Name Issuer -Value $cert.issuer
    $val | Add-Member -MemberType NoteProperty -Name SigType -Value $cert.SignatureAlgorithm.FriendlyName
    $certlist += $val
  }
  Write-Host -ForegroundColor black -BackgroundColor white -Object "SSL Certificates `n"
  $certlist | Format-Table -AutoSize
  $certlist |
  ConvertTo-Csv -Delimiter ':' -NoTypeInformation |
  Out-File -FilePath ssl-certs.csv

  #get web services

  $weblist = $list |
  Where-Object -FilterScript {
    ($_.state -eq 'open') -and ($_.service -like '*http*')
  } |
  Select-Object -Property host, port
  Write-Host -ForegroundColor black -BackgroundColor white -Object "Web Servers/Services `n"
  #pass the web services to nikto for example
  $weblist | ForEach-Object -Process {
    $s = 'perl ./nikto/program/nikto.pl -host '+ $_.host +' -port ' +([string] $_.port) + ' -Tuning x6 -maxtime 2m -Format htm -output '+$_.host+'_'+([string] $_.port)+'.nikto.out.html'
    Invoke-Expression -Command $s 
  }
}
