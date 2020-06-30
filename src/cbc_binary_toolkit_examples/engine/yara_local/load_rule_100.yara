rule CompanyMatch
{
    meta:
      sev = 2
    strings:
       $microsoft = "microsoft" nocase
       $google = "google" nocase

    condition:
       $microsoft or $google
}

rule is__Mirai_gen7 {
    meta:
      sev = 9
    strings:
            $st01 = "/bin/busybox rm" fullword nocase wide ascii
            $st02 = "/bin/busybox echo" fullword nocase wide ascii
            $st03 = "/bin/busybox wget" fullword nocase wide ascii
            $st04 = "/bin/busybox tftp" fullword nocase wide ascii
            $st05 = "/bin/busybox cp" fullword nocase wide ascii
            $st06 = "/bin/busybox chmod" fullword nocase wide ascii
            $st07 = "/bin/busybox cat" fullword nocase wide ascii

    condition:
            5 of them
}

rule LIGHTDART_APT1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        sev = 5
    strings:
        $s1 = "ret.log" wide ascii
        $s2 = "Microsoft Internet Explorer 6.0" wide ascii
        $s3 = "szURL Fail" wide ascii
        $s4 = "szURL Successfully" wide ascii
        $s5 = "%s&sdate=%04ld-%02ld-%02ld" wide ascii

    condition:
        all of them
}

rule AURIGA_APT1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        sev = 3
    strings:
        $s1 = "superhard corp." wide ascii
        $s2 = "microsoft corp." wide ascii
        $s3 = "[Insert]" wide ascii
        $s4 = "[Delete]" wide ascii
        $s5 = "[End]" wide ascii
        $s6 = "!(*@)(!@KEY" wide ascii
        $s7 = "!(*@)(!@SID=" wide ascii

    condition:
        all of them
}

rule AURIGA_driver_APT1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        sev = 10
    strings:
        $s1 = "Services\\riodrv32" wide ascii
        $s2 = "riodrv32.sys" wide ascii
        $s3 = "svchost.exe" wide ascii
        $s4 = "wuauserv.dll" wide ascii
        $s5 = "arp.exe" wide ascii
        $pdb = "projects\\auriga" wide ascii

    condition:
        all of ($s*) or $pdb
}

rule BANGAT_APT1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        sev = 8
    strings:
        $s1 = "superhard corp." wide ascii
        $s2 = "microsoft corp." wide ascii
        $s3 = "[Insert]" wide ascii
        $s4 = "[Delete]" wide ascii
        $s5 = "[End]" wide ascii
        $s6 = "!(*@)(!@KEY" wide ascii
        $s7 = "!(*@)(!@SID=" wide ascii
        $s8 = "end      binary output" wide ascii
        $s9 = "XriteProcessMemory" wide ascii
        $s10 = "IE:Password-Protected sites" wide ascii
        $s11 = "pstorec.dll" wide ascii

    condition:
        all of them
}

rule BISCUIT_GREENCAT_APT1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        sev = 7
    strings:
        $s1 = "zxdosml" wide ascii
        $s2 = "get user name error!" wide ascii
        $s3 = "get computer name error!" wide ascii
        $s4 = "----client system info----" wide ascii
        $s5 = "stfile" wide ascii
        $s6 = "cmd success!" wide ascii

    condition:
        all of them
}

rule BOUNCER_APT1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        sev = 4
    strings:
        $s1 = "*Qd9kdgba33*%Wkda0Qd3kvn$*&><(*&%$E#%$#1234asdgKNAg@!gy565dtfbasdg" wide ascii
        $s2 = "IDR_DATA%d" wide ascii
        $s3 = "asdfqwe123cxz" wide ascii
        $s4 = "Mode must be 0(encrypt) or 1(decrypt)." wide ascii

    condition:
        ($s1 and $s2) or ($s3 and $s4)
}

rule BOUNCER_DLL_APT1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        sev = 6
    strings:
        $s1 = "new_connection_to_bounce():" wide ascii
        $s2 = "usage:%s IP port [proxip] [port] [key]" wide ascii

    condition:
        all of them
}

rule CALENDAR_APT1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        sev = 8
    strings:
        $s1 = "content" wide ascii
        $s2 = "title" wide ascii
        $s3 = "entry" wide ascii
        $s4 = "feed" wide ascii
        $s5 = "DownRun success" wide ascii
        $s6 = "%s@gmail.com" wide ascii
        $s7 = "<!--%s-->" wide ascii
        $b8 = "W4qKihsb+So=" wide ascii
        $b9 = "PoqKigY7ggH+VcnqnTcmhFCo9w==" wide ascii
        $b10 = "8oqKiqb5880/uJLzAsY=" wide ascii

    condition:
        all of ($s*) or all of ($b*)
}

rule DeltaCharlie
{
	meta:
    sev = 4
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$rsaKey = {7B 4E 1E A7 E9 3F 36 4C DE F4 F0 99 C4 D9 B7 94 A1 FF F2 97 D3 91 13 9D C0 12 02 E4 4C BB 6C 77 48 EE 6F 4B  73 D7 1A 44 13 B3 6A BB 61 44 AF 31 47 E7 87 C2 AE 7A A7 2C 3A D9 5C 2E 42 1A A6 78 FE 2C AD ED 39 3F FA D0 AD 3D D9 C5 3F 58 A0 19 27 CC 27 C9 E8 D8 1E 7E EE 91 DD 13 B3 47 EF 57 1A CA FF 9A 60 E0 64 08 AA E2 92 D0}

	condition:
		any of them
}

rule IndiaCharlie_One
{
	meta:
    sev = 7
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$ = "WMPNetworkSvcUpdate"
		$ = "backSched.dll"
		$ = "\\mspaint.exe"
		$aesKey = "X,LLIe{))%%l2i<[AM|aq!Ql/lPlw]d7@C-#j.<c|#*}Kx4_H(q^F-F^p/[t#%HT"
	condition:
		2 of them or $aesKey
}

rule IndiaCharlie_Two
{
	meta:
    sev = 8
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$s1 = "%s is an essential element in Windows System configuration and management. %s"
		$s2 = "%SYSTEMROOT%\\system32\\svchost.exe -k "
		$s3 = "%s\\system32\\%s"
		$s4 = "\\mspaint.exe"
		$s5 = ":R\nIF NOT EXIST %s GOTO E\ndel /a %s\nGOTO R\n:E\ndel /a d.bat"
		$aesKey = "}[eLkQAeEae0t@h18g!)3x-RvE%+^`n.6^()?+00ME6a&F7vcV}`@.dj]&u$o*vX"

	condition:
		3 of ($s*) or $aesKey
}

rule apt_c16_win_memory_pcclient
{

  meta:
    sev = 9
    author = "@dragonthreatlab"
    md5 = "ec532bbe9d0882d403473102e9724557"
    description = "File matching the md5 above tends to only live in memory, hence the lack of MZ header check."
    date = "2015/01/11"
    reference = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"

  strings:
    $str1 = "Kill You" ascii
    $str2 = "%4d-%02d-%02d %02d:%02d:%02d" ascii
    $str3 = "%4.2f  KB" ascii
    $encodefunc = {8A 08 32 CA 02 CA 88 08 40 4E 75 F4}

  condition:
    all of them
}

rule apt_c16_win_disk_pcclient
{

  meta:
    sev = 9
    author = "@dragonthreatlab"
    md5 = "55f84d88d84c221437cd23cdbc541d2e"
    description = "Encoded version of pcclient found on disk"
    date = "2015/01/11"
    reference = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"

  strings:
    $header = {51 5C 96 06 03 06 06 06 0A 06 06 06 FF FF 06 06 BE 06 06 06 06 06 06 06 46 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 EE 06 06 06 10 1F BC 10 06 BA 0D D1 25 BE 05 52 D1 25 5A 6E 6D 73 26 76 74 6F 67 74 65 71 26 63 65 70 70 6F 7A 26 64 69 26 74 79 70 26 6D 70 26 4A 4F 53 26 71 6F 6A 69 30 11 11 0C 2A 06 06 06 06 06 06 06 73 43 96 1B 37 24 00 4E 37 24 00 4E 37 24 00 4E BA 40 F6 4E 39 24 00 4E 5E 41 FA 4E 33 24 00 4E 5E 41 FC 4E 39 24 00 4E 37 24 FF 4E 0D 24 00 4E FA 31 A3 4E 40 24 00 4E DF 41 F9 4E 36 24 00 4E F6 2A FE 4E 38 24 00 4E DF 41 FC 4E 38 24 00 4E 54 6D 63 6E 37 24 00 4E 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 56 49 06 06 52 05 09 06 5D 87 8C 5A 06 06 06 06 06 06 06 06 E6 06 10 25 0B 05 08 06 06 1C 06 06 06 1A 06 06 06 06 06 06 E5 27 06 06 06 16 06 06 06 36 06 06 06 06 06 16 06 16 06 06 06 04 06 06 0A 06 06 06 06 06 06 06 0A 06 06 06 06 06 06 06 06 76 06 06 06 0A 06 06 06 06 06 06 04 06 06 06 06 06 16 06 06 16 06 06}

  condition:
    $header at 0
}

rule apt_c16_win32_dropper
{

  meta:
    sev = 9
    author = "@dragonthreatlab"
    md5 = "ad17eff26994df824be36db246c8fb6a"
    description = "APT malware used to drop PcClient RAT"
    date = "2015/01/11"
    reference = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"

  strings:
    $mz = {4D 5A}
    $str1 = "clbcaiq.dll" ascii
    $str2 = "profapi_104" ascii
    $str3 = "/ShowWU" ascii
    $str4 = "Software\\Microsoft\\Windows\\CurrentVersion\\" ascii
    $str5 = {8A 08 2A CA 32 CA 88 08 40 4E 75 F4 5E}

  condition:
    $mz at 0 and all of ($str*)
}

rule apt_c16_win_swisyn
{

  meta:
    sev = 9
    author = "@dragonthreatlab"
    md5 = "a6a18c846e5179259eba9de238f67e41"
    description = "File matching the md5 above tends to only live in memory, hence the lack of MZ header check."
    date = "2015/01/11"
    reference = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"

  strings:
    $mz = {4D 5A}
    $str1 = "/ShowWU" ascii
    $str2 = "IsWow64Process"
    $str3 = "regsvr32 "
    $str4 = {8A 11 2A 55 FC 8B 45 08 88 10 8B 4D 08 8A 11 32 55 FC 8B 45 08 88 10}

  condition:
    $mz at 0 and all of ($str*)
}

rule apt_c16_win_wateringhole
{

  meta:
    sev = 9
    author = "@dragonthreatlab"
    description = "Detects code from APT wateringhole"
    date = "2015/01/11"
    reference = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"

  strings:
    $str1 = "function runmumaa()"
    $str2 = "Invoke-Expression $(New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$([Convert]::FromBase64String("
    $str3 = "function MoSaklgEs7(k)"

  condition:
    any of ($str*)
}

rule apt_c16_win64_dropper
{

    meta:
      sev = 9
      author = "@dragonthreatlab"
      date = "2015/01/11"
      description = "APT malware used to drop PcClient RAT"
      reference = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"

    strings:
        $mz = { 4D 5A }
        $str1 = "clbcaiq.dll" ascii
        $str2 = "profapi_104" ascii
        $str3 = "\\Microsoft\\wuauclt\\wuauclt.dat" ascii
        $str4 = { 0F B6 0A 48 FF C2 80 E9 03 80 F1 03 49 FF C8 88 4A FF 75 EC }

    condition:
        $mz at 0 and all of ($str*)
}

rule Industroyer_Malware_1 {
   meta:
      sev = 2
      description = "Detects Industroyer related malware"
      author = "Florian Roth"
      reference = "https://goo.gl/x81cSy"
      date = "2017-06-13"
      hash1 = "ad23c7930dae02de1ea3c6836091b5fb3c62a89bf2bcfb83b4b39ede15904910"
      hash2 = "018eb62e174efdcdb3af011d34b0bf2284ed1a803718fba6edffe5bc0b446b81"
   strings:
      $s1 = "haslo.exe" fullword ascii
      $s2 = "SYSTEM\\CurrentControlSet\\Services\\%ls" fullword wide
      $s3 = "SYS_BASCON.COM" fullword wide
      $s4 = "*.pcmt" fullword wide
      $s5 = "*.pcmi" fullword wide

      $x1 = { 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73
         00 5C 00 25 00 6C 00 73 00 00 00 49 00 6D 00 61
         00 67 00 65 00 50 00 61 00 74 00 68 00 00 00 43
         00 3A 00 5C 00 00 00 44 00 3A 00 5C 00 00 00 45
         00 3A 00 5C 00 00 00 }
      $x2 = "haslo.dat\x00Crash"
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of ($x*) or 2 of them )
}

rule Industroyer_Malware_2 {
   meta:
      sev = 8
      description = "Detects Industroyer related malware"
      author = "Florian Roth"
      reference = "https://goo.gl/x81cSy"
      date = "2017-06-13"
      hash1 = "3e3ab9674142dec46ce389e9e759b6484e847f5c1e1fc682fc638fc837c13571"
      hash2 = "37d54e3d5e8b838f366b9c202f75fa264611a12444e62ae759c31a0d041aa6e4"
      hash3 = "ecaf150e087ddff0ec6463c92f7f6cca23cc4fd30fe34c10b3cb7c2a6d135c77"
      hash1 = "6d707e647427f1ff4a7a9420188a8831f433ad8c5325dc8b8cc6fc5e7f1f6f47"
   strings:
      $x1 = "sc create %ls type= own start= auto error= ignore binpath= \"%ls\" displayname= \"%ls\"" fullword wide
      $x2 = "10.15.1.69:3128" fullword wide

      $s1 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; InfoPath.1)" fullword wide
      $s2 = "/c sc stop %s" fullword wide
      $s3 = "sc start %ls" fullword wide
      $s4 = "93.115.27.57" fullword wide
      $s5 = "5.39.218.152" fullword wide
      $s6 = "tierexe" fullword wide
      $s7 = "comsys" fullword wide
      $s8 = "195.16.88.6" fullword wide
      $s9 = "TieringService" fullword wide

      $a1 = "TEMP\x00\x00DEF" fullword wide
      $a2 = "TEMP\x00\x00DEF-C" fullword wide
      $a3 = "TEMP\x00\x00DEF-WS" fullword wide
      $a4 = "TEMP\x00\x00DEF-EP" fullword wide
      $a5 = "TEMP\x00\x00DC-2-TEMP" fullword wide
      $a6 = "TEMP\x00\x00DC-2" fullword wide
      $a7 = "TEMP\x00\x00CES-McA-TEMP" fullword wide
      $a8 = "TEMP\x00\x00SRV_WSUS" fullword wide
      $a9 = "TEMP\x00\x00SRV_DC-2" fullword wide
      $a10 = "TEMP\x00\x00SCE-WSUS01" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 1 of ($x*) or 3 of them or 1 of ($a*) ) or ( 5 of them )
}

rule Industroyer_Portscan_3 {
   meta:
    sev = 4
    description = "Detects Industroyer related custom port scaner"
    author = "Florian Roth"
    reference = "https://goo.gl/x81cSy"
    date = "2017-06-13"
    hash1 = "893e4cca7fe58191d2f6722b383b5e8009d3885b5913dcd2e3577e5a763cdb3f"
   strings:
    $s1 = "!ZBfamily" fullword ascii
    $s2 = ":g/outddomo;" fullword ascii
    $s3 = "GHIJKLMNOTST" fullword ascii
    /* Decompressed File */
    $d1 = "Error params Arguments!!!" fullword wide
    $d2 = "^(.+?.exe).*\\s+-ip\\s*=\\s*(.+)\\s+-ports\\s*=\\s*(.+)$" fullword wide
    $d3 = "Exhample:App.exe -ip= 127.0.0.1-100," fullword wide
    $d4 = "Error IP Range %ls - %ls" fullword wide
    $d5 = "Can't closesocket." fullword wide
   condition:
    ( uint16(0) == 0x5a4d and filesize < 500KB and all of ($s*) or 2 of ($d*) )
}

rule Industroyer_Portscan_3_Output {
   meta:
    sev = 9
    description = "Detects Industroyer related custom port scaner output file"
    author = "Florian Roth"
    reference = "https://goo.gl/x81cSy"
    date = "2017-06-13"
   strings:
    $s1 = "WSA library load complite." fullword ascii
    $s2 = "Connection refused" fullword ascii
   condition:
    all of them
}

rule Industroyer_Malware_4 {
   meta:
    sev = 2
    description = "Detects Industroyer related malware"
    author = "Florian Roth"
    reference = "https://goo.gl/x81cSy"
    date = "2017-06-13"
    hash1 = "21c1fdd6cfd8ec3ffe3e922f944424b543643dbdab99fa731556f8805b0d5561"
   strings:
    $s1 = "haslo.dat" fullword wide
    $s2 = "defragsvc" fullword ascii

    /* .dat\x00\x00Crash */
    $a1 = { 00 2E 00 64 00 61 00 74 00 00 00 43 72 61 73 68 00 00 00 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of ($s*) or $a1 )
}

rule Industroyer_Malware_5 {
   meta:
    sev = 7
    description = "Detects Industroyer related malware"
    author = "Florian Roth"
    reference = "https://goo.gl/x81cSy"
    date = "2017-06-13"
    hash1 = "7907dd95c1d36cf3dc842a1bd804f0db511a0f68f4b3d382c23a3c974a383cad"
   strings:
    $x1 = "D2MultiCommService.exe" fullword ascii
    $x2 = "Crash104.dll" fullword ascii
    $x3 = "iec104.log" fullword ascii
    $x4 = "IEC-104 client: ip=%s; port=%s; ASDU=%u " fullword ascii

    $s1 = "Error while getaddrinfo executing: %d" fullword ascii
    $s2 = "return info-Remote command" fullword ascii
    $s3 = "Error killing process ..." fullword ascii
    $s4 = "stop_comm_service_name" fullword ascii
    $s5 = "*1* Data exchange: Send: %d (%s)" fullword ascii
   condition:
    ( uint16(0) == 0x5a4d and filesize < 400KB and ( 1 of ($x*) or 4 of them ) ) or ( all of them )
}

rule rtf_Kaba_jDoe
{

meta:
    sev = 5
    author = "@patrickrolsen"
    maltype = "APT.Kaba"
    filetype = "RTF"
    version = "0.1"
    description = "fe439af268cd3de3a99c21ea40cf493f, d0e0e68a88dce443b24453cc951cf55f, b563af92f144dea7327c9597d9de574e, and def0c9a4c732c3a1e8910db3f9451620"
    date = "2013-12-10"

strings:
    $magic1 = { 7b 5c 72 74 30 31 } // {\rt01
    $magic2 = { 7b 5c 72 74 66 31 } // {\rtf1
    $magic3 = { 7b 5c 72 74 78 61 33 } // {\rtxa3
    $author1 = { 4A 6F 68 6E 20 44 6F 65 } // "John Doe"
    $author2 = { 61 75 74 68 6f 72 20 53 74 6f 6e 65 } // "author Stone"
    $string1 = { 44 30 [16] 43 46 [23] 31 31 45 }

condition:
    ($magic1 or $magic2 or $magic3 at 0) and all of ($author*) and $string1
}







rule apt_equation_exploitlib_mutexes
{

    meta:
        sev = 5
        copyright = "Kaspersky Lab"
        description = "Rule to detect Equation group's Exploitation library http://goo.gl/ivt8EW"
        version = "1.0"
        last_modified = "2015-02-16"
        reference = "http://securelist.com/blog/research/68750/equation-the-death-star-of-malware-galaxy/"

    strings:
        $mz="MZ"
        $a1="prkMtx" wide
        $a2="cnFormSyncExFBC" wide
        $a3="cnFormVoidFBC" wide
        $a4="cnFormSyncExFBC"
        $a5="cnFormVoidFBC"

    condition:
        (($mz at 0) and any of ($a*))
}

rule apt_equation_doublefantasy_genericresource
{

    meta:
        sev = 5
        copyright = "Kaspersky Lab"
        description = "Rule to detect DoubleFantasy encoded config http://goo.gl/ivt8EW"
        version = "1.0"
        last_modified = "2015-02-16"
        reference = "http://securelist.com/blog/research/68750/equation-the-death-star-of-malware-galaxy/"

    strings:
        $mz="MZ"
        $a1={06 00 42 00 49 00 4E 00 52 00 45 00 53 00}
        $a2="yyyyyyyyyyyyyyyy"
        $a3="002"

    condition:
        (($mz at 0) and all of ($a*)) and filesize < 500000
}

rule apt_equation_equationlaser_runtimeclasses
{

    meta:
        sev = 5
        copyright = "Kaspersky Lab"
        description = "Rule to detect the EquationLaser malware"
        version = "1.0"
        last_modified = "2015-02-16"
        reference = "https://securelist.com/blog/"

    strings:
        $a1="?a73957838_2@@YAXXZ"
        $a2="?a84884@@YAXXZ"
        $a3="?b823838_9839@@YAXXZ"
        $a4="?e747383_94@@YAXXZ"
        $a5="?e83834@@YAXXZ"
        $a6="?e929348_827@@YAXXZ"

    condition:
        any of them
}

rule apt_equation_cryptotable
{

    meta:
        sev = 5
        copyright = "Kaspersky Lab"
        description = "Rule to detect the crypto library used in Equation group malware"
        version = "1.0"
        last_modified = "2015-02-16"
        reference = "https://securelist.com/blog/"

    strings:
        $a={37 DF E8 B6 C7 9C 0B AE 91 EF F0 3B 90 C6 80 85 5D 19 4B 45 44 12 3C E2 0D 5C 1C 7B C4 FF D6 05 17 14 4F 03 74 1E 41 DA 8F 7D DE 7E 99 F1 35 AC B8 46 93 CE 23 82 07 EB 2B D4 72 71 40 F3 B0 F7 78 D7 4C D1 55 1A 39 83 18 FA E1 9A 56 B1 96 AB A6 30 C5 5F BE 0C 50 C1}

    condition:
        $a
}

/* Equation Group - Kaspersky ---------------------------------------------- */

rule Equation_Kaspersky_TripleFantasy_1
{

    meta:
        sev = 5
        description = "Equation Group Malware - TripleFantasy http://goo.gl/ivt8EW"
        author = "Florian Roth"
        reference = "http://goo.gl/ivt8EW"
        date = "2015/02/16"
        hash = "b2b2cd9ca6f5864ef2ac6382b7b6374a9fb2cbe9"

    strings:
        $mz = { 4d 5a }
        $s0 = "%SystemRoot%\\system32\\hnetcfg.dll" fullword wide
        $s1 = "%WINDIR%\\System32\\ahlhcib.dll" fullword wide
        $s2 = "%WINDIR%\\sjyntmv.dat" fullword wide
        $s3 = "Global\\{8c38e4f3-591f-91cf-06a6-67b84d8a0102}" fullword wide
        $s4 = "%WINDIR%\\System32\\owrwbsdi" fullword wide
        $s5 = "Chrome" fullword wide
        $s6 = "StringIndex" fullword ascii
        $x1 = "itemagic.net@443" fullword wide
        $x2 = "team4heat.net@443" fullword wide
        $x5 = "62.216.152.69@443" fullword wide
        $x6 = "84.233.205.37@443" fullword wide
        $z1 = "www.microsoft.com@80" fullword wide
        $z2 = "www.google.com@80" fullword wide
        $z3 = "127.0.0.1:3128" fullword wide

    condition:
        ( $mz at 0 ) and filesize < 300000 and (( all of ($s*) and all of ($z*) ) or ( all of ($s*) and 1 of ($x*) ))
}

rule Equation_Kaspersky_DoubleFantasy_1
{

    meta:
        sev = 5
        description = "Equation Group Malware - DoubleFantasy"
        author = "Florian Roth"
        reference = "http://goo.gl/ivt8EW"
        date = "2015/02/16"
        hash = "d09b4b6d3244ac382049736ca98d7de0c6787fa2"

    strings:
        $mz = { 4d 5a }
        $z1 = "msvcp5%d.dll" fullword ascii
        $s0 = "actxprxy.GetProxyDllInfo" fullword ascii
        $s3 = "actxprxy.DllGetClassObject" fullword ascii
        $s5 = "actxprxy.DllRegisterServer" fullword ascii
        $s6 = "actxprxy.DllUnregisterServer" fullword ascii
        $x1 = "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy" ascii
        $x2 = "191H1a1" fullword ascii
        $x3 = "November " fullword ascii
        $x4 = "abababababab" fullword ascii
        $x5 = "January " fullword ascii
        $x6 = "October " fullword ascii
        $x7 = "September " fullword ascii

    condition:
        ( $mz at 0 ) and filesize < 350000 and (( $z1 ) or ( all of ($s*) and 6 of ($x*) ))
}

rule Equation_Kaspersky_GROK_Keylogger
{

    meta:
        sev = 5
        description = "Equation Group Malware - GROK keylogger"
        author = "Florian Roth"
        reference = "http://goo.gl/ivt8EW"
        date = "2015/02/16"
        hash = "50b8f125ed33233a545a1aac3c9d4bb6aa34b48f"

    strings:
        $mz = { 4d 5a }
        $s0 = "c:\\users\\rmgree5\\" ascii
        $s1 = "msrtdv.sys" fullword wide
        $x1 = "svrg.pdb" fullword ascii
        $x2 = "W32pServiceTable" fullword ascii
        $x3 = "In forma" fullword ascii
        $x4 = "ReleaseF" fullword ascii
        $x5 = "criptor" fullword ascii
        $x6 = "astMutex" fullword ascii
        $x7 = "ARASATAU" fullword ascii
        $x8 = "R0omp4ar" fullword ascii
        $z1 = "H.text" fullword ascii
        $z2 = "\\registry\\machine\\software\\Microsoft\\Windows NT\\CurrentVersion" fullword wide
        $z4 = "\\registry\\machine\\SYSTEM\\ControlSet001\\Control\\Session Manager\\Environment" wide fullword

    condition:
        ( $mz at 0 ) and filesize < 250000 and ($s0 or ( $s1 and 6 of ($x*) ) or ( 6 of ($x*) and all of ($z*) ))
}

rule Equation_Kaspersky_GreyFishInstaller
{

    meta:
        sev = 5
        description = "Equation Group Malware - Grey Fish"
        author = "Florian Roth"
        reference = "http://goo.gl/ivt8EW"
        date = "2015/02/16"
        hash = "58d15d1581f32f36542f3e9fb4b1fc84d2a6ba35"

    strings:
        $s0 = "DOGROUND.exe" fullword wide
        $s1 = "Windows Configuration Services" fullword wide
        $s2 = "GetMappedFilenameW" fullword ascii

    condition:
        all of them
}

rule Equation_Kaspersky_EquationDrugInstaller
{

    meta:
        sev = 5
        description = "Equation Group Malware - EquationDrug installer LUTEUSOBSTOS"
        author = "Florian Roth"
        reference = "http://goo.gl/ivt8EW"
        date = "2015/02/16"
        hash = "61fab1b8451275c7fd580895d9c68e152ff46417"

    strings:
        $mz = { 4d 5a }

        $s0 = "\\system32\\win32k.sys" fullword wide
        $s1 = "ALL_FIREWALLS" fullword ascii
        $x1 = "@prkMtx" fullword wide
        $x2 = "STATIC" fullword wide
        $x3 = "windir" fullword wide
        $x4 = "cnFormVoidFBC" fullword wide
        $x5 = "CcnFormSyncExFBC" fullword wide
        $x6 = "WinStaObj" fullword wide
        $x7 = "BINRES" fullword wide

    condition:
        ( $mz at 0 ) and filesize < 500000 and all of ($s*) and 5 of ($x*)
}

rule Equation_Kaspersky_EquationLaserInstaller
{

    meta:
        sev = 5
        description = "Equation Group Malware - EquationLaser Installer"
        author = "Florian Roth"
        reference = "http://goo.gl/ivt8EW"
        date = "2015/02/16"
        hash = "5e1f56c1e57fbff96d4999db1fd6dd0f7d8221df"

    strings:
        $mz = { 4d 5a }
        $s0 = "Failed to get Windows version" fullword ascii
        $s1 = "lsasrv32.dll and lsass.exe" fullword wide
        $s2 = "\\\\%s\\mailslot\\%s" fullword ascii
        $s3 = "%d-%d-%d %d:%d:%d Z" fullword ascii
        $s4 = "lsasrv32.dll" fullword ascii
        $s5 = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" fullword ascii
        $s6 = "%s %02x %s" fullword ascii
        $s7 = "VIEWERS" fullword ascii
        $s8 = "5.2.3790.220 (srv03_gdr.040918-1552)" fullword wide

    condition:
        ( $mz at 0 ) and filesize < 250000 and 6 of ($s*)
}

rule Equation_Kaspersky_FannyWorm
{

    meta:
        sev = 5
        description = "Equation Group Malware - Fanny Worm"
        author = "Florian Roth"
        reference = "http://goo.gl/ivt8EW"
        date = "2015/02/16"
        hash = "1f0ae54ac3f10d533013f74f48849de4e65817a7"

    strings:
        $mz = { 4d 5a }
        $s1 = "x:\\fanny.bmp" fullword ascii
        $s2 = "32.exe" fullword ascii
        $s3 = "d:\\fanny.bmp" fullword ascii
        $x1 = "c:\\windows\\system32\\kernel32.dll" fullword ascii
        $x2 = "System\\CurrentControlSet\\Services\\USBSTOR\\Enum" fullword ascii
        $x3 = "System\\CurrentControlSet\\Services\\PartMgr\\Enum" fullword ascii
        $x4 = "\\system32\\win32k.sys" fullword wide
        $x5 = "\\AGENTCPD.DLL" fullword ascii
        $x6 = "agentcpd.dll" fullword ascii
        $x7 = "PADupdate.exe" fullword ascii
        $x8 = "dll_installer.dll" fullword ascii
        $x9 = "\\restore\\" fullword ascii
        $x10 = "Q:\\__?__.lnk" fullword ascii
        $x11 = "Software\\Microsoft\\MSNetMng" fullword ascii
        $x12 = "\\shelldoc.dll" fullword ascii
        $x13 = "file size = %d bytes" fullword ascii
        $x14 = "\\MSAgent" fullword ascii
        $x15 = "Global\\RPCMutex" fullword ascii
        $x16 = "Global\\DirectMarketing" fullword ascii

    condition:
        ( $mz at 0 ) and filesize < 300000 and (( 2 of ($s*) ) or ( 1 of ($s*) and 6 of ($x*) ) or ( 14 of ($x*)))
}

rule Equation_Kaspersky_HDD_reprogramming_module
{

    meta:
        sev = 5
        description = "Equation Group Malware - HDD reprogramming module"
        author = "Florian Roth"
        reference = "http://goo.gl/ivt8EW"
        date = "2015/02/16"
        hash = "ff2b50f371eb26f22eb8a2118e9ab0e015081500"

    strings:
        $mz = { 4d 5a }
        $s0 = "nls_933w.dll" fullword ascii
        $s1 = "BINARY" fullword wide
        $s2 = "KfAcquireSpinLock" fullword ascii
        $s3 = "HAL.dll" fullword ascii
        $s4 = "READ_REGISTER_UCHAR" fullword ascii
    condition:
        ( $mz at 0 ) and filesize < 300000 and all of ($s*)
}

rule Equation_Kaspersky_EOP_Package
{

    meta:
        sev = 5
        description = "Equation Group Malware - EoP package and malware launcher"
        author = "Florian Roth"
        reference = "http://goo.gl/ivt8EW"
        date = "2015/02/16"
        hash = "2bd1b1f5b4384ce802d5d32d8c8fd3d1dc04b962"

    strings:
        $mz = { 4d 5a }
        $s0 = "abababababab" fullword ascii
        $s1 = "abcdefghijklmnopq" fullword ascii
        $s2 = "@STATIC" fullword wide
        $s3 = "$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" fullword ascii
        $s4 = "@prkMtx" fullword wide
        $s5 = "prkMtx" fullword wide
        $s6 = "cnFormVoidFBC" fullword wide

    condition:
        ( $mz at 0 ) and filesize < 100000 and all of ($s*)
}

rule Equation_Kaspersky_TripleFantasy_Loader
{

    meta:
        sev = 5
        description = "Equation Group Malware - TripleFantasy Loader"
        author = "Florian Roth"
        reference = "http://goo.gl/ivt8EW"
        date = "2015/02/16"
        hash = "4ce6e77a11b443cc7cbe439b71bf39a39d3d7fa3"

    strings:
        $mz = { 4d 5a }
        $x1 = "Original Innovations, LLC" fullword wide
        $x2 = "Moniter Resource Protocol" fullword wide
        $x3 = "ahlhcib.dll" fullword wide
        $s0 = "hnetcfg.HNetGetSharingServicesPage" fullword ascii
        $s1 = "hnetcfg.IcfGetOperationalMode" fullword ascii
        $s2 = "hnetcfg.IcfGetDynamicFwPorts" fullword ascii
        $s3 = "hnetcfg.HNetFreeFirewallLoggingSettings" fullword ascii
        $s4 = "hnetcfg.HNetGetShareAndBridgeSettings" fullword ascii
        $s5 = "hnetcfg.HNetGetFirewallSettingsPage" fullword ascii

    condition:
        ( $mz at 0 ) and filesize < 50000 and ( all of ($x*) and all of ($s*) )
}

/* Rule generated from the mentioned keywords */

rule Equation_Kaspersky_SuspiciousString
{

    meta:
        sev = 5
        description = "Equation Group Malware - suspicious string found in sample"
        author = "Florian Roth"
        reference = "http://goo.gl/ivt8EW"
        date = "2015/02/17"
        score = 60

    strings:
        $mz = { 4d 5a }
        $s1 = "i386\\DesertWinterDriver.pdb" fullword
        $s2 = "Performing UR-specific post-install..."
        $s3 = "Timeout waiting for the \"canInstallNow\" event from the implant-specific EXE!"
        $s4 = "STRAITSHOOTER30.exe"
        $s5 = "standalonegrok_2.1.1.1"
        $s6 = "c:\\users\\rmgree5\\"

    condition:
        ( $mz at 0 ) and filesize < 500000 and all of ($s*)
}

/* EquationDrug Update 11.03.2015 - http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/ */

rule EquationDrug_NetworkSniffer1
{

    meta:
        sev = 5
        description = "EquationDrug - Backdoor driven by network sniffer - mstcp32.sys, fat32.sys"
        author = "Florian Roth @4nc4p"
        reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
        date = "2015/03/11"
        hash = "26e787997a338d8111d96c9a4c103cf8ff0201ce"

    strings:
        $s0 = "Microsoft(R) Windows (TM) Operating System" fullword wide
        $s1 = "\\Registry\\User\\CurrentUser\\" fullword wide
        $s3 = "sys\\mstcp32.dbg" fullword ascii
        $s7 = "mstcp32.sys" fullword wide
        $s8 = "p32.sys" fullword ascii
        $s9 = "\\Device\\%ws_%ws" fullword wide
        $s10 = "\\DosDevices\\%ws" fullword wide
        $s11 = "\\Device\\%ws" fullword wide

    condition:
        all of them
}

rule EquationDrug_CompatLayer_UnilayDLL
{

    meta:
        sev = 5
        description = "EquationDrug - Unilay.DLL"
        author = "Florian Roth @4nc4p"
        reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
        date = "2015/03/11"
        hash = "a3a31937956f161beba8acac35b96cb74241cd0f"

    strings:
        $mz = { 4d 5a }
        $s0 = "unilay.dll" fullword ascii

    condition:
        ( $mz at 0 ) and $s0
}

rule EquationDrug_HDDSSD_Op
{

    meta:
        sev = 5
        description = "EquationDrug - HDD/SSD firmware operation - nls_933w.dll"
        author = "Florian Roth @4nc4p"
        reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
        date = "2015/03/11"
        hash = "ff2b50f371eb26f22eb8a2118e9ab0e015081500"

    strings:
        $s0 = "nls_933w.dll" fullword ascii

    condition:
        all of them
}

rule EquationDrug_NetworkSniffer2
{

    meta:
        sev = 5
        description = "EquationDrug - Network Sniffer - tdip.sys"
        author = "Florian Roth @4nc4p"
        reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
        date = "2015/03/11"
        hash = "7e3cd36875c0e5ccb076eb74855d627ae8d4627f"

    strings:
        $s0 = "Microsoft(R) Windows (TM) Operating System" fullword wide
        $s1 = "IP Transport Driver" fullword wide
        $s2 = "tdip.sys" fullword wide
        $s3 = "sys\\tdip.dbg" fullword ascii
        $s4 = "dip.sys" fullword ascii
        $s5 = "\\Device\\%ws_%ws" fullword wide
        $s6 = "\\DosDevices\\%ws" fullword wide
        $s7 = "\\Device\\%ws" fullword wide

    condition:
        all of them
}

rule EquationDrug_NetworkSniffer3
{

    meta:
        sev = 5
        description = "EquationDrug - Network Sniffer - tdip.sys"
        author = "Florian Roth @4nc4p"
        reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
        date = "2015/03/11"
        hash = "14599516381a9646cd978cf962c4f92386371040"

    strings:
        $s0 = "Corporation. All rights reserved." fullword wide
        $s1 = "IP Transport Driver" fullword wide
        $s2 = "tdip.sys" fullword wide
        $s3 = "tdip.pdb" fullword ascii

    condition:
        all of them
}

rule EquationDrug_VolRec_Driver
{

    meta:
        sev = 5
        description = "EquationDrug - Collector plugin for Volrec - msrstd.sys"
        author = "Florian Roth @4nc4p"
        reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
        date = "2015/03/11"
        hash = "ee2b504ad502dc3fed62d6483d93d9b1221cdd6c"

    strings:
        $s0 = "msrstd.sys" fullword wide
        $s1 = "msrstd.pdb" fullword ascii
        $s2 = "msrstd driver" fullword wide

    condition:
        all of them
}

rule EquationDrug_KernelRootkit
{

    meta:
        sev = 5
        description = "EquationDrug - Kernel mode stage 0 and rootkit (Windows 2000 and above) - msndsrv.sys"
        author = "Florian Roth @4nc4p"
        reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
        date = "2015/03/11"
        hash = "597715224249e9fb77dc733b2e4d507f0cc41af6"

    strings:
        $s0 = "Microsoft(R) Windows (TM) Operating System" fullword wide
        $s1 = "Parmsndsrv.dbg" fullword ascii
        $s2 = "\\Registry\\User\\CurrentUser\\" fullword wide
        $s3 = "msndsrv.sys" fullword wide
        $s5 = "\\REGISTRY\\MACHINE\\System\\CurrentControlSet\\Control\\Windows" fullword wide
        $s6 = "\\Device\\%ws_%ws" fullword wide
        $s7 = "\\DosDevices\\%ws" fullword wide
        $s9 = "\\Device\\%ws" fullword wide

    condition:
        all of them
}

rule EquationDrug_Keylogger
{

    meta:
        sev = 5
        description = "EquationDrug - Key/clipboard logger driver - msrtvd.sys"
        author = "Florian Roth @4nc4p"
        reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
        date = "2015/03/11"
        hash = "b93aa17b19575a6e4962d224c5801fb78e9a7bb5"

    strings:
        $s0 = "\\registry\\machine\\software\\Microsoft\\Windows NT\\CurrentVersion" fullword wide
        $s2 = "\\registry\\machine\\SYSTEM\\ControlSet001\\Control\\Session Manager\\En" wide
        $s3 = "\\DosDevices\\Gk" fullword wide
        $s5 = "\\Device\\Gk0" fullword wide

    condition:
        all of them
}

rule EquationDrug_NetworkSniffer4
{

    meta:
        sev = 5
        description = "EquationDrug - Network-sniffer/patcher - atmdkdrv.sys"
        author = "Florian Roth @4nc4p"
        reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
        date = "2015/03/11"
        hash = "cace40965f8600a24a2457f7792efba3bd84d9ba"

    strings:
        $s0 = "Copyright 1999 RAVISENT Technologies Inc." fullword wide
        $s1 = "\\systemroot\\" fullword ascii
        $s2 = "RAVISENT Technologies Inc." fullword wide
        $s3 = "Created by VIONA Development" fullword wide
        $s4 = "\\Registry\\User\\CurrentUser\\" fullword wide
        $s5 = "\\device\\harddiskvolume" fullword wide
        $s7 = "ATMDKDRV.SYS" fullword wide
        $s8 = "\\Device\\%ws_%ws" fullword wide
        $s9 = "\\DosDevices\\%ws" fullword wide
        $s10 = "CineMaster C 1.1 WDM Main Driver" fullword wide
        $s11 = "\\Device\\%ws" fullword wide
        $s13 = "CineMaster C 1.1 WDM" fullword wide

    condition:
        all of them
}

/* 50 rule mark */

rule EquationDrug_PlatformOrchestrator
{

    meta:
        sev = 8
        description = "EquationDrug - Platform orchestrator - mscfg32.dll, svchost32.dll"
        author = "Florian Roth @4nc4p"
        reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
        date = "2015/03/11"
        hash = "febc4f30786db7804008dc9bc1cebdc26993e240"

    strings:
        $s0 = "SERVICES.EXE" fullword wide
        $s1 = "\\command.com" fullword wide
        $s2 = "Microsoft(R) Windows (TM) Operating System" fullword wide
        $s3 = "LSASS.EXE" fullword wide
        $s4 = "Windows Configuration Services" fullword wide
        $s8 = "unilay.dll" fullword ascii

    condition:
        all of them
}

rule EquationDrug_NetworkSniffer5
{

    meta:
        sev = 8
        description = "EquationDrug - Network-sniffer/patcher - atmdkdrv.sys"
        author = "Florian Roth @4nc4p"
        reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
        date = "2015/03/11"
        hash = "09399b9bd600d4516db37307a457bc55eedcbd17"

    strings:
        $s0 = "Microsoft(R) Windows (TM) Operating System" fullword wide
        $s1 = "\\Registry\\User\\CurrentUser\\" fullword wide
        $s2 = "atmdkdrv.sys" fullword wide
        $s4 = "\\Device\\%ws_%ws" fullword wide
        $s5 = "\\DosDevices\\%ws" fullword wide
        $s6 = "\\Device\\%ws" fullword wide

    condition:
        all of them
}

rule EquationDrug_FileSystem_Filter
{

    meta:
        sev = 8
        description = "EquationDrug - Filesystem filter driver – volrec.sys, scsi2mgr.sys"
        author = "Florian Roth @4nc4p"
        reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
        date = "2015/03/11"
        hash = "57fa4a1abbf39f4899ea76543ebd3688dcc11e13"

    strings:
        $s0 = "volrec.sys" fullword wide
        $s1 = "volrec.pdb" fullword ascii
        $s2 = "Volume recognizer driver" fullword wide

    condition:
        all of them
}

rule apt_equation_keyword
{

    meta:
        sev = 8
        description = "Rule to detect Equation group's keyword in executable file"
        author = "Florian Roth @4nc4p"
        last_modified = "2015-09-26"
        reference = "http://securelist.com/blog/research/68750/equation-the-death-star-of-malware-galaxy/"

    strings:
         $a1 = "Backsnarf_AB25" wide
         $a2 = "Backsnarf_AB25" ascii

    condition:
         uint16(0) == 0x5a4d and 1 of ($a*)
}


rule TidePool_Malware
{

    meta:
        sev = 8
        description = "Detects TidePool malware mentioned in Ke3chang report by Palo Alto Networks"
        author = "Florian Roth"
        reference = "http://goo.gl/m2CXWR"
        date = "2016-05-24"
        hash1 = "9d0a47bdf00f7bd332ddd4cf8d95dd11ebbb945dda3d72aac512512b48ad93ba"
        hash2 = "67c4e8ab0f12fae7b4aeb66f7e59e286bd98d3a77e5a291e8d58b3cfbc1514ed"
        hash3 = "2252dcd1b6afacde3f94d9557811bb769c4f0af3cb7a48ffe068d31bb7c30e18"
        hash4 = "38f2c86041e0446730479cdb9c530298c0c4936722975c4e7446544fd6dcac9f"
        hash5 = "9d0a47bdf00f7bd332ddd4cf8d95dd11ebbb945dda3d72aac512512b48ad93ba"

    strings:
        $x1 = "Content-Disposition: form-data; name=\"m1.jpg\"" fullword ascii
        $x2 = "C:\\PROGRA~2\\IEHelper\\mshtml.dll" fullword wide
        $x3 = "C:\\DOCUME~1\\ALLUSE~1\\IEHelper\\mshtml.dll" fullword wide
        $x4 = "IEComDll.dat" fullword ascii
        $s1 = "Content-Type: multipart/form-data; boundary=----=_Part_%x" fullword wide
        $s2 = "C:\\Windows\\System32\\rundll32.exe" fullword wide
        $s3 = "network.proxy.socks_port\", " fullword ascii

    condition:
        ( uint16(0) == 0x5a4d and filesize < 200KB and ( 1 of ($x*) ) ) or ( 4 of them )
}

rule backdoor_apt_pcclient
{

    meta:
        sev = 7
        author = "@patrickrolsen"
        maltype = "APT.PCCLient"
        filetype = "DLL"
        version = "0.1"
        description = "Detects the dropper: 869fa4dfdbabfabe87d334f85ddda234 AKA dw20.dll/msacm32.drv dropped by 4a85af37de44daf5917f545c6fd03902 (RTF)"
        date = "2012-10"

    strings:
        $magic = { 4d 5a } // MZ
        $string1 = "www.micro1.zyns.com"
        $string2 = "Mozilla/4.0 (compatible; MSIE 8.0; Win32)"
        $string3 = "msacm32.drv" wide
        $string4 = "C:\\Windows\\Explorer.exe" wide
        $string5 = "Elevation:Administrator!" wide
        $string6 = "C:\\Users\\cmd\\Desktop\\msacm32\\Release\\msacm32.pdb"

    condition:
        $magic at 0 and 4 of ($string*)
}

rule Trojan_Win32_PlaSrv
{

  meta:
      sev = 3
      author = "Microsoft"
      description = "Hotpatching Injector"
      original_sample_sha1 = "ff7f949da665ba8ce9fb01da357b51415634eaad"
      unpacked_sample_sha1 = "dff2fee984ba9f5a8f5d97582c83fca4fa1fe131"
      activity_group = "Platinum"
      version = "1.0"
      last_modified = "2016-04-12"

  strings:
      $Section_name = ".hotp1"
      $offset_x59 = { C7 80 64 01 00 00 00 00 01 00 }

  condition:
      $Section_name and $offset_x59
}

rule Trojan_Win32_Platual
{

  meta:
      sev = 3
      author = "Microsoft"
      description = "Installer component"
      original_sample_sha1 = "e0ac2ae221328313a7eee33e9be0924c46e2beb9"
      unpacked_sample_sha1 = "ccaf36c2d02c3c5ca24eeeb7b1eae7742a23a86a"
      activity_group = "Platinum"
      version = "1.0"
      last_modified = "2016-04-12"

  strings:
      $class_name = "AVCObfuscation"
      $scrambled_dir = { A8 8B B8 E3 B1 D7 FE 85 51 32 3E C0 F1 B7 73 99 }

  condition:
      $class_name and $scrambled_dir
}

rule Trojan_Win32_Plaplex
{

    meta:
        sev = 3
        author = "Microsoft"
        description = "Variant of the JPin backdoor"
        original_sample_sha1 = "ca3bda30a3cdc15afb78e54fa1bbb9300d268d66"
        unpacked_sample_sha1 = "2fe3c80e98bbb0cf5a0c4da286cd48ec78130a24"
        activity_group = "Platinum"
        version = "1.0"
        last_modified = "2016-04-12"

    strings:
        $class_name1 = "AVCObfuscation"
        $class_name2 = "AVCSetiriControl"

    condition:
        $class_name1 and $class_name2
}

rule Trojan_Win32_Dipsind_B
{

    meta:
        sev = 3
        author = "Microsoft"
        description = "Dipsind Family"
        sample_sha1 = "09e0dfbb5543c708c0dd6a89fd22bbb96dc4ca1c"
        activity_group = "Platinum"
        version = "1.0"
        last_modified = "2016-04-12"

    strings:
        $frg1 = {8D 90 04 01 00 00 33 C0 F2 AE F7 D1 2B F9 8B C1 8B F7 8B FA C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 4D EC 8B 15 ?? ?? ?? ?? 89 91 ?? 07 00 00 }
        $frg2 = {68 A1 86 01 00 C1 E9 02 F3 AB 8B CA 83 E1 03 F3 AA}
        $frg3 = {C0 E8 07 D0 E1 0A C1 8A C8 32 D0 C0 E9 07 D0 E0 0A C8 32 CA 80 F1 63}

    condition:
        $frg1 and $frg2 and $frg3
}

rule Trojan_Win32_PlaKeylog_B
{

    meta:
        sev = 3
        author = "Microsoft"
        description = "Keylogger component"
        original_sample_sha1 = "0096a3e0c97b85ca75164f48230ae530c94a2b77"
        unpacked_sample_sha1 = "6a1412daaa9bdc553689537df0a004d44f8a45fd"
        activity_group = "Platinum"
        version = "1.0"
        last_modified = "2016-04-12"

    strings:
        $hook = {C6 06 FF 46 C6 06 25}
        $dasm_engine = {80 C9 10 88 0E 8A CA 80 E1 07 43 88 56 03 80 F9 05}

    condition:
        $hook and $dasm_engine
}

rule Trojan_Win32_Adupib
{

    meta:
        sev = 3
        author = "Microsoft"
        description = "Adupib SSL Backdoor"
        original_sample_sha1 = "d3ad0933e1b114b14c2b3a2c59d7f8a95ea0bcbd"
        unpacked_sample_sha1 = "a80051d5ae124fd9e5cc03e699dd91c2b373978b"
        activity_group = "Platinum"
        version = "1.0"
        last_modified = "2016-04-12"

    strings:
        $str1 = "POLL_RATE"
        $str2 = "OP_TIME(end hour)"
        $str3 = "%d:TCP:*:Enabled"
        $str4 = "%s[PwFF_cfg%d]"
        $str5 = "Fake_GetDlgItemTextW: ***value***="

    condition:
        $str1 and $str2 and $str3 and $str4 and $str5
}

rule Trojan_Win32_PlaLsaLog
{

    meta:
        sev = 3
        author = "Microsoft"
        description = "Loader / possible incomplete LSA Password Filter"
        original_sample_sha1 = "fa087986697e4117c394c9a58cb9f316b2d9f7d8"
        unpacked_sample_sha1 = "29cb81dbe491143b2f8b67beaeae6557d8944ab4"
        activity_group = "Platinum"
        version = "1.0"
        last_modified = "2016-04-12"

    strings:
        $str1 = {8A 1C 01 32 DA 88 1C 01 8B 74 24 0C 41 3B CE 7C EF 5B 5F C6 04 01 00 5E 81 C4 04 01 00 00 C3}
        $str2 = "PasswordChangeNotify"

    condition:
        $str1 and $str2
}

rule Trojan_Win32_Plagon
{

    meta:
        sev = 3
        author = "Microsoft"
        description = "Dipsind variant"
        original_sample_sha1 = "48b89f61d58b57dba6a0ca857bce97bab636af65"
        unpacked_sample_sha1 = "6dccf88d89ad7b8611b1bc2e9fb8baea41bdb65a"
        activity_group = "Platinum"
        version = "1.0"
        last_modified = "2016-04-12"

    strings:
        $str1 = "VPLRXZHTU"
        $str2 = {64 6F 67 32 6A 7E 6C}
        $str3 = "Dqpqftk(Wou\"Isztk)"
        $str4 = "StartThreadAtWinLogon"
        condition:
        $str1 and $str2 and $str3 and $str4
}

rule Trojan_Win32_Plakelog
{

    meta:
        sev = 3
        author = "Microsoft"
        description = "Raw-input based keylogger"
        original_sample_sha1 = "3907a9e41df805f912f821a47031164b6636bd04"
        unpacked_sample_sha1 = "960feeb15a0939ec0b53dcb6815adbf7ac1e7bb2"
        activity_group = "Platinum"
        version = "1.0"
        last_modified = "2016-04-12"

    strings:
        $str1 = "<0x02>" wide
        $str2 = "[CTR-BRK]" wide
        $str3 = "[/WIN]" wide
        $str4 = {8A 16 8A 18 32 DA 46 88 18 8B 15 08 E6 42 00 40 41 3B CA 72 EB 5E 5B}

    condition:
        $str1 and $str2 and $str3 and $str4
}

rule Trojan_Win32_Plainst
{

    meta:
        sev = 3
        author = "Microsoft"
        description = "Installer component"
        original_sample_sha1 = "99c08d31af211a0e17f92dd312ec7ca2b9469ecb"
        unpacked_sample_sha1 = "dcb6cf7cf7c8fdfc89656a042f81136bda354ba6"
        activity_group = "Platinum"
        version = "1.0"
        last_modified = "2016-04-12"

    strings:
        $str1 = {66 8B 14 4D 18 50 01 10 8B 45 08 66 33 14 70 46 66 89 54 77 FE 66 83 7C 77 FE 00 75 B7 8B 4D FC 89 41 08 8D 04 36 89 41 0C 89 79 04}
        $str2 = {4b D3 91 49 A1 80 91 42 83 B6 33 28 36 6B 90 97}

    condition:
        $str1 and $str2
}

rule Trojan_Win32_Plagicom
{

    meta:
        sev = 3
        author = "Microsoft"
        description = "Installer component"
        original_sample_sha1 = "99dcb148b053f4cef6df5fa1ec5d33971a58bd1e"
        unpacked_sample_sha1 = "c1c950bc6a2ad67488e675da4dfc8916831239a7"
        activity_group = "Platinum"
        version = "1.0"
        last_modified = "2016-04-12"

    strings:
        $str1 = {C6 44 24 ?? 68 C6 44 24 ?? 4D C6 44 24 ?? 53 C6 44 24 ?? 56 C6 44 24 ?? 00}
        $str2 = "OUEMM/EMM"
        $str3 = {85 C9 7E 08 FE 0C 10 40 3B C1 7C F8 C3}

    condition:
        $str1 and $str2 and $str3
}

rule Trojan_Win32_Plaklog
{

    meta:
        sev = 3
        author = "Microsoft"
        description = "Hook-based keylogger"
        original_sample_sha1 = "831a5a29d47ab85ee3216d4e75f18d93641a9819"
        unpacked_sample_sha1 = "e18750207ddbd939975466a0e01bd84e75327dda"
        activity_group = "Platinum"
        version = "1.0"
        last_modified = "2016-04-12"

    strings:
        $str1 = "++[%s^^unknown^^%s]++"
        $str2 = "vtfs43/emm"
        $str3 = {33 C9 39 4C 24 08 7E 10 8B 44 24 04 03 C1 80 00 08 41 3B 4C 24 08 7C F0 C3}

    condition:
        $str1 and $str2 and $str3
}

rule Trojan_Win32_Plapiio
{

    meta:
        sev = 3
        author = "Microsoft"
        description = "JPin backdoor"
        original_sample_sha1 = "3119de80088c52bd8097394092847cd984606c88"
        unpacked_sample_sha1 = "3acb8fe2a5eb3478b4553907a571b6614eb5455c"
        activity_group = "Platinum"
        version = "1.0"
        last_modified = "2016-04-12"

    strings:
        $str1 = "ServiceMain"
        $str2 = "Startup"
        $str3 = {C6 45 ?? 68 C6 45 ?? 4D C6 45 ?? 53 C6 45 ?? 56 C6 45 ?? 6D C6 45 ?? 6D}

    condition:
        $str1 and $str2 and $str3
}

rule Trojan_Win32_Plabit
{

    meta:
        sev = 3
        author = "Microsoft" description = "Installer component" sample_sha1 = "6d1169775a552230302131f9385135d385efd166" activity_group = "Platinum" version = "1.0"
        last_modified = "2016-04-12"

    strings:
        $str1 = {4b D3 91 49 A1 80 91 42 83 B6 33 28 36 6B 90 97}
        $str2 = "GetInstanceW"
        $str3 = {8B D0 83 E2 1F 8A 14 0A 30 14 30 40 3B 44 24 04 72 EE}

    condition:
        $str1 and $str2 and $str3
}

rule Trojan_Win32_Placisc2
{

    meta:
        sev = 3
        author = "Microsoft"
        description = "Dipsind variant"
        original_sample_sha1 = "bf944eb70a382bd77ee5b47548ea9a4969de0527"
        unpacked_sample_sha1 = "d807648ddecc4572c7b04405f496d25700e0be6e"
        activity_group = "Platinum"
        version = "1.0"
        last_modified = "2016-04-12"

    strings:
        $str1 = {76 16 8B D0 83 E2 07 8A 4C 14 24 8A 14 18 32 D1 88 14 18 40 3B C7 72 EA }
        $str2 = "VPLRXZHTU"
        $str3 = "%d) Command:%s"
        $str4 = {0D 0A 2D 2D 2D 2D 2D 09 2D 2D 2D 2D 2D 2D 0D 0A}

    condition:
        $str1 and $str2 and $str3 and $str4
}

rule Trojan_Win32_Placisc3
{

    meta:
        sev = 3
        author = "Microsoft"
        description = "Dipsind variant"
        original_sample_sha1 = "1b542dd0dacfcd4200879221709f5fa9683cdcda"
        unpacked_sample_sha1 = "bbd4992ee3f3a3267732151636359cf94fb4575d"
        activity_group = "Platinum"
        version = "1.0"
        last_modified = "2016-04-12"

    strings:
        $str1 = {BA 6E 00 00 00 66 89 95 ?? ?? FF FF B8 73 00 00 00 66 89 85 ?? ?? FF FF B9 64 00 00 00 66 89 8D ?? ?? FF FF BA 65 00 00 00 66 89 95 ?? ?? FF FF B8 6C 00 00 00}
        $str2 = "VPLRXZHTU"
        $str3 = {8B 44 24 ?? 8A 04 01 41 32 C2 3B CF 7C F2 88 03}

    condition:
        $str1 and $str2 and $str3
}

rule Trojan_Win32_Placisc4
{

    meta:
        sev = 3
        author = "Microsoft"
        description = "Installer for Dipsind variant"
        original_sample_sha1 = "3d17828632e8ff1560f6094703ece5433bc69586"
        unpacked_sample_sha1 = "2abb8e1e9cac24be474e4955c63108ff86d1a034"
        activity_group = "Platinum"
        version = "1.0"
        last_modified = "2016-04-12"

    strings:
        $str1 = {8D 71 01 8B C6 99 BB 0A 00 00 00 F7 FB 0F BE D2 0F BE 04 39 2B C2 88 04 39 84 C0 74 0A}
        $str2 = {6A 04 68 00 20 00 00 68 00 00 40 00 6A 00 FF D5}
        $str3 = {C6 44 24 ?? 64 C6 44 24 ?? 6F C6 44 24 ?? 67 C6 44 24 ?? 32 C6 44 24 ?? 6A}

    condition:
        $str1 and $str2 and $str3
}

rule Trojan_Win32_Plakpers
{

    meta:
        sev = 3
        author = "Microsoft"
        description = "Injector / loader component"
        original_sample_sha1 = "fa083d744d278c6f4865f095cfd2feabee558056"
        unpacked_sample_sha1 = "3a678b5c9c46b5b87bfcb18306ed50fadfc6372e"
        activity_group = "Platinum"
        version = "1.0"
        last_modified = "2016-04-12"

    strings:
        $str1 = "MyFileMappingObject"
        $str2 = "[%.3u] %s %s %s [%s:" wide
        $str3 = "%s\\{%s}\\%s" wide

    condition:
        $str1 and $str2 and $str3
}

rule Trojan_Win32_Plainst2
{

    meta:
        sev = 3
        author = "Microsoft"
        description = "Zc tool"
        original_sample_sha1 = "3f2ce812c38ff5ac3d813394291a5867e2cddcf2"
        unpacked_sample_sha1 = "88ff852b1b8077ad5a19cc438afb2402462fbd1a"
        activity_group = "Platinum"
        version = "1.0"
        last_modified = "2016-04-12"

    strings:
        $str1 = "Connected [%s:%d]..."
        $str2 = "reuse possible: %c"
        $str3 = "] => %d%%\x0a"

    condition:
        $str1 and $str2 and $str3
}

rule Trojan_Win32_Plakpeer
{

    meta:
        sev = 3
        author = "Microsoft"
        description = "Zc tool v2"
        original_sample_sha1 = "2155c20483528377b5e3fde004bb604198463d29"
        unpacked_sample_sha1 = "dc991ef598825daabd9e70bac92c79154363bab2"
        activity_group = "Platinum"
        version = "1.0"
        last_modified = "2016-04-12"

    strings:
        $str1 = "@@E0020(%d)" wide
        $str2 = /exit.{0,3}@exit.{0,3}new.{0,3}query.{0,3}rcz.{0,3}scz/ wide
        $str3 = "---###---" wide
        $str4 = "---@@@---" wide

    condition:
        $str1 and $str2 and $str3 and $str4
}

/* 76 rules */

rule APT_Win_Pipcreat
{

  meta:
    sev = 9
    author = "chort (@chort0)"
    description = "APT backdoor Pipcreat"
    filetype = "pe,dll"
    date = "2013-03"
    MD5 = "f09d832bea93cf320986b53fce4b8397" // (incorrectly?) identified as Hupigon by many AV on VT
    Reference = "http://www.cyberengineeringservices.com/login-exe-analysis-trojan-pipcreat/"
    version = "1.0"

  strings:
    $strA = "pip creat failed" wide fullword
    $strB = "CraatePipe" ascii fullword
    $strC = "are you there? " wide fullword
    $strD = "success kill process ok" wide fullword
    $strE = "Vista|08|Win7" wide fullword
    $rut = "are you there!@#$%^&*()_+" ascii fullword

  condition:
    $rut or (2 of ($str*))
  }

  rule backdoor_apt_pcclient
  {

      meta:
          sev = 4
          author = "@patrickrolsen"
          maltype = "APT.PCCLient"
          filetype = "DLL"
          version = "0.1"
          description = "Detects the dropper: 869fa4dfdbabfabe87d334f85ddda234 AKA dw20.dll/msacm32.drv dropped by 4a85af37de44daf5917f545c6fd03902 (RTF)"
          date = "2012-10"

      strings:
          $magic = { 4d 5a } // MZ
          $string1 = "www.micro1.zyns.com"
          $string2 = "Mozilla/4.0 (compatible; MSIE 8.0; Win32)"
          $string3 = "msacm32.drv" wide
          $string4 = "C:\\Windows\\Explorer.exe" wide
          $string5 = "Elevation:Administrator!" wide
          $string6 = "C:\\Users\\cmd\\Desktop\\msacm32\\Release\\msacm32.pdb"

      condition:
          $magic at 0 and 4 of ($string*)
  }

  rule OilRig_Malware_Campaign_Gen1
  {

     meta:
        sev = 2
        description = "Detects malware from OilRig Campaign"
        author = "Florian Roth"
        reference = "https://goo.gl/QMRZ8K"
        date = "2016-10-12"
        hash1 = "d808f3109822c185f1d8e1bf7ef7781c219dc56f5906478651748f0ace489d34"
        hash2 = "80161dad1603b9a7c4a92a07b5c8bce214cf7a3df897b561732f9df7920ecb3e"
        hash3 = "662c53e69b66d62a4822e666031fd441bbdfa741e20d4511c6741ec3cb02475f"
        hash4 = "903b6d948c16dc92b69fe1de76cf64ab8377893770bf47c29bf91f3fd987f996"
        hash5 = "c4fbc723981fc94884f0f493cb8711fdc9da698980081d9b7c139fcffbe723da"
        hash6 = "57efb7596e6d9fd019b4dc4587ba33a40ab0ca09e14281d85716a253c5612ef4"
        hash7 = "1b2fee00d28782076178a63e669d2306c37ba0c417708d4dc1f751765c3f94e1"
        hash8 = "9f31a1908afb23a1029c079ee9ba8bdf0f4c815addbe8eac85b4163e02b5e777"
        hash9 = "0cd9857a3f626f8e0c07495a4799c59d502c4f3970642a76882e3ed68b790f8e"
        hash10 = "4b5112f0fb64825b879b01d686e8f4d43521252a3b4f4026c9d1d76d3f15b281"
        hash11 = "4e5b85ea68bf8f2306b6b931810ae38c8dff3679d78da1af2c91032c36380353"
        hash12 = "c3c17383f43184a29f49f166a92453a34be18e51935ddbf09576a60441440e51"
        hash13 = "f3856c7af3c9f84101f41a82e36fc81dfc18a8e9b424a3658b6ba7e3c99f54f2"
        hash14 = "0c64ab9b0c122b1903e8063e3c2c357cbbee99de07dc535e6c830a0472a71f39"
        hash15 = "d874f513a032ccb6a5e4f0cd55862b024ea0bee4de94ccf950b3dd894066065d"
        hash16 = "8ee628d46b8af20c4ba70a2fe8e2d4edca1980583171b71fe72455c6a52d15a9"
        hash17 = "55d0e12439b20dadb5868766a5200cbbe1a06053bf9e229cf6a852bfcf57d579"
        hash18 = "528d432952ef879496542bc62a5a4b6eee788f60f220426bd7f933fa2c58dc6b"
        hash19 = "93940b5e764f2f4a2d893bebef4bf1f7d63c4db856877020a5852a6647cb04a0"
        hash20 = "e2ec7fa60e654f5861e09bbe59d14d0973bd5727b83a2a03f1cecf1466dd87aa"
        hash21 = "9c0a33a5dc62933f17506f20e0258f877947bdcd15b091a597eac05d299b7471"
        hash22 = "a787c0e42608f9a69f718f6dca5556607be45ec77d17b07eb9ea1e0f7bb2e064"
        hash23 = "3772d473a2fe950959e1fd56c9a44ec48928f92522246f75f4b8cb134f4713ff"
        hash24 = "3986d54b00647b507b2afd708b7a1ce4c37027fb77d67c6bc3c20c3ac1a88ca4"
        hash25 = "f5a64de9087b138608ccf036b067d91a47302259269fb05b3349964ca4060e7e"

     strings:
        $x1 = "Get-Content $env:Public\\Libraries\\update.vbs) -replace" ascii
        $x2 = "wss.Run \"powershell.exe \" & Chr(34) & \"& {waitfor haha /T 2}\" & Chr(34), 0" fullword ascii
        $x3 = "Call Extract(UpdateVbs, wss.ExpandEnvironmentStrings(\"%PUBLIC%\") & \"\\Libraries\\update.vbs\")" fullword ascii
        $s4 = "CreateObject(\"WScript.Shell\").Run cmd, 0o" fullword ascii
        /* Base64 encode config */
        /* $global:myhost = */
        $b1 = "JGdsb2JhbDpteWhvc3QgP" ascii
        /* HOME="%public%\Libraries\" */
        $b2 = "SE9NRT0iJXB1YmxpYyVcTGlicmFyaWVzX" ascii
        /* Set wss = CreateObject("wScript.Shell") */
        $b3 = "U2V0IHdzcyA9IENyZWF0ZU9iamVjdCgid1NjcmlwdC5TaGV" ascii
        /* $scriptdir = Split-Path -Parent -Path $ */
        $b4 = "JHNjcmlwdGRpciA9IFNwbGl0LVBhdGggLVBhcmVudCAtUGF0aCA" ascii
        /* \x0aSet wss = CreateObject("wScript.Shell") */
        $b5 = "DQpTZXQgd3NzID0gQ3JlYXRlT2JqZWN" ascii
        /* whoami & hostname */
        $b6 = "d2hvYW1pICYgaG9zdG5hb" ascii

     condition:
        ( uint16(0) == 0xcfd0 and filesize < 700KB and 1 of them )
  }

  rule OilRig_Malware_Campaign_Mal1
  {

     meta:
        sev = 2
        description = "Detects malware from OilRig Campaign"
        author = "Florian Roth"
        reference = "https://goo.gl/QMRZ8K"
        date = "2016-10-12"
        hash1 = "e17e1978563dc10b73fd54e7727cbbe95cc0b170a4e7bd0ab223e059f6c25fcc"

     strings:
        $x1 = "DownloadExecute=\"powershell \"\"&{$r=Get-Random;$wc=(new-object System.Net.WebClient);$wc.DownloadFile(" ascii
        $x2 = "-ExecutionPolicy Bypass -File \"&HOME&\"dns.ps1\"" fullword ascii
        $x3 = "CreateObject(\"WScript.Shell\").Run Replace(DownloadExecute,\"-_\",\"bat\")" fullword ascii
        $x4 = "CreateObject(\"WScript.Shell\").Run DnsCmd,0" fullword ascii
        $s1 = "http://winodwsupdates.me" ascii

     condition:
        ( uint16(0) == 0x4f48 and filesize < 4KB and 1 of them ) or ( 2 of them )
  }

  rule OilRig_Malware_Campaign_Gen2
  {

     meta:
        sev = 2
        description = "Detects malware from OilRig Campaign"
        author = "Florian Roth"
        reference = "https://goo.gl/QMRZ8K"
        date = "2016-10-12"
        hash1 = "c6437f57a8f290b5ec46b0933bfa8a328b0cb2c0c7fbeea7f21b770ce0250d3d"
        hash2 = "293522e83aeebf185e653ac279bba202024cedb07abc94683930b74df51ce5cb"

     strings:
        $s1 = "%userprofile%\\AppData\\Local\\Microsoft\\ " fullword ascii
        $s2 = "$fdn=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('" fullword ascii
        $s3 = "&{$rn = Get-Random; $id = 'TR" fullword ascii
        $s4 = "') -replace '__',('DNS'+$id) | " fullword ascii
        $s5 = "\\upd.vbs" fullword ascii
        $s6 = "schtasks /create /F /sc minute /mo " fullword ascii
        $s7 = "') -replace '__',('HTP'+$id) | " fullword ascii
        $s8 = "&{$rn = Get-Random -minimum 1 -maximum 10000; $id = 'AZ" fullword ascii
        $s9 = "http://www.israirairlines.com/?mode=page&page=14635&lang=eng<" fullword ascii

     condition:
        ( uint16(0) == 0xcfd0 and filesize < 4000KB and 2 of ($s*) ) or ( 4 of them )
  }

  rule OilRig_Malware_Campaign_Gen3
  {

     meta:
        sev = 2
        description = "Detects malware from OilRig Campaign"
        author = "Florian Roth"
        reference = "https://goo.gl/QMRZ8K"
        date = "2016-10-12"
        hash1 = "5e9ddb25bde3719c392d08c13a295db418d7accd25d82d020b425052e7ba6dc9"
        hash2 = "bd0920c8836541f58e0778b4b64527e5a5f2084405f73ee33110f7bc189da7a9"
        hash3 = "90639c7423a329e304087428a01662cc06e2e9153299e37b1b1c90f6d0a195ed"

     strings:
        $x1 = "source code from https://www.fireeye.com/blog/threat-research/2016/05/targeted_attacksaga.htmlrrrr" fullword ascii
        $x2 = "\\Libraries\\fireueye.vbs" fullword ascii
        $x3 = "\\Libraries\\fireeye.vbs&" fullword wide

     condition:
        ( uint16(0) == 0xcfd0 and filesize < 100KB and 1 of them )
  }

  rule OilRig_Malware_Campaign_Mal2
  {

     meta:
        sev = 2
        description = "Detects malware from OilRig Campaign"
        author = "Florian Roth"
        reference = "https://goo.gl/QMRZ8K"
        date = "2016-10-12"
        hash1 = "65920eaea00764a245acb58a3565941477b78a7bcc9efaec5bf811573084b6cf"

     strings:
        $x1 = "wss.Run \"powershell.exe \" & Chr(34) & \"& {(Get-Content $env:Public\\Libraries\\update.vbs) -replace '__',(Get-Random) | Set-C" ascii
        $x2 = "Call Extract(UpdateVbs, wss.ExpandEnvironmentStrings(\"%PUBLIC%\") & \"\\Libraries\\update.vbs\")" fullword ascii
        $x3 = "mailto:Mohammed.sarah@gratner.com" fullword wide
        $x4 = "mailto:Tarik.Imam@gartner.com" fullword wide
        $x5 = "Call Extract(DnsPs1, wss.ExpandEnvironmentStrings(\"%PUBLIC%\") & \"\\Libraries\\dns.ps1\")" fullword ascii
        $x6 = "2dy53My5vcmcvMjAw" fullword wide /* base64 encoded string 'w.w3.org/200' */

     condition:
        ( uint16(0) == 0xcfd0 and filesize < 200KB and 1 of them )
  }

  rule OilRig_Campaign_Reconnaissance
  {

     meta:
        sev = 2
        description = "Detects Windows discovery commands - known from OilRig Campaign"
        author = "Florian Roth"
        reference = "https://goo.gl/QMRZ8K"
        date = "2016-10-12"
        hash1 = "5893eae26df8e15c1e0fa763bf88a1ae79484cdb488ba2fc382700ff2cfab80c"

     strings:
        $s1 = "whoami & hostname & ipconfig /all" ascii
        $s2 = "net user /domain 2>&1 & net group /domain 2>&1" ascii
        $s3 = "net group \"domain admins\" /domain 2>&1 & " ascii

     condition:
        ( filesize < 1KB and 1 of them )
  }

  rule OilRig_Malware_Campaign_Mal3
  {

     meta:
        sev = 2
        description = "Detects malware from OilRig Campaign"
        author = "Florian Roth"
        reference = "https://goo.gl/QMRZ8K"
        date = "2016-10-12"
        hash1 = "02226181f27dbf59af5377e39cf583db15200100eea712fcb6f55c0a2245a378"

     strings:
        $x1 = "(Get-Content $env:Public\\Libraries\\dns.ps1) -replace ('#'+'##'),$botid | Set-Content $env:Public\\Libraries\\dns.ps1" fullword ascii
        $x2 = "Invoke-Expression ($global:myhome+'tp\\'+$global:filename+'.bat > '+$global:myhome+'tp\\'+$global:filename+'.txt')" fullword ascii
        $x3 = "('00000000'+(convertTo-Base36(Get-Random -Maximum 46655)))" fullword ascii

     condition:
        ( filesize < 10KB and 1 of them )
  }

  /* 85 rules */

  rule Sofacy_Fybis_ELF_Backdoor_Gen1
  {

      meta:
          sev = 4
          description = "Detects Sofacy Fysbis Linux Backdoor_Naikon_APT_Sample1"
          author = "Florian Roth"
          reference = "http://researchcenter.paloaltonetworks.com/2016/02/a-look-into-fysbis-sofacys-linux-backdoor/"
          date = "2016-02-13"
          score = 80
          hash1 = "02c7cf55fd5c5809ce2dce56085ba43795f2480423a4256537bfdfda0df85592"
          hash2 = "8bca0031f3b691421cb15f9c6e71ce193355d2d8cf2b190438b6962761d0c6bb"

      strings:
          $x1 = "Your command not writed to pipe" fullword ascii
          $x2 = "Terminal don`t started for executing command" fullword ascii
          $x3 = "Command will have end with \\n" fullword ascii
          $s1 = "WantedBy=multi-user.target' >> /usr/lib/systemd/system/" fullword ascii
          $s2 = "Success execute command or long for waiting executing your command" fullword ascii
          $s3 = "ls /etc | egrep -e\"fedora*|debian*|gentoo*|mandriva*|mandrake*|meego*|redhat*|lsb-*|sun-*|SUSE*|release\"" fullword ascii
          $s4 = "rm -f /usr/lib/systemd/system/" fullword ascii
          $s5 = "ExecStart=" fullword ascii
          $s6 = "<table><caption><font size=4 color=red>TABLE EXECUTE FILES</font></caption>" fullword ascii

      condition:
          ( uint16(0) == 0x457f and filesize < 500KB and 1 of ($x*) ) or ( 1 of ($x*) and 3 of ($s*) )
  }

  rule Sofacy_Fysbis_ELF_Backdoor_Gen2
  {

      meta:
          sev = 4
          description = "Detects Sofacy Fysbis Linux Backdoor"
          author = "Florian Roth"
          reference = "http://researchcenter.paloaltonetworks.com/2016/02/a-look-into-fysbis-sofacys-linux-backdoor/"
          date = "2016-02-13"
          score = 80
          hash1 = "02c7cf55fd5c5809ce2dce56085ba43795f2480423a4256537bfdfda0df85592"
          hash2 = "8bca0031f3b691421cb15f9c6e71ce193355d2d8cf2b190438b6962761d0c6bb"
          hash3 = "fd8b2ea9a2e8a67e4cb3904b49c789d57ed9b1ce5bebfe54fe3d98214d6a0f61"

      strings:
          $s1 = "RemoteShell" ascii
          $s2 = "basic_string::_M_replace_dispatch" fullword ascii
          $s3 = "HttpChannel" ascii

      condition:
          uint16(0) == 0x457f and filesize < 500KB and all of them
  }

  rule apt_all_JavaScript_ScanboxFramework_obfuscated

{
              meta:
                    sev = 8
                    ref = "https://www.fidelissecurity.com/TradeSecret"

                  strings:

              $sa1 = /(var|new|return)\s[_\$]+\s?/

                  $sa2 = "function"

                  $sa3 = "toString"

                  $sa4 = "toUpperCase"

                  $sa5 = "arguments.length"

                  $sa6 = "return"

                  $sa7 = "while"

                  $sa8 = "unescape("

                  $sa9 = "365*10*24*60*60*1000"

                  $sa10 = ">> 2"

                  $sa11 = "& 3) << 4"

                  $sa12 = "& 15) << 2"

                  $sa13 = ">> 6) | 192"

                  $sa14 = "& 63) | 128"

                  $sa15 = ">> 12) | 224"

                  condition:

                  all of them

}

rule GEN_PowerShell
{

    meta:
        sev = 6
        description = "Generic PowerShell Malware Rule"
        author = "https://github.com/interleaved"

    strings:
        $s1 = "powershell"
        $s2 = "-ep bypass" nocase
        $s3 = "-nop" nocase
        $s10 = "-executionpolicy bypass" nocase
        $s4 = "-win hidden" nocase
        $s5 = "-windowstyle hidden" nocase
        $s11 = "-w hidden" nocase
        /*$s6 = "-noni" fullword ascii*/
        /*$s7 = "-noninteractive" fullword ascii*/
        $s8 = "-enc" nocase
        $s9 = "-encodedcommand" nocase

    condition:
        $s1 and (($s2 or $s3 or $s10) and ($s4 or $s5 or $s11) and ($s8 or $s9))
}

rule Batel_export_function
{

    meta:
        sev = 5
        author = "@j0sm1"
        date = "2016/10/15"
        description = "Batel backdoor"
        reference = "https://www.symantec.com/security_response/writeup.jsp?docid=2016-091923-4146-99"
        filetype = "binary"

    condition:
        pe.exports("run_shell") and pe.imports("kernel32.dll","GetTickCount") and pe.imports("kernel32.dll","IsDebuggerPresent") and pe.imports("msvcr100.dll","_crt_debugger_hook") and pe.imports("kernel32.dll","TerminateProcess") and pe.imports("kernel32.dll","UnhandledExceptionFilter")
}

rule ws_f0xy_downloader {
  meta:
    sev = 7
    description = "f0xy malware downloader"
    author = "Nick Griffin (Websense)"

  strings:
    $mz="MZ"
    $string1="bitsadmin /transfer"
    $string2="del rm.bat"
    $string3="av_list="

  condition:
    ($mz at 0) and (all of ($string*))
}

rule Backdoor_Jolob
{
	meta:
    sev = 2
		maltype = "Backdoor.Jolob"
    ref = "https://github.com/reed1713"
		reference = "http://www.symantec.com/connect/blogs/new-flash-zero-day-linked-yet-more-watering-hole-attacks"
		description = "the backdoor registers an auto start service with the display name \"Network Access Management Agent\" pointing to the dll netfilter.dll. This is accomplished without notifying the user via the sysprep UAC bypass method."
	strings:
		$type = "Microsoft-Windows-Security-Auditing"
		$eventid = "4673"
		$data1 = "Security"
		$data2 = "SeCreateGlobalPrivilege"
		$data3 = "Windows\\System32\\sysprep\\sysprep.exe" nocase

		$type1 = "Microsoft-Windows-Security-Auditing"
		$eventid1 = "4688"
		$data4 = "Windows\\System32\\sysprep\\sysprep.exe" nocase

		$type2 = "Service Control Manager"
		$eventid2 = "7036"
		$data5 = "Network Access Management Agent"
		$data6 = "running"

		$type3 = "Service Control Manager"
		$eventid3 = "7045"
		$data7 = "Network Access Management Agent"
		$data8 = "user mode service"
		$data9 = "auto start"
    condition:
    	all of them
}

rule NaikonCode : Naikon Family
{
    meta:
        sev = 10
        description = "Naikon code features"
        author = "Seth Hardy"
        last_modified = "2014-06-25"

    strings:
        // decryption
        $ = { 0F AF C1 C1 E0 1F } // imul eax, ecx; shl eah, 1fh
        $ = { 35 5A 01 00 00} // xor eax, 15ah
        $ = { 81 C2 7F 14 06 00 } // add edx, 6147fh

    condition:
        all of them
}

rule NaikonStrings : Naikon Family
{
    meta:
        sev = 1
        description = "Naikon Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-25"

    strings:
        $ = "NOKIAN95/WEB"
        $ = "/tag=info&id=15"
        $ = "skg(3)=&3.2d_u1"
        $ = "\\Temp\\iExplorer.exe"
        $ = "\\Temp\\\"TSG\""

    condition:
       any of them
}

rule Naikon : Family
{
    meta:
        sev = 3
        description = "Naikon"
        author = "Seth Hardy"
        last_modified = "2014-06-25"

    condition:
        NaikonCode or NaikonStrings
}
rule Backdoor_Naikon_APT_Sample1 {
	meta:
		description = "Detects backdoors related to the Naikon APT"
		author = "Florian Roth"
		reference = "https://goo.gl/7vHyvh"
		date = "2015-05-14"
		hash = "d5716c80cba8554eb79eecfb4aa3d99faf0435a1833ec5ef51f528146c758eba"
		hash = "f5ab8e49c0778fa208baad660fe4fa40fc8a114f5f71614afbd6dcc09625cb96"
	strings:
		$x0 = "GET http://%s:%d/aspxabcdef.asp?%s HTTP/1.1" fullword ascii
		$x1 = "POST http://%s:%d/aspxabcdefg.asp?%s HTTP/1.1" fullword ascii
		$x2 = "greensky27.vicp.net" fullword ascii
		$x3 = "\\tempvxd.vxd.dll" fullword wide
		$x4 = "otna.vicp.net" fullword ascii
		$x5 = "smithking19.gicp.net" fullword ascii

		$s1 = "User-Agent: webclient" fullword ascii
		$s2 = "\\User.ini" fullword ascii
		$s3 = "User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-EN; rv:1.7.12) Gecko/200" ascii
		$s4 = "\\UserProfile.dll" fullword wide
		$s5 = "Connection:Keep-Alive: %d" fullword ascii
		$s6 = "Referer: http://%s:%d/" fullword ascii
		$s7 = "%s %s %s %d %d %d " fullword ascii
		$s8 = "%s--%s" fullword wide
		$s9 = "Run File Success!" fullword wide
		$s10 = "DRIVE_REMOTE" fullword wide
		$s11 = "ProxyEnable" fullword wide
		$s12 = "\\cmd.exe" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and
		(
			1 of ($x*) or 7 of ($s*)
		)
}

rule Predator_The_Thief : Predator_The_Thief {
   meta:
        sev = 8
        description = "Yara rule for Predator The Thief v2.3.5 & +"
        author = "Fumik0_"
        date = "2018/10/12"
        source = "https://fumik0.com/2018/10/15/predator-the-thief-in-depth-analysis-v2-3-5/"
   strings:
        $mz = { 4D 5A }

        $hex1 = { BF 00 00 40 06 }
        $hex2 = { C6 04 31 6B }
        $hex3 = { C6 04 31 63 }
        $hex4 = { C6 04 31 75 }
        $hex5 = { C6 04 31 66 }

        $s1 = "sqlite_" ascii wide
   condition:
        $mz at 0 and all of ($hex*) and all of ($s*)
}

rule Tedroo : Spammer
{
	meta:
    sev = 2
		author="Kevin Falcoz"
		date="22/11/2015"
		description="Tedroo Spammer"

	strings:
		$signature1={25 73 25 73 2E 65 78 65}
		$signature2={5F 6C 6F 67 2E 74 78 74}

	condition:
		$signature1 and $signature2
}

rule yordanyan_activeagent {
	meta:
    sev = 8
		description = "Memory string yara for Yordanyan ActiveAgent"
		author = "J from THL <j@techhelplist.com>"
		reference1 = "https://www.virustotal.com/#/file/a2e34bfd5a9789837bc2d580e87ec11b9f29c4a50296ef45b06e3895ff399746/detection"
		reference2 = "ETPRO TROJAN Win32.ActiveAgent CnC Create"
		date = "2018-10-04"
		maltype = "Botnet"
		filetype = "memory"

	strings:
		// the wide strings are 16bit bigendian strings in memory. strings -e b memdump.file
		$s01 = "I'm KeepRunner!" wide
		$s02 = "I'm Updater!" wide
		$s03 = "Starting Download..." wide
		$s04 = "Download Complete!" wide
		$s05 = "Running New Agent and terminating updater!" wide
		$s06 = "Can't Run downloaded file!" wide
		$s07 = "Retrying download and run!" wide
		$s08 = "Can't init Client." wide
		$s09 = "Client initialised -" wide
		$s10 = "Client not found!" wide
		$s11 = "Client signed." wide
		$s12 = "GetClientData" wide
		$s13 = "&counter=" wide
		$s14 = "&agent_file_version=" wide
		$s15 = "&agent_id=" wide
		$s16 = "mac_address=" wide
		$s17 = "Getting Attachments" wide
		$s18 = "public_name" wide
		$s19 = "Yor agent id =" wide
		$s20 = "Yor agent version =" wide
		$s21 = "Last agent version =" wide
		$s22 = "Agent is last version." wide
		$s23 = "Updating Agent" wide
		$s24 = "Terminating RunKeeper" wide
		$s25 = "Terminating RunKeeper: Done" wide
		$s26 = "ActiveAgent" ascii
		$s27 = "public_name" ascii

	condition:
		15 of them

}

rule PoS_Malware_fastpos : FastPOS POS keylogger
{
meta:
sev = 7
author = "Trend Micro, Inc."
date = "2016-05-18"
description = "Used to detect FastPOS keyloggger + scraper"
reference = "http://documents.trendmicro.com/assets/fastPOS-quick-and-easy-credit-card-theft.pdf"
sample_filetype = "exe"
strings:
$string1 = "uniqyeidclaxemain"
$string2 = "http://%s/cdosys.php"
$string3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
$string4 = "\\The Hook\\Release\\The Hook.pdb" nocase
condition:
all of ($string*)
}

rule Ransom_Satana
{
    meta:
        sev = 7
        description = "Regla para detectar Ransom.Satana"
        author = "CCN-CERT"
        version = "1.0"
    strings:
        $a = { 21 00 73 00 61 00 74 00 61 00 6E 00 61 00 21 00 2E 00 74 00 78 00 74 00 00 }
        $b = { 74 67 77 79 75 67 77 71 }
        $c = { 53 77 76 77 6E 67 75 }
        $d = { 45 6E 75 6D 4C 6F 63 61 6C 52 65 73 }
        $e = { 57 4E 65 74 4F 70 65 6E 45 6E 75 6D 57 00 }
        $f = { 21 53 41 54 41 4E 41 21 }
    condition:
        $b or $c and $d and $a and $e and $f
}

rule Ransom_Satana_Dropper
{
    meta:
        description = "Regla para detectar el dropper de Ransom.Satana"
        author = "CCN-CERT"
        version = "1.0"
    strings:
        $a = { 25 73 2D 54 72 79 45 78 63 65 70 74 }
        $b = { 64 3A 5C 6C 62 65 74 77 6D 77 79 5C 75 69 6A 65 75 71 70 6C 66 77 75 62 2E 70 64 62 }
        $c = { 71 66 6E 74 76 74 68 62 }
    condition:
        all of them
}
