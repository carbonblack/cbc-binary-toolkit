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
