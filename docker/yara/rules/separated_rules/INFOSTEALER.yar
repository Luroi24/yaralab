rule DEADBITS_KPOT_V2 : WINMALWARE INFOSTEALER FILE
{
	meta:
		description = "No description has been set in the source file - DeadBits"
		author = "Adam Swanda"
		id = "19e8d261-c658-5d0d-a95c-43fcaf2942e2"
		date = "2019-08-05"
		modified = "2019-08-05"
		reference = "https://github.com/deadbits/yara-rules"
		source_url = "https://github.com/deadbits/yara-rules//blob/d002f7ecee23e09142a3ac3e79c84f71dda3f001/rules/KPOT_v2.yara#L1-L33"
		license_url = "N/A"
		logic_hash = "dc8cce2ae3a427f771b19b4d0e027b653ff03a7bf816303460398987535c5351"
		score = 75
		quality = 80
		tags = "WINMALWARE, INFOSTEALER, FILE"
		Description = "Attempts to detect KPOT version 2 payloads"
		Author = "Adam M. Swanda"

	strings:
		$str01 = "%s: " ascii fullword
		$str02 = " _%s_" ascii fullword
		$str03 = "0|%S|%s|%s|%s" ascii fullword
		$str04 = "%s | %02d/%04d | %s | %s | %s" ascii fullword
		$str05 = "%s | %s | %s | %s | %s | %s | %s | %d | %s" ascii fullword
		$str06 = "%s: %s | %02d/%04d | %s" ascii fullword
		$str07 = "%s = %s" ascii fullword
		$str08 = "password-check" ascii fullword
		$conf_re1 = /(SMTP|POP3|IMAP)\sServer/ wide
		$conf_re2 = /(SMTP|POP3|IMAP)\s(User|Password|Port)/ wide
		$conf01 = "*.config" ascii wide fullword
		$conf02 = "HTTP Server URL" ascii wide fullword
		$conf03 = "%s: %d" ascii wide fullword
		$conf04 = "%s\\Outlook.txt" ascii wide fullword

	condition:
		uint16( 0 ) == 0x5a4d and all of ( $str* ) and all of ( $conf_re* ) and all of ( $conf0* )
}

rule DEADBITS_APT34_PICKPOCKET : APT APT34 INFOSTEALER WINMALWARE FILE
{
	meta:
		description = "Detects the PICKPOCKET malware used by APT34, a browser credential-theft tool identified by FireEye in May 2018"
		author = "Adam Swanda"
		id = "71db5c74-4964-5c5e-a830-242bfd0a2158"
		date = "2019-07-22"
		modified = "2019-07-22"
		reference = "https://www.fireeye.com/blog/threat-research/2019/07/hard-pass-declining-apt34-invite-to-join-their-professional-network.html"
		source_url = "https://github.com/deadbits/yara-rules//blob/d002f7ecee23e09142a3ac3e79c84f71dda3f001/rules/APT34_PICKPOCKET.yara#L1-L30"
		license_url = "N/A"
		logic_hash = "7063cff3eb42c4468e01c9b214161cd306f7126f66650d99d43168730d1dc83a"
		score = 75
		quality = 80
		tags = "APT, APT34, INFOSTEALER, WINMALWARE, FILE"

	strings:
		$s1 = "SELECT * FROM moz_logins;" ascii fullword
		$s2 = "\\nss3.dll" ascii fullword
		$s3 = "SELECT * FROM logins;" ascii fullword
		$s4 = "| %Q || substr(name,%d+18) ELSE name END WHERE tbl_name=%Q COLLATE nocase AND (type='table' OR type='index' OR type='trigger');" ascii fullword
		$s5 = "\\Login Data" ascii fullword
		$s6 = "%s\\Mozilla\\Firefox\\profiles.ini" ascii fullword
		$s7 = "Login Data" ascii fullword
		$s8 = "encryptedUsernamencryptedPasswor" ascii fullword
		$s10 = "%s\\Mozilla\\Firefox\\%s" ascii fullword
		$s11 = "encryptedUsername" ascii fullword
		$s12 = "2013-12-06 14:53:30 27392118af4c38c5203a04b8013e1afdb1cebd0d" ascii fullword
		$s13 = "27392118af4c38c5203a04b8013e1afdb1cebd0d" ascii
		$s15 = "= 'table' AND name!='sqlite_sequence'   AND coalesce(rootpage,1)>0" ascii fullword
		$s18 = "[*] FireFox :" fullword wide
		$s19 = "[*] Chrome :" fullword wide
		$s20 = "username_value" ascii fullword

	condition:
		uint16( 0 ) == 0x5a4d and ( 8 of them or all of them )
}

rule DEADBITS_Avemaria_Warzone : AVEMARIA WARZONE WINMALWARE INFOSTEALER FILE
{
	meta:
		description = "No description has been set in the source file - DeadBits"
		author = "Adam Swanda"
		id = "1e03927b-d59c-5e1f-bdee-e44dfb172fad"
		date = "2019-07-18"
		modified = "2019-08-08"
		reference = "https://github.com/deadbits/yara-rules"
		source_url = "https://github.com/deadbits/yara-rules//blob/d002f7ecee23e09142a3ac3e79c84f71dda3f001/rules/avemaria_warzone.yara#L1-L32"
		license_url = "N/A"
		logic_hash = "1fe55fc8ea80616b11757193c2c74b9cf577ab661ddca4c6c64cfad63a300614"
		score = 75
		quality = 80
		tags = "AVEMARIA, WARZONE, WINMALWARE, INFOSTEALER, FILE"
		Author = "Adam M. Swanda"

	strings:
		$str1 = "cmd.exe /C ping 1.2.3.4 -n 2 -w 1000 > Nul & Del /f /q " ascii fullword
		$str2 = "MsgBox.exe" wide fullword
		$str4 = "\\System32\\cmd.exe" wide fullword
		$str6 = "Ave_Maria" wide
		$str7 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList" ascii fullword
		$str8 = "SMTP Password" wide fullword
		$str11 = "\\Google\\Chrome\\User Data\\Default\\Login Data" wide fullword
		$str12 = "\\sqlmap.dll" wide fullword
		$str14 = "SELECT * FROM logins" ascii fullword
		$str16 = "Elevation:Administrator!new" wide
		$str17 = "/n:%temp%" ascii wide

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 400KB ) and ( 5 of ( $str* ) or all of them )
}

rule DEADBITS_APT34_VALUEVAULT : APT34 INFOSTEALER WINMALWARE FILE
{
	meta:
		description = "No description has been set in the source file - DeadBits"
		author = "Adam Swanda"
		id = "11d08fe7-9080-5393-b566-6f01e3eec18b"
		date = "2020-02-02"
		modified = "2020-02-02"
		reference = "https://www.fireeye.com/blog/threat-research/2019/07/hard-pass-declining-apt34-invite-to-join-their-professional-network.html"
		source_url = "https://github.com/deadbits/yara-rules//blob/d002f7ecee23e09142a3ac3e79c84f71dda3f001/rules/APT34_VALUEVAULT.yara#L1-L63"
		license_url = "N/A"
		logic_hash = "311eed153920b29b8d9e99651fe62259d685140d12bb073001e0576811a01198"
		score = 75
		quality = 78
		tags = "APT34, INFOSTEALER, WINMALWARE, FILE"
		Description = "Information stealing malware used by APT34, written in Go."

	strings:
		$fsociety = "fsociety.dat" ascii
		$powershell = "New-Object -ComObject Shell.Application" ascii
		$gobuild = "Go build ID: " ascii
		$gopath01 = "browsers-password-cracker" ascii nocase
		$gopath02 = "main.go" ascii nocase
		$gopath03 = "mozilla.go" ascii nocase
		$gopath04 = "ie.go" ascii nocase
		$str1 = "main.Decrypt" ascii fullword
		$str3 = "main.NewBlob" ascii fullword
		$str4 = "main.CheckFileExist" ascii fullword
		$str5 = "main.CopyFileToDirectory" ascii fullword
		$str6 = "main.CrackChromeBased" ascii fullword
		$str7 = "main.CrackIE" ascii fullword
		$str8 = "main.decipherPassword" ascii fullword
		$str9 = "main.DecodeUTF16" ascii fullword
		$str10 = "main.getHashTable" ascii fullword
		$str11 = "main.getHistory" ascii fullword
		$str12 = "main.getHistoryWithPowerShell" ascii fullword
		$str13 = "main.getHistoryFromRegistery" ascii fullword
		$str14 = "main.main" ascii fullword
		$str15 = "main.DecryptAESFromBase64" ascii fullword
		$str16 = "main.DecryptAES" ascii fullword
		$str17 = "main.CrackMozila" ascii fullword
		$str18 = "main.decodeLoginData" ascii fullword
		$str19 = "main.decrypt" ascii fullword
		$str20 = "main.removePadding" ascii fullword
		$str21 = "main.getLoginData" ascii fullword
		$str22 = "main.isMasterPasswordCorrect" ascii fullword
		$str23 = "main.decrypt3DES" ascii fullword
		$str24 = "main.getKey" ascii fullword
		$str25 = "main.manageMasterPassword" ascii fullword
		$str26 = "main.getFirefoxProfiles" ascii fullword
		$str27 = "main._Cfunc_DumpVault" ascii fullword
		$str28 = "main.CrackIEandEdgeNew" ascii fullword
		$str29 = "main.init.ializers" ascii fullword
		$str30 = "main.init" ascii fullword

	condition:
		uint16( 0 ) == 0x5a4d and ( ( 10 of ( $str* ) and 3 of ( $gopath* ) ) or ( $fsociety and $powershell and $gobuild ) or ( $fsociety and 10 of ( $str* ) ) )
}

