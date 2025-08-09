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

rule DEADBITS_Dnspionage : APT DNSCHANGER FILE
{
	meta:
		description = "No description has been set in the source file - DeadBits"
		author = "Adam Swanda"
		id = "9f740645-60dc-5376-94ad-59d8efbf1942"
		date = "2019-07-18"
		modified = "2019-07-19"
		reference = "https://github.com/deadbits/yara-rules"
		source_url = "https://github.com/deadbits/yara-rules//blob/d002f7ecee23e09142a3ac3e79c84f71dda3f001/rules/DNSpionage.yara#L1-L47"
		license_url = "N/A"
		logic_hash = "f20c71d0698d98cc58fa199c708ec7bf5cb0ec62503a20b532e752dab9aab920"
		score = 75
		quality = 78
		tags = "APT, DNSCHANGER, FILE"
		Description = "Attempts to detect DNSpionage PE samples"
		Author = "Adam M. Swanda"

	strings:
		$x00 = "/Loginnn?id=" fullword ascii
		$hdr0 = "Content-Disposition: fo" fullword ascii
		$hdr1 = "Content-Type: multi" fullword ascii
		$ua0 = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.80 Safari/537.36" fullword ascii
		$ua1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246" fullword ascii
		$str0 = "send command result error! status code is: " fullword ascii
		$str1 = "uploading command result form" fullword ascii
		$str2 = "log.txt" fullword ascii
		$str3 = "http host not found in config!" fullword ascii
		$str4 = "send command result" fullword ascii
		$str5 = "download error. status code: " fullword ascii
		$str6 = "get command with dns" fullword ascii
		$str7 = "dns host not found in config!" fullword ascii
		$str8 = "command result is: " fullword ascii
		$str9 = "command result size: " fullword ascii
		$str10 = "connection type not found in config!" fullword ascii
		$str11 = "commands: " fullword ascii
		$str12 = "command is: " fullword ascii
		$str13 = "port not found in config!" fullword ascii
		$str14 = "download filename not found! " fullword ascii
		$str15 = "base64 key not found in config!" fullword ascii
		$str16 = "download filename is: " fullword ascii
		$str17 = "config json is not valid" fullword ascii
		$str18 = "config file will be changed from server!" fullword ascii

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1000KB and ( ( 5 of ( $str* ) ) or ( $x00 and ( 1 of ( $hdr* ) ) and 1 of ( $ua* ) ) )
}

rule DRAGON_THREAT_LABS_Apt_C16_Win_Memory_Pcclient : MEMORY APT
{
	meta:
		description = "File matching the md5 above tends to only live in memory, hence the lack of MZ header check."
		author = "@dragonthreatlab"
		id = "59333cd4-b532-510e-afe5-fc3b2e96698f"
		date = "2015-01-11"
		modified = "2016-09-27"
		reference = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Dragonthreatlabs/dragonthreatlabs_index.yara#L4-L19"
		license_url = "N/A"
		hash = "ec532bbe9d0882d403473102e9724557"
		logic_hash = "e863fcbcbde61db569a34509061732371143f38734a0213dc856dc3c9188b042"
		score = 75
		quality = 80
		tags = "MEMORY, APT"

	strings:
		$str1 = "Kill You" ascii
		$str2 = "%4d-%02d-%02d %02d:%02d:%02d" ascii
		$str3 = "%4.2f  KB" ascii
		$encodefunc = {8A 08 32 CA 02 CA 88 08 40 4E 75 F4}

	condition:
		all of them
}

rule SIGNATURE_BASE_APT_KE3CHANG_TMPFILE : APT KE3CHANG TMPFILE FILE
{
	meta:
		description = "Detects Strings left in TMP Files created by K3CHANG Backdoor Ketrican"
		author = "Markus Neis, Swisscom"
		id = "84d411af-ea3d-5862-8c2f-7caca60c1b66"
		date = "2020-06-18"
		modified = "2023-12-05"
		reference = "https://app.any.run/tasks/a96f4f9d-c27d-490b-b5d3-e3be0a1c93e9/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_ke3chang.yar#L1-L21"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "75c97fe2eeb82e09f52e98d76bd529824f171da4c802b5febc1036314d8145f0"
		score = 75
		quality = 85
		tags = "APT, KE3CHANG, TMPFILE, FILE"
		hash1 = "4ef11e84d5203c0c425d1a76d4bf579883d40577c2e781cdccc2cc4c8a8d346f"

	strings:
		$pps1 = "PSParentPath             : Microsoft.PowerShell.Core\\Registry::HKEY_CURRENT_USE" fullword ascii
		$pps2 = "PSPath                   : Microsoft.PowerShell.Core\\Registry::HKEY_CURRENT_USE" fullword ascii
		$psp1 = ": Microsoft.PowerShell.Core\\Registry" ascii
		$s4 = "PSChildName  : PhishingFilter" fullword ascii
		$s1 = "DisableFirstRunCustomize : 2" fullword ascii
		$s7 = "PSChildName  : 3" fullword ascii
		$s8 = "2500         : 3" fullword ascii

	condition:
		uint16( 0 ) == 0x5350 and filesize < 1KB and $psp1 and 1 of ( $pps* ) and 1 of ( $s* )
}

rule SIGNATURE_BASE_Winnti_Dropper_X64_Libtomcrypt_Fns : TAU CN APT
{
	meta:
		description = "Designed to catch winnti 4.0 loader and hack tool x64"
		author = "CarbonBlack Threat Research"
		id = "080d837c-248f-5718-b4a2-290495cd3b38"
		date = "2019-08-26"
		modified = "2023-12-05"
		reference = "https://www.carbonblack.com/2019/09/04/cb-tau-threat-intelligence-notification-winnti-malware-4-0/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_winnti.yar#L280-L327"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "39d23f2a12a3b78182e52847e2fdb2d09386765138c37eb7f75edfc680505531"
		score = 75
		quality = 83
		tags = "TAU, CN, APT"
		rule_version = 1
		yara_version = "3.8.1"
		Confidence = "Prod"
		Priority = "High"
		TLP = "White"
		exemplar_hashes = "5ebf39d614c22e750bb8dbfa3bcb600756dd3b36929755db9b577d2b653cd2d1"
		sample_md5 = "794E127D627B3AF9015396810A35AF1C"

	strings:
		$0x140001820 = { 48 83 EC 28 83 3D ?? ?? ?? ?? 00 }
		$0x140001831 = { 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 FF }
		$0x140001842 = { B8 0B 00 E0 0C 48 83 C4 28 C3 }
		$0x14000184c = { 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 FF }
		$0x140001881 = { B8 0C 00 E0 0C 48 83 C4 28 C3 }
		$0x14000188b = { 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 FF }
		$0x1400018e4 = { B8 0D 00 E0 0C 48 83 C4 28 C3 }
		$0x1400018ee = { 48 8D 0D ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 41 B8 A0 01 00 00 E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 01 00 00 00 }
		$0x140001911 = { 33 C0 48 83 C4 28 C3 }
		$0x140001670 = { 40 55 56 57 41 55 41 56 41 57 B8 38 12 00 00 E8 ?? ?? ?? ?? 48 2B E0 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 84 24 10 12 00 00 48 8B AC 24 90 12 00 00 4C 8B B4 24 A0 12 00 00 45 33 FF 44 39 3D ?? ?? ?? ?? 49 8B F1 41 0F B7 F8 4C 8B EA 44 8B D9 66 44 89 7C 24 40 }
		$0x1400016c8 = { B8 01 00 E0 0C }
		$0x1400016d2 = { 48 89 9C 24 30 12 00 00 4D 85 C9 }
		$0x1400016ec = { 8B 9C 24 98 12 00 00 83 FB 01 }
		$0x1400016fc = { 48 8D 54 24 40 }
		$0x140001701 = { 4C 89 A4 24 28 12 00 00 E8 ?? ?? ?? ?? 44 0F B7 64 24 40 66 44 3B E7 }
		$0x140001727 = { 48 8D 54 24 40 41 8B CB E8 ?? ?? ?? ?? 0F B7 94 24 A8 12 00 00 66 39 54 24 40 }
		$0x140001750 = { 41 8B CB E8 ?? ?? ?? ?? 8B F8 83 F8 FF }
		$0x14000175f = { B8 0F 00 E0 0C }
		$0x140001764 = { 4C 8B A4 24 28 12 00 00 }
		$0x14000176c = { 48 8B 9C 24 30 12 00 00 }
		$0x140001774 = { 48 8B 8C 24 10 12 00 00 48 33 CC E8 ?? ?? ?? ?? 48 81 C4 38 12 00 00 41 5F 41 5E 41 5D 5F 5E 5D C3 }
		$0x140001795 = { 48 8D 4C 24 54 33 D2 41 B8 B4 11 00 00 44 89 7C 24 50 E8 ?? ?? ?? ?? 48 8D 44 24 50 48 89 44 24 30 45 0F B7 CC 4D 8B C5 49 8B D6 8B CF 44 89 7C 24 28 44 89 7C 24 20 E8 ?? ?? ?? ?? 85 C0 }
		$0x1400017d5 = { 4C 8D 4C 24 50 44 8B C3 48 8B D5 48 8B CE E8 ?? ?? ?? ?? 48 8D 4C 24 50 8B D8 E8 ?? ?? ?? ?? 8B C3 }
		$0x1400017fb = { B8 04 00 E0 0C }
		$0x140001805 = { B8 03 00 E0 0C }
		$0x14000180f = { B8 02 00 E0 0C }

	condition:
		all of them
}

rule SIGNATURE_BASE_Winnti_Dropper_X86_Libtomcrypt_Fns : TAU CN APT
{
	meta:
		description = "Designed to catch winnti 4.0 loader and hack tool x86"
		author = "CarbonBlack Threat Research"
		id = "48e7a3b0-55c7-5db5-855f-1614bd00afb4"
		date = "2019-08-26"
		modified = "2023-12-05"
		reference = "https://www.carbonblack.com/2019/09/04/cb-tau-threat-intelligence-notification-winnti-malware-4-0/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_winnti.yar#L329-L370"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "84bfe001758677ff3a0d60d98e29c33ad1525a0afb27b73df750b2131e298879"
		score = 75
		quality = 85
		tags = "TAU, CN, APT"
		rule_version = 1
		yara_version = "3.8.1"
		confidence = "Prod"
		oriority = "High"
		TLP = "White"
		exemplar_hashes = "0fdcbd59d6ad41dda9ae8bab8fad9d49b1357282027e333f6894c9a92d0333b3"
		sample_md5 = "da3b64ec6468a4ec56f977afb89661b1"

	strings:
		$0x401d20 = { 8B 0D ?? ?? ?? ?? 33 C0 85 C9 }
		$0x401d30 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 04 83 F8 ?? }
		$0x401d46 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 F8 ?? }
		$0x401d76 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 1C 83 F8 ?? }
		$0x401dc4 = { 56 57 B9 ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? 33 C0 F3 A5 5F C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 5E C3 }
		$0x401bd0 = { 55 8B EC B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 53 56 57 85 C0 C7 45 FC ?? ?? ?? ?? }
		$0x401bf4 = { 8B 45 14 85 C0 }
		$0x401bff = { 8B 45 18 85 C0 }
		$0x401c14 = { 8B 7D 08 8D 45 FC 50 57 E8 ?? ?? ?? ?? 8B 75 ?? 83 C4 08 66 }
		$0x401c31 = { 8B 45 0C 85 C0 }
		$0x401c3c = { 8D 4D FC 51 57 E8 ?? ?? ?? ?? 66 8B 55 FC 83 C4 08 66 3B 55 24 }
		$0x401c57 = { 8B 5D 20 85 DB }
		$0x401c62 = { 57 E8 ?? ?? ?? ?? 8B D0 83 C4 04 83 FA ?? }
		$0x401c72 = { B9 ?? ?? ?? ?? 33 C0 8D BD 48 EE FF FF C7 85 44 EE FF FF ?? ?? ?? ?? F3 AB 8B 4D 0C 8D 85 44 EE FF FF 50 6A ?? 81 E6 FF FF 00 00 6A ?? 56 51 53 52 E8 ?? ?? ?? ?? 83 C4 1C 85 C0 }
		$0x401caf = { 8B 45 1C 8B 4D 18 8D 95 44 EE FF FF 52 8B 55 14 50 51 52 E8 ?? ?? ?? ?? 8B F0 8D 85 44 EE FF FF 50 E8 ?? ?? ?? ?? 83 C4 14 8B C6 5F 5E 5B 8B E5 5D C3 }
		$0x401ce1 = { 5F 5E B8 ?? ?? ?? ?? 5B 8B E5 5D C3 }
		$0x401ced = { 5F 5E B8 ?? ?? ?? ?? 5B 8B E5 5D C3 }
		$0x401cf9 = { 5F 5E B8 ?? ?? ?? ?? 5B 8B E5 5D C3 }
		$0x401d05 = { 5F 5E B8 ?? ?? ?? ?? 5B 8B E5 5D C3 }
		$0x401d16 = { 5F 5E 5B 8B E5 5D C3 }

	condition:
		all of them
}

rule SIGNATURE_BASE_APT_Donotteam_Ytyframework : APT DONOTTEAM WINDOWS FILE
{
	meta:
		description = "Modular malware framework with similarities to EHDevel"
		author = "James E.C, ProofPoint"
		id = "6dd07019-aa5a-5966-8331-b6f6758b0652"
		date = "2018-08-03"
		modified = "2023-12-05"
		reference = "https://labs.bitdefender.com/2017/09/ehdevel-the-story-of-a-continuously-improving-advanced-threat-creation-toolkit/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_donotteam_ytyframework.yar#L3-L43"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		hash = "1e0c1b97925e1ed90562d2c68971e038d8506b354dd6c1d2bcc252d2a48bc31c"
		logic_hash = "8e2841fd4550f12d88fb451a893f1ba41f0d3c123d9c195fe97366202376ef61"
		score = 75
		quality = 83
		tags = "APT, DONOTTEAM, WINDOWS, FILE"

	strings:
		$x1 = "/football/download2/" ascii wide
		$x2 = "/football/download/" ascii wide
		$x3 = "Caption: Xp>" wide
		$x_c2 = "5.135.199.0" ascii fullword
		$a1 = "getGoogle" ascii fullword
		$a2 = "/q /noretstart" wide
		$a3 = "IsInSandbox" ascii fullword
		$a4 = "syssystemnew" ascii fullword
		$a5 = "ytyinfo" ascii fullword
		$a6 = "\\ytyboth\\yty " ascii
		$s1 = "SELECT Name FROM Win32_Processor" wide
		$s2 = "SELECT Caption FROM Win32_OperatingSystem" wide
		$s3 = "SELECT SerialNumber FROM Win32_DiskDrive" wide
		$s4 = "VM: Yes" wide fullword
		$s5 = "VM: No" wide fullword
		$s6 = "helpdll.dll" ascii fullword
		$s7 = "boothelp.exe" ascii fullword
		$s8 = "SbieDll.dll" wide fullword
		$s9 = "dbghelp.dll" wide fullword
		$s10 = "YesNoMaybe" ascii fullword
		$s11 = "saveData" ascii fullword
		$s12 = "saveLogs" ascii fullword

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 500KB and ( pe.imphash ( ) == "87775285899fa860b9963b11596a2ded" or 1 of ( $x* ) or 3 of ( $a* ) or 6 of ( $s* ) )
}

rule SIGNATURE_BASE_Explosive_EXE : APT FILE
{
	meta:
		description = "Explosion/Explosive Malware - Volatile Cedar APT"
		author = "Check Point Software Technologies Inc."
		id = "3a9fb6b2-2f19-5d70-81ed-a08c3b8b2d80"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_volatile_cedar.yar#L1-L12"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "77eb74586f5ef2878c0d283b925e6e066f704d00525303990cf5ea7988a6637d"
		score = 75
		quality = 85
		tags = "APT, FILE"

	strings:
		$DLD_S = "DLD-S:"
		$DLD_E = "DLD-E:"

	condition:
		all of them and uint16( 0 ) == 0x5A4D
}

rule SIGNATURE_BASE_CN_Portscan : APT FILE
{
	meta:
		description = "CN Port Scanner"
		author = "Florian Roth (Nextron Systems)"
		id = "fb52a89a-2270-5170-9874-9278a0177454"
		date = "2013-11-29"
		modified = "2025-04-14"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/thor-hacktools.yar#L2927-L2941"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "e1b745bd321527cee3eb203847d00c9eda4a7b1e498cb8f0ad6b588f87221759"
		score = 70
		quality = 85
		tags = "APT, FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		confidential = false

	strings:
		$s2 = "TCP 12.12.12.12"

	condition:
		uint16( 0 ) == 0x5A4D and $s2
}

rule SIGNATURE_BASE_WMI_Vbs : APT
{
	meta:
		description = "WMI Tool - APT"
		author = "Florian Roth (Nextron Systems)"
		id = "b367306a-38d8-5f4d-8f09-2bf025831f0a"
		date = "2013-11-29"
		modified = "2025-04-14"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/thor-hacktools.yar#L2943-L2957"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "94163981c1a80838d1bea1b21f713f1d8fbdac8704319d1a145f0b4f6d8ff3f6"
		score = 70
		quality = 85
		tags = "APT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		confidential = false

	strings:
		$s3 = "WScript.Echo \"   $$\\      $$\\ $$\\      $$\\ $$$$$$\\ $$$$$$$$\\ $$\\   $$\\ $$$$$$$$\\  $$$$$$"

	condition:
		all of them
}

rule SIGNATURE_BASE_APT_WEBSHELL_Tiny_Webshell : APT HAFNIUM WEBSHELL FILE
{
	meta:
		description = "Detects WebShell Injection"
		author = "Markus Neis,Swisscom"
		id = "aa2fcecc-4c8b-570d-a81a-5dfb16c04e05"
		date = "2021-03-05"
		modified = "2023-12-05"
		reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_hafnium.yar#L67-L82"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		hash = "099c8625c58b315b6c11f5baeb859f4c"
		logic_hash = "9309f9b57353b6fe292048d00794699a8637a3e6e429c562fb36c7e459003a3b"
		score = 75
		quality = 85
		tags = "APT, HAFNIUM, WEBSHELL, FILE"

	strings:
		$x1 = "<%@ Page Language=\"Jscript\" Debug=true%>"
		$s1 = "=Request.Form(\""
		$s2 = "eval("

	condition:
		filesize < 300 and all of ( $s* ) and $x1
}

rule SIGNATURE_BASE_APT_NK_Scarcruft_RUBY_Shellcode_XOR_Routine : APT
{
	meta:
		description = "Detects Ruby ShellCode XOR routine used by ScarCruft APT group"
		author = "S2WLAB_TALON_JACK2"
		id = "c393f2db-8ade-5083-9cec-f62f23056f8b"
		date = "2021-05-20"
		modified = "2023-12-05"
		reference = "https://medium.com/s2wlab/matryoshka-variant-of-rokrat-apt37-scarcruft-69774ea7bf48"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_nk_inkysquid.yar#L104-L133"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "a97041a06729d639c22a4ee272cc96555345b692fc0da8b62e898891d02b23ea"
		score = 75
		quality = 85
		tags = "APT"
		type = "APT"
		version = "0.1"

	strings:
		$hex1 = {C1 C7 0D 40 F6 C7 01 74 ?? 81 F7}
		$hex2 = {41 C1 C2 0D 41 8B C2 44 8B CA 41 8B CA 41 81 F2}

	condition:
		1 of them
}

rule SIGNATURE_BASE_APT_NK_Scarcruft_Evolved_ROKRAT : APT FILE
{
	meta:
		description = "Detects RokRAT malware used by ScarCruft APT group"
		author = "S2WLAB_TALON_JACK2"
		id = "53cabf41-0154-5372-b667-60d8a7cb9806"
		date = "2021-07-09"
		modified = "2023-12-05"
		reference = "https://medium.com/s2wlab/matryoshka-variant-of-rokrat-apt37-scarcruft-69774ea7bf48"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_nk_inkysquid.yar#L135-L179"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "01a2f410687c943d6c6e421ffacfe42f9e7b6afb82e43ba03a8d525e075a3a3c"
		score = 75
		quality = 85
		tags = "APT, FILE"
		type = "APT"
		version = "0.1"

	strings:
		$AES_IV_KEY = {
        C7 44 24 ?? 32 31 12 23
        C7 44 24 ?? 34 45 56 67
        C7 44 24 ?? 78 89 9A AB
        C7 44 24 ?? 0C BD CE DF
        C7 45 ?? 2B 7E A5 16
        C7 45 ?? 28 AE D2 A6
        C7 45 ?? AB F7 15 88
        C7 45 ?? 09 CF 4F 3C
        }
		$url_deocde = {
               80 E9 0F
               80 F1 C8
               88 48 ??
               48 83 EA 01  }

	condition:
		uint16( 0 ) == 0x5A4D and any of them
}

