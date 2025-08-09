rule DEADBITS_TA505_Flowerpippi : TA505 FINANCIAL BACKDOOR WINMALWARE FILE
{
	meta:
		description = "No description has been set in the source file - DeadBits"
		author = "Adam Swanda"
		id = "1cfcb25e-1de9-53ac-b272-22792844a2d0"
		date = "2019-07-18"
		modified = "2019-07-22"
		reference = "https://github.com/deadbits/yara-rules"
		source_url = "https://github.com/deadbits/yara-rules//blob/d002f7ecee23e09142a3ac3e79c84f71dda3f001/rules/TA505_FlowerPippi.yara#L1-L65"
		license_url = "N/A"
		logic_hash = "eb709915f67d7225b024da99bc84a21455f3b9d5fb4bc779bbdf6a4d3ab33489"
		score = 75
		quality = 24
		tags = "TA505, FINANCIAL, BACKDOOR, WINMALWARE, FILE"
		Author = "Adam M. Swanda"

	strings:
		$pipi = "pipipipip" ascii fullword
		$pdb0 = "Loader.pdb" ascii fullword
		$str0 = "bot.php" ascii fullword
		$str1 = "%.2X" ascii fullword
		$str2 = "sd.bat" ascii fullword
		$str3 = "open" ascii fullword
		$str4 = "domain" ascii fullword
		$str5 = "proxy" ascii fullword
		$str6 = ".exe" ascii fullword
		$str7 = "Can't launch EXE file" ascii fullword
		$str8 = "Can't load file" ascii fullword
		$str9 = ".dll" ascii fullword
		$str10 = "Dll function not found" ascii fullword
		$str11 = "Can't load Dll" ascii fullword
		$str12 = "__start_session__" ascii fullword
		$str13 = "__failed__" ascii fullword
		$str14 = "RSDSG" ascii fullword
		$str15 = "ProxyServer" ascii fullword
		$str16 = ":Repeat" ascii fullword
		$str17 = "del \"%s\"" ascii fullword
		$str18 = "if exist \"%s\" goto Repeat" ascii fullword
		$str19 = "rmdir \"%s" ascii fullword
		$str20 = "del \"%s\"" ascii fullword
		$str21 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" ascii fullword
		$str22 = "ProxyEnable" ascii fullword
		$str23 = ".00cfg" ascii fullword
		$str24 = ".idata" ascii fullword
		$api0 = "IsProcessorFeaturePresent" ascii fullword
		$api1 = "IsDebuggerPresent" ascii fullword
		$api2 = "HttpOpenRequestA" ascii fullword
		$api3 = "InternetCrackUrlA" ascii fullword
		$api4 = "InternetOpenW" ascii fullword
		$api5 = "HttpSendRequestW" ascii fullword
		$api6 = "InternetCloseHandle" ascii fullword
		$api7 = "InternetConnectA" ascii fullword
		$api8 = "InternetSetOptionW" ascii fullword
		$api9 = "InternetReadFile" ascii fullword
		$api10 = "WININET.dll" ascii fullword
		$api11 = "URLDownloadToFileA" ascii fullword

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 700KB and ( ( 10 of ( $str* ) and $pipi ) or ( 10 of ( $str* ) and $pdb0 ) or ( 10 of ( $str* ) and 5 of ( $api* ) ) or ( all of them ) )
}

rule TRELLIX_ARC_MALW_Emotet : FINANCIAL FILE
{
	meta:
		description = "Rule to detect unpacked Emotet"
		author = "Marc Rivero | McAfee ATR Team"
		id = "5bc83065-dfdd-56b7-9983-200bff35c8b1"
		date = "2020-07-21"
		modified = "2020-08-14"
		reference = "https://github.com/advanced-threat-research/Yara-Rules/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/malware/MALW_emotet.yar#L1-L32"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		logic_hash = "223e4453a6c3b56b0bc0f91147fa55ea59582d64b8a5c08f1f8d06026044065e"
		score = 75
		quality = 70
		tags = "FINANCIAL, FILE"
		rule_version = "v1"
		malware_type = "financial"
		malware_family = "Backdoor:W32/Emotet"
		actor_type = "Cybercrime"
		hash1 = "a6621c093047446e0e8ae104769af93a5a8ed147ab8865afaafbbd22adbd052d"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$pattern_0 = { 8b45fc 8be5 5d c3 55 8bec }
		$pattern_1 = { 3c39 7e13 3c61 7c04 3c7a 7e0b 3c41 }
		$pattern_2 = { 7c04 3c39 7e13 3c61 7c04 3c7a 7e0b }
		$pattern_3 = { 5f 8bc6 5e 5b 8be5 }
		$pattern_4 = { 5f 668906 5e 5b }
		$pattern_5 = { 3c30 7c04 3c39 7e13 3c61 7c04 }
		$pattern_6 = { 53 56 57 8bfa 8bf1 }
		$pattern_7 = { 3c39 7e13 3c61 7c04 3c7a 7e0b }
		$pattern_8 = { 55 8bec 83ec14 53 }
		$pattern_9 = { 5e 8be5 5d c3 55 8bec }

	condition:
		7 of them and filesize < 180224
}

rule TRELLIX_ARC_Shifu : FINANCIAL
{
	meta:
		description = "No description has been set in the source file - Trellix ARC"
		author = "McAfee Labs"
		id = "81e9ad25-1df0-5196-be8b-1d1d5d8e4387"
		date = "2025-06-01"
		modified = "2020-08-14"
		reference = "https://blogs.mcafee.com/mcafee-labs/japanese-banking-trojan-shifu-combines-malware-tools/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/malware/MALW_Shifu.yar#L1-L24"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		logic_hash = "dfa6165f8d2750330c71dedbde293780d2bb27e8eb3635e47ca770ff7b9a9d63"
		score = 75
		quality = 70
		tags = "FINANCIAL"
		malware_type = "financial"
		malware_family = "Backdoor:W32/Shifu"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$b = "RegCreateKeyA"
		$a = "CryptCreateHash"
		$c = {2F 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 22 00 22 00 20 00 22 00 25 00 73 00 22 00 20 00 25 00 73 00 00 00 00 00 63 00 6D 00 64 00 2E 00 65 00 78 00 65 00 00 00 72 00 75 00 6E}
		$d = {53 00 6E 00 64 00 56 00 6F 00 6C 00 2E 00 65 00 78 00 65}
		$e = {52 00 65 00 64 00 69 00 72 00 65 00 63 00 74 00 45 00 58 00 45}

	condition:
		all of them
}

