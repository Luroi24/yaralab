rule VOLEXITY_Apt_Malware_Vbs_Basicstar_A : CHARMINGCYPRESS FILE MEMORY
{
	meta:
		description = "VBS backdoor which bares architectural similarity to the POWERSTAR malware family."
		author = "threatintel@volexity.com"
		id = "e790defe-2bd5-5629-8420-ce8091483589"
		date = "2024-01-04"
		modified = "2025-05-21"
		reference = "TIB-20240111"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-02-13 CharmingCypress/rules.yar#L68-L98"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "977bb42553bb6585c8d0e1e89675644720ca9abf294eccd797e20d4bca516810"
		score = 75
		quality = 80
		tags = "CHARMINGCYPRESS, FILE, MEMORY"
		hash1 = "c6f91e5585c2cbbb8d06b7f239e30b271f04393df4fb81815f6556fa4c793bb0"
		os = "win"
		os_arch = "all"
		report2 = "TIB-20240126"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10037
		version = 8

	strings:
		$s1 = "Base64Encode(EncSess)" ascii wide
		$s2 = "StrReverse(PlainSess)" ascii wide
		$s3 = "ComDecode, \"Module\"" ascii wide
		$s4 = "ComDecode, \"SetNewConfig\"" ascii wide
		$s5 = "ComDecode, \"kill\"" ascii wide
		$magic = "cmd /C start /MIN curl --ssl-no-revoke -s -d " ascii wide

	condition:
		3 of ( $s* ) or $magic
}

rule VOLEXITY_Apt_Malware_Ps1_Powerless_B : CHARMINGCYPRESS FILE MEMORY
{
	meta:
		description = "Detects POWERLESS malware."
		author = "threatintel@volexity.com"
		id = "e62703b5-32fb-5ceb-9f21-f52a4871f3d9"
		date = "2023-10-25"
		modified = "2024-01-29"
		reference = "TIB-20231027"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-02-13 CharmingCypress/rules.yar#L99-L156"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "eb9d199c1f7c2a42d711c1a44ab13526787169c18a77ce988568525baca043ef"
		score = 75
		quality = 78
		tags = "CHARMINGCYPRESS, FILE, MEMORY"
		hash1 = "62de7abb39cf4c47ff120c7d765749696a03f4fa4e3e84c08712bb0484306ae1"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 9794
		version = 5

	strings:
		$fun_1 = "function verifyClickStorke"
		$fun_2 = "function ConvertTo-SHA256"
		$fun_3 = "function Convert-Tobase" fullword
		$fun_4 = "function Convert-Frombase" fullword
		$fun_5 = "function Send-Httppacket"
		$fun_6 = "function Generat-FetchCommand"
		$fun_7 = "function Create-Fetchkey"
		$fun_8 = "function Run-Uploader"
		$fun_9 = "function Run-Shot" fullword
		$fun_10 = "function ShotThis("
		$fun_11 = "function File-Manager"
		$fun_12 = "function zip-files"
		$fun_13 = "function Run-Stealer"
		$fun_14 = "function Run-Downloader"
		$fun_15 = "function Run-Stro" fullword
		$fun_16 = "function Run-Tele" fullword
		$fun_17 = "function Run-Voice"
		$s_1 = "if($commandtype -eq \"klg\")"
		$s_2 = "$desrilizedrecievedcommand"
		$s_3 = "$getAsyncKeyProto = @"
		$s_4 = "$Global:BotId ="
		$s_5 = "$targetCLSID = (Get-ScheduledTask | Where-Object TaskName -eq"
		$s_6 = "$burl = \"$Global:HostAddress/"
		$s_7 = "$hashString = [System.BitConverter]::ToString($hash).Replace('-','').ToLower()"
		$s_8 = "$Global:UID = ((gwmi win32_computersystemproduct).uuid -replace '[^0-9a-z]').substring("
		$s_9 = "$rawpacket = \"{`\"MId`\":`\"$Global:MachineID`\",`\"BotId`\":`\"$basebotid`\"}\""
		$s_12 = "Runned Without any Error"
		$s_13 = "$commandresponse = (Invoke-Expression $instruction -ErrorAction Stop) | Out-String"
		$s_14 = "Operation started successfuly"
		$s_15 = "$t_path = (Get-WmiObject Win32_Process -Filter \"name = '$process'\" | Select-Object CommandLine).CommandLine"
		$s_16 = "?{ $_.DisplayName -match \"Telegram Desktop\" } | %{$app_path += $_.InstallLocation }"
		$s_17 = "$chlids = get-ChildItem $t -Recurse -Exclude \"$t\\tdata\\user_data\""
		$s_18 = "if($FirsttimeFlag -eq $True)"
		$s_19 = "Update-Conf -interval $inter -url $url -next_url $next -conf_path $conf_path -key $config_key"

	condition:
		3 of ( $fun_* ) or any of ( $s_* )
}

rule VOLEXITY_Apt_Malware_Macos_Vpnclient_Cc_Oct23 : CHARMINGCYPRESS FILE MEMORY
{
	meta:
		description = "Detection for fake macOS VPN client used by CharmingCypress."
		author = "threatintel@volexity.com"
		id = "e0957936-dc6e-5de6-bb23-d0ef61655029"
		date = "2023-10-17"
		modified = "2023-10-27"
		reference = "TIB-20231027"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-02-13 CharmingCypress/rules.yar#L245-L271"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "da5e9be752648b072a9aaeed884b8e1729a14841e33ed6633a0aaae1f11bd139"
		score = 75
		quality = 80
		tags = "CHARMINGCYPRESS, FILE, MEMORY"
		hash1 = "11f0e38d9cf6e78f32fb2d3376badd47189b5c4456937cf382b8a574dc0d262d"
		os = "darwin,linux"
		os_arch = "all"
		parent_hash = "31ca565dcbf77fec474b6dea07101f4dd6e70c1f58398eff65e2decab53a6f33"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 9770
		version = 3

	strings:
		$s1 = "networksetup -setsocksfirewallproxystate wi-fi off" ascii
		$s2 = "networksetup -setsocksfirewallproxy wi-fi ___serverAdd___ ___portNum___; networksetup -setsocksfirewallproxystate wi-fi on" ascii
		$s3 = "New file imported successfully." ascii
		$s4 = "Error in importing the File." ascii

	condition:
		2 of ( $s* )
}

rule VOLEXITY_Apt_Malware_Charmingcypress_Openvpn_Configuration : CHARMINGCYPRESS FILE
{
	meta:
		description = "Detection for a .ovpn file used in a malicious VPN client on victim machines by CharmingCypress."
		author = "threatintel@volexity.com"
		id = "f39b2d7c-f0c5-5623-a114-02ba32469e59"
		date = "2023-10-17"
		modified = "2023-10-27"
		reference = "TIB-20231027"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-02-13 CharmingCypress/rules.yar#L272-L297"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "f4c5f13ac75504b14def9c37d3a41c6eea4c45845d4b54c50030b1f00691e4bf"
		score = 75
		quality = 80
		tags = "CHARMINGCYPRESS, FILE"
		hash1 = "d6d043973d8843a82033368c785c362f51395b1a1d475fa4705aff3526e15268"
		parent_hash = "31ca565dcbf77fec474b6dea07101f4dd6e70c1f58398eff65e2decab53a6f33"
		os = "all"
		os_arch = "all"
		scan_context = "file"
		severity = "high"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 9769
		version = 3

	strings:
		$remote = "remote-cert-tls server" ascii
		$ip = "Ip: "
		$tls = "<tls_auth>"

	condition:
		all of them
}

rule VOLEXITY_Apt_Delivery_Win_Charming_Openvpn_Client : CHARMINGCYPRESS FILE
{
	meta:
		description = "Detects a fake OpenVPN client developed by CharmingCypress."
		author = "threatintel@volexity.com"
		id = "b69fdd72-4a55-5e83-b754-401fe9339007"
		date = "2023-10-17"
		modified = "2023-10-27"
		reference = "TIB-20231027"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-02-13 CharmingCypress/rules.yar#L298-L322"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "02596a62cb1ba17ecabef0ae93f434e4774b00422a6da2106a2bc4c59d2f8077"
		score = 75
		quality = 80
		tags = "CHARMINGCYPRESS, FILE"
		hash1 = "2d99755d5cd25f857d6d3aa15631b69f570d20f95c6743574f3d3e3e8765f33c"
		os = "win"
		os_arch = "all"
		scan_context = "file"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 9768
		version = 2

	strings:
		$s1 = "DONE!"
		$s2 = "AppCore.dll"
		$s3 = "ultralight@@"

	condition:
		all of ( $s* )
}

