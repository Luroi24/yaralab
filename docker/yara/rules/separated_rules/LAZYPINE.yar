rule VOLEXITY_Apt_Malware_Win_Applejeus_Oct22 : LAZYPINE FILE MEMORY
{
	meta:
		description = "Detects AppleJeus DLL samples."
		author = "threatintel@volexity.com"
		id = "f88e2253-e296-57d8-a627-6cb4ccff7a92"
		date = "2022-11-03"
		modified = "2025-05-21"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2022/2022-12-01 Buyer Beware - Fake Cryptocurrency Applications Serving as Front for AppleJeus Malware/yara.yar#L1-L22"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "46f3325a7e8e33896862b1971f561f4871670842aecd46bcc7a5a1af869ecdc4"
		score = 75
		quality = 80
		tags = "LAZYPINE, FILE, MEMORY"
		hash1 = "82e67114d632795edf29ce1d50a4c1c444846d9e16cd121ce26e63c8dc4a1629"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 8495
		version = 3

	strings:
		$s1 = "HijackingLib.dll" ascii

	condition:
		$s1
}

rule VOLEXITY_Apt_Malware_Win_Applejeus_B_Oct22 : LAZYPINE FILE MEMORY
{
	meta:
		description = "Detects unpacked AppleJeus samples."
		author = "threatintel@volexity.com"
		id = "8586dc64-225b-5f28-a6d6-b9b6e8f1c815"
		date = "2022-11-03"
		modified = "2025-05-21"
		reference = "https://www.volexity.com/blog/2022/12/01/buyer-beware-fake-cryptocurrency-applications-serving-as-front-for-applejeus-malware/"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2022/2022-12-01 Buyer Beware - Fake Cryptocurrency Applications Serving as Front for AppleJeus Malware/yara.yar#L24-L54"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "76f3c9692ea96d3cadbbcad03477ab6c53445935352cb215152b9b5483666d43"
		score = 75
		quality = 80
		tags = "LAZYPINE, FILE, MEMORY"
		hash1 = "9352625b3e6a3c998e328e11ad43efb5602fe669aed9c9388af5f55fadfedc78"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 8497
		version = 5

	strings:
		$key1 = "AppX7y4nbzq37zn4ks9k7amqjywdat7d"
		$key2 = "Gd2n5frvG2eZ1KOe"
		$str1 = "Windows %d(%d)-%s"
		$str2 = "&act=check"

	condition:
		( any of ( $key* ) and 1 of ( $str* ) ) or all of ( $str* )
}

rule VOLEXITY_Apt_Malware_Win_Applejeus_C_Oct22 : LAZYPINE MEMORY
{
	meta:
		description = "Detects unpacked AppleJeus samples."
		author = "threatintel@volexity.com"
		id = "c9cbddde-220c-5e26-8760-85c29b98bfeb"
		date = "2022-11-03"
		modified = "2023-09-28"
		reference = "https://www.volexity.com/blog/2022/12/01/buyer-beware-fake-cryptocurrency-applications-serving-as-front-for-applejeus-malware/"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2022/2022-12-01 Buyer Beware - Fake Cryptocurrency Applications Serving as Front for AppleJeus Malware/yara.yar#L57-L84"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "a9e635d9353c8e5c4992beba79299fb889a7a3d5bc3eaf191f8bb7f51258a6c6"
		score = 75
		quality = 80
		tags = "LAZYPINE, MEMORY"
		hash1 = "a0db8f8f13a27df1eacbc01505f311f6b14cf9b84fbc7e84cb764a13f001dbbb"
		os = "win"
		os_arch = "all"
		scan_context = "memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 8519
		version = 3

	strings:
		$str1 = "%sd.e%sc \"%s > %s 2>&1\"" wide
		$str2 = "tuid"
		$str4 = "payload"
		$str5 = "fconn"
		$str6 = "Mozilla_%lu"

	condition:
		5 of ( $str* )
}

rule VOLEXITY_Apt_Malware_Win_Applejeus_D_Oct22 : LAZYPINE FILE MEMORY
{
	meta:
		description = "Detected AppleJeus unpacked samples."
		author = "threatintel@volexity.com"
		id = "80d2821b-a437-573e-9e9d-bf79f9422cc9"
		date = "2022-11-10"
		modified = "2025-05-21"
		reference = "https://www.volexity.com/blog/2022/12/01/buyer-beware-fake-cryptocurrency-applications-serving-as-front-for-applejeus-malware/"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2022/2022-12-01 Buyer Beware - Fake Cryptocurrency Applications Serving as Front for AppleJeus Malware/yara.yar#L87-L112"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "23c0642e5be15a75a39d089cd52f2f14d633f7af6889140b9ec6e53c5c023974"
		score = 75
		quality = 80
		tags = "LAZYPINE, FILE, MEMORY"
		hash1 = "a241b6611afba8bb1de69044115483adb74f66ab4a80f7423e13c652422cb379"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 8534
		version = 3

	strings:
		$reg = "Software\\Bitcoin\\Bitcoin-Qt"
		$pattern = "%s=%d&%s=%s&%s=%s&%s=%d"
		$exec = " \"%s\", RaitingSetupUI "
		$http = "Accept: */*" wide

	condition:
		all of them
}

rule VOLEXITY_Apt_Delivery_Macro_Lazypine_Jeus_B : LAZYPINE FILE
{
	meta:
		description = "Detects macros used by the LazyPine threat actor to distribute AppleJeus."
		author = "threatintel@volexity.com"
		id = "ac4d4e82-e29f-5134-999d-b8dcef59d285"
		date = "2022-11-03"
		modified = "2025-05-21"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2022/2022-12-01 Buyer Beware - Fake Cryptocurrency Applications Serving as Front for AppleJeus Malware/yara.yar#L114-L139"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "e55199e6ad26894f98e930cd4716127ee868872d08ada1c44675e4db1ec27894"
		score = 75
		quality = 80
		tags = "LAZYPINE, FILE"
		hash1 = "17e6189c19dedea678969e042c64de2a51dd9fba69ff521571d63fd92e48601b"
		os = "win"
		os_arch = "all"
		scan_context = "file"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 8493
		version = 3

	strings:
		$a1 = ", vbDirectory) = \"\" Then" ascii
		$a2 = ".Caption & " ascii
		$a3 = ".nodeTypedValue" ascii
		$a4 = ".Application.Visible = False" ascii
		$a5 = " MkDir (" ascii

	condition:
		all of ( $a* )
}

rule VOLEXITY_Apt_Delivery_Office_Macro_Lazypine_Jeus : LAZYPINE FILE
{
	meta:
		description = "Detects malicious documents used by LazyPine in a campaign dropping the AppleJeus malware."
		author = "threatintel@volexity.com"
		id = "f9a92f47-aa1d-56ea-ac59-47cc559f379f"
		date = "2022-11-02"
		modified = "2025-05-21"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2022/2022-12-01 Buyer Beware - Fake Cryptocurrency Applications Serving as Front for AppleJeus Malware/yara.yar#L141-L165"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "54d5396b889a45d81122301eadf77f73135937fbe9647ad60491ac7856faf5ad"
		score = 75
		quality = 80
		tags = "LAZYPINE, FILE"
		hash1 = "17e6189c19dedea678969e042c64de2a51dd9fba69ff521571d63fd92e48601b"
		os = "all"
		os_arch = "all"
		scan_context = "file"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 8490
		version = 7

	strings:
		$s1 = "0M8R4K" ascii
		$s2 = "bin.base64" ascii
		$s3 = "dragon" ascii
		$s4 = "Workbook_Open" ascii

	condition:
		all of ( $s* )
}

