rule VOLEXITY_Malware_Win_Backwash_Cpp : WHEELEDASH FILE MEMORY
{
	meta:
		description = "CPP loader for the Backwash malware."
		author = "threatintel@volexity.com"
		id = "8a1c4ff1-1827-5e6f-b838-664d8c3be840"
		date = "2021-11-17"
		modified = "2023-11-13"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-12-06 - XEGroup/indicators/yara.yar#L3-L26"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "c8ed2d3103aa85363acd7f5573aeb936a5ab5a3bacbcf1f04e6b298299f24dae"
		score = 75
		quality = 80
		tags = "WHEELEDASH, FILE, MEMORY"
		hash1 = "0cf93de64aa4dba6cec99aa5989fc9c5049bc46ca5f3cb327b49d62f3646a852"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6147
		version = 2

	strings:
		$s1 = "cor1dbg.dll" wide
		$s2 = "XEReverseShell.exe" wide
		$s3 = "XOJUMAN=" wide

	condition:
		2 of them
}

rule VOLEXITY_Malware_Win_Iis_Shellsave : WHEELEDASH FILE MEMORY
{
	meta:
		description = "Detects an AutoIT backdoor designed to run on IIS servers and to install a webshell."
		author = "threatintel@volexity.com"
		id = "a89defa5-4b22-5650-a0c0-f4b3cf3377a7"
		date = "2021-11-17"
		modified = "2023-08-17"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-12-06 - XEGroup/indicators/yara.yar#L27-L49"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "f34d6f4ecaa4cde5965f6b0deac55c7133a2be96f5c466f34775be6e7f730493"
		score = 75
		quality = 80
		tags = "WHEELEDASH, FILE, MEMORY"
		hash1 = "21683e02e11c166d0cf616ff9a1a4405598db7f4adfc87b205082ae94f83c742"
		scan_context = "file,memory"
		severity = "high"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6146
		version = 4

	strings:
		$s1 = "getdownloadshell" ascii
		$s2 = "deleteisme" ascii
		$s3 = "sitepapplication" ascii
		$s4 = "getapplicationpool" ascii

	condition:
		all of them
}

rule VOLEXITY_Malware_Win_Backwash_Iis_Scout : WHEELEDASH FILE MEMORY
{
	meta:
		description = "Simple backdoor which collects information about the IIS server it is installed on. It appears to the attacker refers to this components as 'XValidate' - i.e. to validate infected machines."
		author = "threatintel@volexity.com"
		id = "1f768b39-21a0-574d-9043-5104540003f7"
		date = "2021-11-17"
		modified = "2023-08-17"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-12-06 - XEGroup/indicators/yara.yar#L50-L78"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "18c4e338905ff299d75534006037e63a8f9b191f062cc97b0592245518015f88"
		score = 75
		quality = 80
		tags = "WHEELEDASH, FILE, MEMORY"
		hash1 = "6f44a9c13459533a1f3e0b0e698820611a18113c851f763797090b8be64fd9d5"
		scan_context = "file,memory"
		severity = "high"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6145
		version = 3

	strings:
		$s1 = "SOAPRequest" ascii
		$s2 = "requestServer" ascii
		$s3 = "getFiles" ascii
		$s4 = "APP_POOL_CONFIG" wide
		$s5 = "<virtualDirectory" wide
		$s6 = "stringinstr" ascii
		$s7 = "504f5354" wide
		$s8 = "XValidate" ascii
		$s9 = "XEReverseShell" ascii
		$s10 = "XERsvData" ascii

	condition:
		6 of them
}

rule VOLEXITY_Malware_Js_Xeskimmer : WHEELEDASH FILE
{
	meta:
		description = "Detects JScript code using in skimming credit card details."
		author = "threatintel@volexity.com"
		id = "2c0911cf-a679-5d4e-baad-777745a28e27"
		date = "2021-11-17"
		modified = "2023-11-14"
		reference = "https://github.com/MBThreatIntel/skimmers/blob/master/null_gif_skimmer.js"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-12-06 - XEGroup/indicators/yara.yar#L79-L114"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "cc46e9fab5f408fde13c3897d378a1a2e4acb448f40ca4935c19024ebdc252d7"
		score = 75
		quality = 80
		tags = "WHEELEDASH, FILE"
		hash1 = "92f9593cfa0a28951cae36755d54de63631377f1b954a4cb0474fa0b6193c537"
		os = "win"
		os_arch = "all"
		scan_context = "file"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6144
		version = 4

	strings:
		$s1 = ".match(/^([3456]\\d{14,15})$/g" ascii
		$s2 = "^(p(wd|ass(code|wd|word)))" ascii
		$b1 = "c('686569676874')" ascii
		$b2 = "c('7769647468')" ascii
		$c1 = "('696D67')" ascii
		$c2 = "('737263')" ascii
		$magic = "d=c.charCodeAt(b),a+=d.toString(16);"

	condition:
		all of ( $s* ) or all of ( $b* ) or all of ( $c* ) or $magic
}

rule VOLEXITY_Malware_Win_Backwash_Iis : WHEELEDASH FILE MEMORY
{
	meta:
		description = "Variant of the BACKWASH malware family with IIS worm functionality."
		author = "threatintel@volexity.com"
		id = "08a86a58-32af-5c82-90d2-d6603dae8d63"
		date = "2020-09-04"
		modified = "2023-08-17"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-12-06 - XEGroup/indicators/yara.yar#L181-L208"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		hash = "98e39573a3d355d7fdf3439d9418fdbf4e42c2e03051b5313d5c84f3df485627"
		logic_hash = "95a7f9e0afb031b49cd0da66b5a887d26ad2e06cce625bc45739b4a80e96ce9c"
		score = 75
		quality = 80
		tags = "WHEELEDASH, FILE, MEMORY"
		scan_context = "file,memory"
		severity = "high"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 231
		version = 6

	strings:
		$a1 = "GetShell" ascii
		$a2 = "smallShell" ascii
		$a3 = "createSmallShell" ascii
		$a4 = "getSites" ascii
		$a5 = "getFiles " ascii
		$b1 = "action=saveshell&domain=" ascii wide
		$b2 = "&shell=backsession.aspx" ascii wide

	condition:
		all of ( $a* ) or any of ( $b* )
}

