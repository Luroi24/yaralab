rule TRELLIX_ARC_Dropper_Demekaf_Pdb : DROPPER FILE
{
	meta:
		description = "Rule to detect Demekaf dropper based on PDB"
		author = "Marc Rivero | McAfee ATR Team"
		id = "b49f42c1-d737-5afa-b547-7268e4cde360"
		date = "2011-03-26"
		modified = "2020-08-14"
		reference = "https://v.virscan.org/Trojan-Dropper.Win32.Demekaf.html"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/malware/MALW_dropper_demekaf_pdb.yar#L1-L25"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		hash = "fab320fceb38ba2c5398debdc828a413a41672ce9745afc0d348a0e96c5de56e"
		logic_hash = "89c0c1da1f8997b12a446c93bbde200e62fac9cab2a9a17147b268d435bdc3b6"
		score = 75
		quality = 70
		tags = "DROPPER, FILE"
		rule_version = "v1"
		malware_type = "dropper"
		malware_family = "Dropper:W32/Demekaf"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$pdb = "\\vc\\res\\fake1.19-jpg\\fake\\Release\\fake.pdb"

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 150KB and any of them
}

rule SECUINFRA_DROPPER_Njrat_VBS : VBS NJRAT DROPPER FILE
{
	meta:
		description = "No description has been set in the source file - SecuInfra"
		author = "SECUINFRA Falcon Team"
		id = "5296667a-2932-597e-8f49-b7fa755cb387"
		date = "2022-02-27"
		modified = "2022-02-27"
		reference = "https://bazaar.abuse.ch/sample/daea0b5dfcc3e20b75292df60fe5f0e16a40735254485ff6cc7884697a007c0d/"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Dropper/njrat.yar#L2-L23"
		license_url = "N/A"
		logic_hash = "7640be8850992ee7f05e85e1f781b4c63ccf958cf62da8deacfe9bb116627ceb"
		score = 75
		quality = 70
		tags = "VBS, NJRAT, DROPPER, FILE"

	strings:
		$a1 = "[System.Convert]::FromBase64String( $Codigo.replace(" wide
		$a2 = "WDySjnçIJwGnYGadvbOQBvKzlNzWDDgUqgGlLKÇQvvkKPNjaUIdApxgqHTfDLUkfOKsXOKçDcQtltyXDXhNNbGNNPACgAzWRtuLt" wide
		$b1 = "CreateObject(\"WScript.Shell\")" wide
		$b2 = "\"R\" + \"e\" + \"p\" + \"l\" + \"a\" + \"c\" + \"e\"" wide
		$b3 = "BBBB\" + \"BBBBBBB\" + \"BBBBBBB\" + \"BBBBBBBB" wide
		$b4 = "& DGRP & NvWt & DGRP &" wide
		$b5 = "= ogidoC$" wide

	condition:
		filesize < 300KB and ( ( 1 of ( $a* ) ) or ( 2 of ( $b* ) ) )
}

rule SECUINFRA_DROPPER_Unknown_1 : DROPPER HTA FILE
{
	meta:
		description = "Detects unknown HTA Dropper"
		author = "SECUINFRA Falcon Team"
		id = "70c06b9d-8474-5b6e-bd9c-d45a25585ee9"
		date = "2022-10-02"
		modified = "2022-02-19"
		reference = "https://bazaar.abuse.ch/sample/c2bf8931028e0a18eeb8f1a958ade0ab9d64a00c16f72c1a3459f160f0761348/"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Dropper/unknown.yar#L1-L21"
		license_url = "N/A"
		hash = "1749f4127bba3f7204710286b1252e14"
		logic_hash = "d02874514bcb6c3603d1bfee702ec9e18c15153bc14a55ca8d637308c3f35a75"
		score = 75
		quality = 43
		tags = "DROPPER, HTA, FILE"

	strings:
		$a1 = "<script type=\"text/vbscript\" LANGUAGE=\"VBScript\" >"
		$a2 = "Function XmlTime(t)"
		$a3 = "C:\\ProgramData\\"
		$a4 = "wscript.exe"
		$a5 = "Array" nocase
		$b = "chr" nocase

	condition:
		filesize < 70KB and all of ( $a* ) and #b > 7
}

rule SECUINFRA_DROPPER_Vjw0Rm_Stage_1 : JAVASCRIPT DROPPER VJW0RM FILE
{
	meta:
		description = "No description has been set in the source file - SecuInfra"
		author = "SECUINFRA Falcon Team"
		id = "a07f80e4-56c3-5b75-be64-648bc1fde964"
		date = "2022-02-19"
		modified = "2022-02-27"
		reference = "https://bazaar.abuse.ch/browse.php?search=tag%3AVjw0rm"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Dropper/Vjw0rm.yar#L2-L19"
		license_url = "N/A"
		logic_hash = "e5cc23431239e8a650369729050809cf6fe2acc58941086f79ce004b4f506eed"
		score = 75
		quality = 20
		tags = "JAVASCRIPT, DROPPER, VJW0RM, FILE"
		version = "0.1"

	strings:
		$a1 = "$$$"
		$a2 = "microsoft.xmldom"
		$a3 = "eval"
		$a4 = "join(\"\")"

	condition:
		( uint16( 0 ) == 0x7566 or uint16( 0 ) == 0x6176 or uint16( 0 ) == 0x0a0d or uint16( 0 ) == 0x660a ) and filesize < 60KB and all of ( $a* )
}

rule DRAGON_THREAT_LABS_Apt_C16_Win32_Dropper : DROPPER FILE
{
	meta:
		description = "APT malware used to drop PcClient RAT"
		author = "@dragonthreatlab"
		id = "a1546f02-f01b-50ba-b4d9-9676e52dc4c1"
		date = "2015-01-11"
		modified = "2016-09-27"
		reference = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Dragonthreatlabs/dragonthreatlabs_index.yara#L35-L52"
		license_url = "N/A"
		hash = "ad17eff26994df824be36db246c8fb6a"
		logic_hash = "bb29bcf5e62cb1a55d7f0cb87b53bace26b99f858513dc4e544d531f70f54281"
		score = 75
		quality = 28
		tags = "DROPPER, FILE"

	strings:
		$mz = {4D 5A}
		$str1 = "clbcaiq.dll" ascii
		$str2 = "profapi_104" ascii
		$str3 = "/ShowWU" ascii
		$str4 = "Software\\Microsoft\\Windows\\CurrentVersion\\" ascii
		$str5 = {8A 08 2A CA 32 CA 88 08 40 4E 75 F4 5E}

	condition:
		$mz at 0 and all of ( $str* )
}

rule DRAGON_THREAT_LABS_Apt_C16_Win64_Dropper : DROPPER FILE
{
	meta:
		description = "APT malware used to drop PcClient RAT"
		author = "@dragonthreatlab"
		id = "dbd1a16c-52a5-5b07-b34f-7eb7b78c1eab"
		date = "2015-01-11"
		modified = "2016-09-27"
		reference = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Dragonthreatlabs/dragonthreatlabs_index.yara#L87-L104"
		license_url = "N/A"
		logic_hash = "df905711eca68c698ad6340e88ae99fdcae918c86ec2b7c26b62eead54fef892"
		score = 75
		quality = 28
		tags = "DROPPER, FILE"

	strings:
		$mz = { 4D 5A }
		$str1 = "clbcaiq.dll" ascii
		$str2 = "profapi_104" ascii
		$str3 = "\\Microsoft\\wuauclt\\wuauclt.dat" ascii
		$str4 = { 0F B6 0A 48 FF C2 80 E9 03 80 F1 03 49 FF C8 88 4A FF 75 EC }

	condition:
		$mz at 0 and all of ( $str* )
}

