rule TRELLIX_ARC_Ransom_Babuk : RANSOM T1027 T1083 T1057 T1082 T1129 T1490 T1543_003 FILE
{
	meta:
		description = "Rule to detect Babuk Locker"
		author = "TS @ McAfee ATR"
		id = "7c0a3b4e-90aa-5442-aa5e-1a7fcae9bec8"
		date = "2021-01-19"
		modified = "2021-02-24"
		reference = "https://github.com/advanced-threat-research/Yara-Rules/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/ransomware/RANSOM_BabukLocker_Jan2021.yar#L1-L25"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		hash = "e10713a4a5f635767dcd54d609bed977"
		logic_hash = "123cebd1c2e66f3e91ee235cb9288df63dfaeba02e6df45f896cb50f38851a8f"
		score = 75
		quality = 70
		tags = "RANSOM, T1027, T1083, T1057, T1082, T1129, T1490, T1543.003, FILE"
		rule_version = "v2"
		malware_family = "Ransom:Win/Babuk"
		malware_type = "Ransom"
		mitre_attack = "T1027, T1083, T1057, T1082, T1129, T1490, T1543.003"

	strings:
		$s1 = {005C0048006F007700200054006F00200052006500730074006F0072006500200059006F00750072002000460069006C00650073002E007400780074}
		$s2 = "delete shadows /all /quiet" fullword wide
		$pattern1 = {006D656D74617300006D65706F63730000736F70686F730000766565616D0000006261636B7570000047785673730000004778426C7200000047784657440000004778435644000000477843494D67720044656657617463680000000063634576744D67720000000063635365744D677200000000536176526F616D005254567363616E0051424643536572766963650051424944505365727669636500000000496E747569742E517569636B426F6F6B732E46435300}
		$pattern2 = {004163725363683253766300004163726F6E69734167656E74000000004341534144324457656253766300000043414152435570646174655376630000730071}
		$pattern3 = {FFB0154000C78584FDFFFFB8154000C78588FDFFFFC0154000C7858CFDFFFFC8154000C78590FDFFFFD0154000C78594FDFFFFD8154000C78598FDFFFFE0154000C7859CFDFFFFE8154000C785A0FDFFFFF0154000C785A4FDFFFFF8154000C785A8FDFFFF00164000C785ACFDFFFF08164000C785B0FDFFFF10164000C785B4FDFFFF18164000C785B8FDFFFF20164000C785BCFDFFFF28164000C785C0FDFFFF30164000C785C4FDFFFF38164000C785C8FDFFFF40164000C785CCFDFFFF48164000C785D0FDFFFF50164000C785D4FDFFFF581640}
		$pattern4 = {400010104000181040002010400028104000301040003810400040104000481040005010400058104000601040006C10400078104000841040008C10400094104000A0104000B0104000C8104000DC104000E8104000F01040000011400008114000181140002411400038114000501140005C11400064114000741140008C114000A8114000C0114000E0114000F4114000101240002812400034124000441240005412400064124000741240008C124000A0124000B8124000D4124000EC1240000C1340002813400054134000741340008C134000A4134000C4134000E8134000FC134000141440003C144000501440006C144000881440009C144000B4144000CC144000E8144000FC144000141540003415400048154000601540007815}

	condition:
		filesize >= 15KB and filesize <= 90KB and 1 of ( $s* ) and 3 of ( $pattern* )
}

rule TRELLIX_ARC_RANSOM_Babuk_Packed_Feb2021 : RANSOM T1027_005 T1027 T1083 T1082 T1059 T1129 FILE
{
	meta:
		description = "Rule to detect Babuk Locker packed"
		author = "McAfee ATR"
		id = "f5f3a3a6-2531-56c4-9153-b698c7bdc3d3"
		date = "2021-02-19"
		modified = "2021-02-24"
		reference = "https://github.com/advanced-threat-research/Yara-Rules/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/ransomware/RANSOM_Babuk_Packed_Feb2021.yar#L1-L30"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		hash = "48e0f7d87fe74a2b61c74f0d32e6a8a5"
		logic_hash = "f3312b9c9147e9f892dbfb329cb95d3ee3ae67eefeec2d089b8c89fd26531953"
		score = 75
		quality = 70
		tags = "RANSOM, T1027.005, T1027, T1083, T1082, T1059, T1129, FILE"
		rule_version = "v1"
		malware_family = "Ransom:Win/Babuk"
		malware_type = "Ransom"
		mitre_attack = "T1027.005, T1027, T1083, T1082, T1059, T1129"

	strings:
		$first_stage1 = { 81 ec 30 04 00 00 68 6c 49 43 00 ff 15 74 20 43 00 a3 60 4e f8 02 b8 db d9 2b 00 ba c5 62 8e 76 b9 35 11 5f 39 eb 09 8d a4 24 00 00 00 00 8b ff 89 14 24 89 4c 24 04 81 04 24 25 10 a3 3b 81 04 24 cf e0 fb 07 81 04 24 35 26 9f 42 81 04 24 65 2b 39 06 81 04 24 3c 37 33 5b 81 44 24 04 48 4f c2 5d 83 e8 01 c7 05 54 4e f8 02 00 00 00 00 75 bf 8b 0d 54 aa 43 00 53 8b 1d 58 20 43 00 55 8b 2d 60 20 43 00 56 81 c1 01 24 0a 00 57 8b 3d 50 20 43 00 89 0d 64 4e f8 02 33 f6 eb 03 8d 49 00 81 f9 fc 00 00 00 75 08 6a 00 ff 15 40 20 43 00 6a 00 ff d7 8b 0d 64 4e f8 02 81 f9 7c 0e 00 00 75 19 6a 00 ff d3 6a 00 6a 00 8d 44 24 48 50 6a 00 6a 00 ff d5 8b 0d 64 4e f8 02 81 fe e5 84 c1 09 7e 0a 81 7c 24 2c 0f 11 00 00 75 12 46 8b c6 99 83 fa 14 7c aa 7f 07 3d 30 c1 cf c7 72 a1 51 6a 00 ff 15 2c 20 43 00 8b 0d 08 a4 43 00 33 f6 a3 f4 31 f8 02 89 0d f4 07 fb 02 39 35 64 4e f8 02 76 10 8b c6 e8 56 e4 ff ff 46 3b 35 64 4e f8 02 72 f0 8b 35 80 20 43 00 bf f0 72 e9 00 8b ff 81 3d 64 4e f8 02 4d 09 00 00 75 04 6a 00 ff d6 83 ef 01 75 eb e8 d6 e3 ff ff e8 11 fe ff ff e8 0c e4 ff ff 5f 5e 5d 33 c0 5b 81 c4 30 04 00 00 c3 }
		$first_stage2 = {81ec3??4????68????????ff??????????a3????????b8????????ba????????b9????????eb??891424894c240481????????????81????????????81????????????81????????????81????????????81??????????????83e801c7??????????????????75??8b??????????538b??????????558b??????????5681??????????578b??????????89??????????33f6eb??81??????????75??6a??ff??????????6a??ffd78b??????????81??????????75??6a??ffd36a??6a??8d442448506a??6a??ffd58b??????????81??????????7e??817c242c0f11????75??468bc69983????7c??7f??3d????????72??516a??ff??????????8b??????????33f6a3????????89??????????39??????????76??8bc6e8????????463b??????????72??8b??????????bf????????8bff81??????????????????75??6a??ffd683ef0175??e8????????e8????????e8????????5f5e5d33c05b81c43??4????c3}
		$first_stage3 = {81ec3??4????68????????ff??????????a3????????b8????????ba????????b9????????[2-6]891424894c240481????????????81????????????81????????????81????????????81????????????81??????????????83e801c7??????????????????[2-6]8b??????????538b??????????558b??????????5681??????????578b??????????89??????????33f6[2-6]81??????????[2-6]6a??ff??????????6a??ffd78b??????????81??????????[2-6]6a??ffd36a??6a??8d442448506a??6a??ffd58b??????????81??????????[2-6]817c242c0f11????[2-6]468bc69983????[2-6][2-6]3d????????[2-6]516a??ff??????????8b??????????33f6a3????????89??????????39??????????[2-6]8bc6e8????????463b??????????[2-6]8b??????????bf????????8bff81??????????????????[2-6]6a??ffd683ef01[2-6]e8????????e8????????e8????????5f5e5d33c05b81c43??4????c3}
		$first_stage4 = { 81 EC 30 04 00 00 68 6C 49 43 00 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? B8 DB D9 2B 00 BA C5 62 8E 76 B9 35 11 5F 39 EB ?? 8D A4 24 ?? ?? ?? ?? 8B FF 89 14 24 89 4C 24 ?? 81 04 24 25 10 A3 3B 81 04 24 CF E0 FB 07 81 04 24 35 26 9F 42 81 04 24 65 2B 39 06 81 04 24 3C 37 33 5B 81 44 24 ?? 48 4F C2 5D 83 E8 01 C7 05 ?? ?? ?? ?? 00 00 00 00 75 ?? 8B 0D ?? ?? ?? ?? 53 8B 1D ?? ?? ?? ?? 55 8B 2D ?? ?? ?? ?? 56 81 C1 01 24 0A 00 57 8B 3D ?? ?? ?? ?? 89 0D ?? ?? ?? ?? 33 F6 EB ?? 8D 49 ?? 81 F9 FC 00 00 00 75 ?? 6A 00 FF 15 ?? ?? ?? ?? 6A 00 FF D7 8B 0D ?? ?? ?? ?? 81 F9 7C 0E 00 00 75 ?? 6A 00 FF D3 6A 00 6A 00 8D 44 24 ?? 50 6A 00 6A 00 FF D5 8B 0D ?? ?? ?? ?? 81 FE E5 84 C1 09 7E ?? 81 7C 24 ?? 0F 11 00 00 75 ?? 46 8B C6 99 83 FA 14 7C ?? 7F ?? 3D 30 C1 CF C7 72 ?? 51 6A 00 FF 15 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 33 F6 A3 ?? ?? ?? ?? 89 0D ?? ?? ?? ?? 39 35 ?? ?? ?? ?? 76 ?? 8B C6 E8 ?? ?? ?? ?? 46 3B 35 ?? ?? ?? ?? 72 ?? 8B 35 ?? ?? ?? ?? BF F0 72 E9 00 8B FF 81 3D ?? ?? ?? ?? 4D 09 00 00 75 ?? 6A 00 FF D6 83 EF 01 75 ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 5F 5E 5D 33 C0 5B 81 C4 30 04 00 00 C3}
		$files_encryption1 = { 8a 46 02 c1 e9 02 88 47 02 83 ee 02 83 ef 02 83 f9 08 72 88 fd f3 a5 fc ff 24 95 20 81 40 00 }
		$files_encryption2 = {8a4602c1e90288470283ee0283ef0283????72??fdf3a5fcff????????????}
		$files_encryption3 = { 8A 46 ?? C1 E9 02 88 47 ?? 83 EE 02 83 EF 02 83 F9 08 72 ?? FD F3 A5 FC FF 24 95 ?? ?? ?? ??}

	condition:
		filesize <= 300KB and any of ( $first_stage* ) and any of ( $files_encryption* )
}

rule ELCEEF_HTML_Smuggling_A : T1027 FILE
{
	meta:
		description = "Generic detection for HTML smuggling (T1027.006)"
		author = "marcin@ulikowski.pl"
		id = "b711318f-81d2-5d0b-968f-04ae18fdea5b"
		date = "2021-05-13"
		modified = "2023-04-16"
		reference = "https://github.com/elceef/yara-rulz"
		source_url = "https://github.com/elceef/yara-rulz/blob/05834717d1464d5efce8ad9d688ff7b53886a0bb/rules/HTML_Smuggling.yara#L1-L31"
		license_url = "https://github.com/elceef/yara-rulz/blob/05834717d1464d5efce8ad9d688ff7b53886a0bb/LICENSE"
		logic_hash = "bc076e9f3d4c6d2aa5a3602436408e5b2ac3140ca9f7cc776c44835cba211951"
		score = 75
		quality = 75
		tags = "T1027, FILE"
		hash1 = "279d5ef8f80aba530aaac8afd049fa171704fc703d9cfe337b56639732e8ce11"

	strings:
		$mssave = { ( 2e | 22 | 27 ) 6d 73 53 61 76 65 }
		$element = { ( 2e | 22 | 27 ) 63 72 65 61 74 65 45 6c 65 6d 65 6e 74 ( 28 | 22 | 27 ) }
		$objecturl = { ( 2e | 22 | 27 ) 63 72 65 61 74 65 4f 62 6a 65 63 74 55 52 4c ( 28 | 22 | 27 ) }
		$download = { ( 2e | 22 | 27 ) 64 6f 77 6e 6c 6f 61 64 ( 3d | 22 | 27 ) }
		$click = { ( 2e | 22 | 27 ) 63 6c 69 63 6b ( 3d | 22 | 27 ) }
		$atob = { 61 74 6f 62 ( 28 | 22 | 27 ) }
		$blob = "new Blob("
		$array = "new Uint8Array("
		$ole2 = "0M8R4KGxGuEA"
		$pe32 = "TVqQAAMAAAAE"
		$iso = "AAAABQ0QwMDE"
		$udf = "AAAAQkVBMDEB"
		$zip = { 55 45 73 44 42 ( 41 | 42 | 43 | 44 ) ( 6f | 30 | 4d | 51 ) ( 41 | 44 ) ( 41 | 43 ) }
		$jsxor = { 2e 63 68 61 72 43 6f 64 65 41 74 28 [1-10] 29 ( 5e | 20 5e ) }

	condition:
		filesize < 5MB and ( $mssave or ( #element == 1 and #objecturl == 1 and #download == 1 and #click == 1 ) ) and $blob and $array and $atob and ( #ole2 + #pe32 + #iso + #udf + #zip + #jsxor ) == 1
}

rule ELCEEF_HTML_Smuggling_B : T1027 FILE
{
	meta:
		description = "Generic detection for HTML smuggling (T1027.006)"
		author = "marcin@ulikowski.pl"
		id = "640d70c2-f1fc-5e32-a720-ebc92839ec40"
		date = "2022-12-02"
		modified = "2023-04-16"
		reference = "https://github.com/elceef/yara-rulz"
		source_url = "https://github.com/elceef/yara-rulz/blob/05834717d1464d5efce8ad9d688ff7b53886a0bb/rules/HTML_Smuggling.yara#L33-L60"
		license_url = "https://github.com/elceef/yara-rulz/blob/05834717d1464d5efce8ad9d688ff7b53886a0bb/LICENSE"
		logic_hash = "3c42e6f715bd5476aea4d47e9f6431747ddf7c7c8098840560201e2c21723eeb"
		score = 75
		quality = 75
		tags = "T1027, FILE"
		hash1 = "63955db0ccd6c0613912afb862635bde0fa925847f27adc8a0d65c994a7e05ea"

	strings:
		$objecturl = { ( 2e | 22 | 27 ) 63 72 65 61 74 65 4f 62 6a 65 63 74 55 52 4c ( 28 | 22 | 27 ) }
		$atob = "atob("
		$blob = "new Blob("
		$file = "new File(["
		$array = "new Uint8Array("
		$ole2 = "0M8R4KGxGuEA"
		$pe32 = "TVqQAAMAAAAE"
		$iso = "AAAABQ0QwMDE"
		$udf = "AAAAQkVBMDEB"
		$zip = { 55 45 73 44 42 ( 41 | 42 | 43 | 44 ) ( 6f | 30 | 4d | 51 ) ( 41 | 44 ) ( 41 | 43 ) }
		$jsxor = { 2e 63 68 61 72 43 6f 64 65 41 74 28 [1-10] 29 ( 5e | 20 5e ) }

	condition:
		filesize < 5MB and $atob and #objecturl == 1 and #file == 1 and #blob == 1 and #array == 1 and ( #ole2 + #pe32 + #iso + #udf + #zip + #jsxor ) == 1
}

rule ELCEEF_HTML_Smuggling_C : T1027 FILE
{
	meta:
		description = "Generic detection for HTML smuggling (T1027.006)"
		author = "marcin@ulikowski.pl"
		id = "ea1eafad-905b-571e-a016-8774e65bd976"
		date = "2023-04-17"
		modified = "2023-04-17"
		reference = "https://github.com/elceef/yara-rulz"
		source_url = "https://github.com/elceef/yara-rulz/blob/05834717d1464d5efce8ad9d688ff7b53886a0bb/rules/HTML_Smuggling.yara#L62-L82"
		license_url = "https://github.com/elceef/yara-rulz/blob/05834717d1464d5efce8ad9d688ff7b53886a0bb/LICENSE"
		logic_hash = "83409b0b173980975f6349e448e72fe1b2115fc7dbdec8ee7ad1826a65db17d3"
		score = 75
		quality = 75
		tags = "T1027, FILE"
		hash1 = "0b4cdfc8ae8ae17d7b6786050f1962c19858b91febb18f61f553083f57d96fea"
		hash2 = "2b99bf97f3d02ba3b44406cedd1ab31824723b56a8aae8057256cc87870c199e"
		hash3 = "904ea1ada62cfd4b964a6a3eb9bab5b98022ab000f77b75eb265a2ac44b45b37"

	strings:
		$blob = "new Blob("
		$array = "new Uint8Array("
		$mssave = { ( 2e | 22 | 27 ) 6d 73 53 61 76 65 }
		$loop = { ?? 5b 69 5d ( 3d | 20 3d | 3d 20 | 20 3d 20 ) ?? 5b 69 5d ( 2d | 20 2d | 2d 20 | 20 2d 20 ) 3? 3b }

	condition:
		filesize < 5MB and $mssave and #blob == 1 and #array == 1 and #loop == 1
}

