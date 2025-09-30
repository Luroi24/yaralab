rule TRELLIX_ARC_Masslogger_Stealer : STEALER FILE
{
	meta:
		description = "Rule to detect unpacked MassLogger stealer"
		author = "Marc Rivero | McAfee ATR Team"
		id = "c3a40108-3f0c-5949-9201-95c3c38b352a"
		date = "2020-07-02"
		modified = "2020-08-14"
		reference = "https://urlhaus.abuse.ch/browse/signature/MassLogger/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/malware/MALW_masslogger_stealer.yar#L1-L63"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		hash = "343873155b6950386f7d9bcd8d2b2e81088521aedf8ff1333d20229426d8145c"
		logic_hash = "476b3f3a54a4616058a2aef01adbe429a38eacc8ee58881d31bd28e795a27575"
		score = 75
		quality = 66
		tags = "STEALER, FILE"
		rule_version = "v1"
		malware_type = "stealer"
		malware_family = "Stealer:W32/MassLogger"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$pattern_0 = { 6437 3e2585829c88 ec ec 1bc8 }
		$pattern_1 = { d7 b9513e1ba7 195ab6 e6df 7e2a 5a b6cc }
		$pattern_2 = { 80aee281aae280 8ee2 808ce2808ee2808e e280 ae 00436f 6e }
		$pattern_3 = { 6d e586 4c 40 }
		$pattern_4 = { e281 ab e280 8ee2 80aee281aae280 8ee2 }
		$pattern_5 = { 6c 69636b65644576 656e 7441 7267 7300 }
		$pattern_6 = { 6e 7e81 d86aaf 61 93 7c2b 832b62 }
		$pattern_7 = { 8b1c87 e7ed 24a2 3218 73df 53 }
		$pattern_8 = { ee 9a357f9a475399 3188eef97d50 3f ef c9 }
		$pattern_9 = { 44 a2???????? 92 7526 42 208fb5ca7050 }
		$pattern_10 = { f2bbafb0d5f8 d524 0d48c906ba 7977 5d }
		$pattern_11 = { 748f 46 4e 49 2af2 ee 9a357f9a475399 }
		$pattern_12 = { 237ddb e200 95 46 99 37 }
		$pattern_13 = { d9ae1d19ec3b 01db c5615c ec }
		$pattern_14 = { 304a8a e2f4 bde7a84f79 c038d3 197ceae6 }
		$pattern_15 = { 291f ff84c3bd55d8dc f331f2 1a3a 9c 7d78 }
		$pattern_16 = { 3f 7af1 77a2 24ae 7ff3 }
		$pattern_17 = { d1655d 7236 3873c1 b59e }
		$pattern_18 = { 2aff 95 55 28ff 94 53 }
		$pattern_19 = { e6b1 43 08d2 ef 43 3c38 }
		$pattern_20 = { 6964427275736800 43 6f 6c 6f 7200 e281 }
		$pattern_21 = { 37 005400a7 877f08 54 00e1 875303 5c }
		$pattern_22 = { 6a45 e42c d3ba76c4f058 ce 3037 }
		$pattern_23 = { b59e 59 f1 f1 }
		$pattern_24 = { 7988 cd09 91 0099664e0391 008288490061 008c88d3099900 }
		$pattern_25 = { 1e e3c2 00ff 698876be8fb365b13eb7 45 }
		$pattern_26 = { 3d4c9deadf 57 ddeb 97 }
		$pattern_27 = { e280 8ee2 808ee281aee280 8ee2 81ace281ace280ade280ab e281 }
		$pattern_28 = { 4d 9c 8e5753 32414f d28a7173e2c4 7ee4 d9ae1d19ec3b }
		$pattern_29 = { 7472 69704d656e755f 53 61 }
		$pattern_30 = { 79bc fa ad 49 }
		$pattern_31 = { 875303 5c 00140a 37 005c00a7 }
		$pattern_32 = { 7265 5f 43 6c 69636b00746f6f 6c 53 }
		$pattern_33 = { 36e633 2b2b 3673d1 d480 124d2d }
		$pattern_34 = { 19b3e7ab29db 51 e1f3 dd3a 266f b884c4b53b }
		$pattern_35 = { 7467 43 f332d2 84bf3df2e66b 4a ba5a20d9f5 3dbf2a3753 }
		$pattern_36 = { f271f3 8877f7 a8e5 6437 3e2585829c88 }
		$pattern_37 = { ce 84604c 3f 8cc6 56 bf165fdec5 4a }
		$pattern_38 = { ad 49 a2???????? 4c e15b 8b1c87 }
		$pattern_39 = { 3400 b687 bc083c00cd 87ce 083400 }

	condition:
		7 of them and filesize < 3834880
}

rule TRELLIX_ARC_STEALER_Credstealesy : STEALER
{
	meta:
		description = "Generic Rule to detect the CredStealer Malware"
		author = "IsecG – McAfee Labs"
		id = "90e23ed8-3243-519b-8eb4-9db5902c73d3"
		date = "2015-05-08"
		modified = "2020-08-14"
		reference = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/when-hackers-get-hacked-the-malware-servers-of-a-data-stealing-campaign/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/stealer/STEALER_credstealer.yar#L1-L24"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		logic_hash = "3d007fc0d2e2eb3d8f0c2b86dd01ede482e72f6c67fd6d284d77c47b53021b3c"
		score = 75
		quality = 70
		tags = "STEALER"
		rule_version = "v1"
		malware_type = "stealer"
		malware_family = "Stealer:W32/CredStealer"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$my_hex_string = "CurrentControlSet\\Control\\Keyboard Layouts\\" wide
		$my_hex_string2 = {89 45 E8 3B 7D E8 7C 0F 8B 45 E8 05 FF 00 00 00 2B C7 89 45 E8}

	condition:
		$my_hex_string and $my_hex_string2
}

rule TRELLIX_ARC_STEALER_Emirates_Statement : STEALER
{
	meta:
		description = "Credentials Stealing Attack"
		author = "Christiaan Beek | McAfee ATR Team"
		id = "b5a6d996-8a3d-5238-95af-bf5ff893bbc5"
		date = "2013-06-30"
		modified = "2020-08-14"
		reference = "https://github.com/advanced-threat-research/Yara-Rules/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/stealer/STEALER_EmiratesStatement.yar#L1-L24"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		hash = "7cf757e0943b0a6598795156c156cb90feb7d87d4a22c01044499c4e1619ac57"
		logic_hash = "17eaddf375fc1875fb0275f8c0f93dfe921b452bdc6eb471adc155f749492328"
		score = 75
		quality = 45
		tags = "STEALER"
		rule_version = "v1"
		malware_type = "stealer"
		malware_family = "Stealer:W32/DarkSide"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$string0 = "msn.klm"
		$string1 = "wmsn.klm"
		$string2 = "bms.klm"

	condition:
		all of them
}

rule TRELLIX_ARC_STEALER_Lokibot : STEALER FILE
{
	meta:
		description = "Rule to detect Lokibot stealer"
		author = "Marc Rivero | McAfee ATR Team"
		id = "75f502a3-2d9f-5ccf-93f8-2d6a73e9e1b7"
		date = "2020-09-23"
		modified = "2020-09-25"
		reference = "https://github.com/advanced-threat-research/Yara-Rules/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/stealer/STEALER_Lokibot.yar#L1-L39"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		logic_hash = "999a69394a545f726cf15e4361e0dfc17eeac6544e6816a0ad140316e9642510"
		score = 75
		quality = 70
		tags = "STEALER, FILE"
		rule_version = "v1"
		malware_type = "stealer"
		malware_family = "Ransomware:W32/Lokibot"
		actor_type = "Cybercrime"
		actor_group = "Unknown"
		hash1 = "0e40f4fdd77e1f90279c585cfc787942b8474e5216ff4d324d952ef6b74f25d2"
		hash2 = "3ad36afad12d8cf245904285c21a8db43f9ed9c82304fdc2f27c4dd1438e4a1d"
		hash3 = "26fbdd516b3c1bfa36784ef35d6bc216baeb0ef2d0c0ba036ff9296da2ce2c84"

	strings:
		$sq1 = { 55 8B EC 56 8B 75 08 57 56 E8 ?? ?? ?? ?? 8B F8 59 85 FF 75 04 33 C0 EB 20 56 6A 00 57 E8 ?? ?? ?? ?? 6A 0C E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 E5 83 60 08 00 89 38 89 70 04 5F 5E 5D C3 }
		$sq2 = { 55 8B EC 83 EC 0C 53 56 57 33 DB BE ?? ?? ?? ?? 53 53 56 6A 09 E8 ?? ?? ?? ?? 6A 10 6A 01 53 53 8D 4D F8 51 FF D0 53 53 56 6A 09 E8 ?? ?? ?? ?? 6A 08 6A 01 53 53 8D 4D F8 51 FF D0 85 C0 0F 84 2B 01 00 00 6A 24 E8 ?? ?? ?? ?? 59 8B D8 33 C0 6A 09 59 8B FB F3 AB 66 8B 4D 24 B8 03 66 00 00 C7 03 08 02 00 00 66 85 C9 74 03 0F B7 C1 8B 4D 08 33 D2 0F B7 C0 89 43 04 89 53 08 85 C9 74 12 C7 43 08 08 00 00 00 8B 01 89 43 0C 8B 41 04 89 43 10 8B 4D 0C 85 C9 74 0F 83 43 08 08 8B 01 89 43 14 8B 41 04 89 43 18 8B 4D 10 85 C9 74 0F 83 43 08 08 8B 01 89 43 1C 8B 41 04 89 43 20 8B 7B 08 8B 75 F8 83 C7 0C 52 52 68 ?? ?? ?? ?? 6A 09 E8 ?? ?? ?? ?? 8D 4D FC 51 6A 00 6A 00 57 53 56 FF D0 85 C0 74 75 8B 75 FC 33 C0 40 83 7D 20 00 0F 45 45 20 33 FF 57 57 68 ?? ?? ?? ?? 6A 09 89 45 F4 E8 ?? ?? ?? ?? 57 8D 4D F4 51 6A 04 56 FF D0 85 C0 74 3B 39 7D 14 74 1A 8B 75 FC 57 57 68 ?? ?? ?? ?? 6A 09 E8 ?? ?? ?? ?? 57 FF 75 14 6A 01 56 FF D0 8B 55 18 8B 4D FC 53 89 0A 8B 55 1C 8B 4D F8 89 0A E8 ?? ?? ?? ?? 33 C0 59 40 EB 21 FF 75 FC E8 BF FB FF FF 59 EB 02 33 FF 53 E8 ?? ?? ?? ?? 57 FF 75 F8 E8 6B FB FF FF 83 C4 0C 33 C0 5F 5E 5B 8B E5 5D C3 }
		$sq3 = { 55 8B EC 83 EC 0C 53 8B 5D 0C 56 57 6A 10 33 F6 89 75 F8 89 75 FC 58 89 45 F4 85 DB 75 0E FF 75 08 E8 ?? ?? ?? ?? 8B D8 8B 45 F4 59 50 E8 ?? ?? ?? ?? 8B F8 59 85 FF 0F 84 B6 00 00 00 FF 75 F4 56 57 E8 C4 ?? ?? ?? 83 C4 0C 56 56 68 ?? ?? ?? ?? 6A 09 E8 ?? ?? ?? ?? 68 00 00 00 F0 6A 01 56 56 8D 4D F8 51 FF D0 85 C0 0F 84 84 00 00 00 8B 75 F8 6A 00 6A 00 68 ?? ?? ?? ?? 6A 09 E8 ?? ?? ?? ?? 8D 4D FC 51 6A 00 6A 00 68 03 80 00 00 56 FF D0 85 C0 74 51 6A 00 53 FF 75 08 FF 75 FC E8 7F FD FF FF 83 C4 10 85 C0 74 3C 8B 75 FC 6A 00 6A 00 68 ?? ?? ?? ?? 6A 09 E8 ?? ?? ?? ?? 6A 00 8D 4D F4 51 57 6A 02 56 FF D0 85 C0 74 19 FF 75 FC E8 16 FD FF FF 6A 00 FF 75 F8 E8 26 FD FF FF 83 C4 0C 8B C7 EB 0E 6A 00 FF 75 F8 E8 15 FD FF FF 59 59 33 C0 5F 5E 5B 8B E5 5D C3 }
		$sq4 = { 55 8B EC 83 7D 10 00 56 57 8B 7D 0C 57 74 0E E8 ?? ?? ?? ?? 8B F0 33 C0 03 F6 40 EB 09 E8 ?? ?? ?? ?? 8B F0 33 C0 83 7D 14 00 59 75 24 50 FF 75 08 E8 2C 00 00 00 59 59 83 F8 01 74 04 33 C0 EB 1D 56 FF 75 08 E8 C5 FE FF FF 59 59 83 F8 01 75 EC 56 57 FF 75 08 E8 CA FE FF FF 83 C4 0C 5F 5E 5D C3 }
		$sq5 = { 55 8B EC 53 56 8B 75 0C 57 85 F6 75 0B FF 75 08 E8 ?? ?? ?? ?? 59 8B F0 6B C6 03 89 45 0C 8D 58 01 53 E8 ?? ?? ?? ?? 8B F8 59 85 FF 74 42 53 6A 00 57 E8 ?? ?? ?? ?? 83 C4 0C 33 D2 85 F6 74 27 8B 45 08 0F B6 0C 02 8B C1 83 E1 0F C1 E8 04 8A 80 ?? ?? ?? ?? 88 04 57 8A 81 ?? ?? ?? ?? 88 44 57 01 42 3B D6 72 D9 8B 45 0C C6 04 07 00 8B C7 5F 5E 5B 5D C3 }
		$sq6 = { 55 8B EC 53 56 57 FF 75 08 E8 ?? ?? ?? ?? 33 C9 6A 02 5B 8D B8 A0 1F 00 00 8B C7 F7 E3 0F 90 C1 F7 D9 0B C8 51 E8 ?? ?? ?? ?? 8B F0 59 59 85 F6 74 6F 8D 0C 3F 51 6A 00 56 E8 ?? ?? ?? ?? 8D 45 0C 50 FF 75 08 56 E8 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 8B F8 83 C4 1C 85 FF 74 40 33 C9 8D 47 02 F7 E3 0F 90 C1 F7 D9 0B C8 51 E8 ?? ?? ?? ?? 8B D8 59 85 DB 74 25 8D 0C 7D 02 00 00 00 51 6A 00 53 E8 ?? ?? ?? ?? 57 56 53 E8 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4 1C 8B C3 EB 09 56 E8 ?? ?? ?? ?? 59 33 C0 5F 5E 5B 5D C3 }
		$sq7 = { 55 8B EC 81 EC 80 00 00 00 56 57 E8 ?? ?? ?? ?? 6A 1F 59 BE ?? ?? ?? ?? 8D 7D 80 F3 A5 33 C9 6A 02 5A 66 A5 8B 7D 08 8D 47 01 F7 E2 0F 90 C1 F7 D9 0B C8 51 E8 ?? ?? ?? ?? 8B F0 59 85 F6 74 4D 8D 04 7D 02 00 00 00 4F 89 45 08 53 50 6A 00 56 E8 ?? ?? ?? ?? 83 C4 0C 33 DB 85 FF 74 1C E8 ?? ?? ?? ?? 33 D2 6A 7E 59 F7 F1 D1 EA 66 8B 44 55 80 66 89 04 5E 43 3B DF 72 E4 56 E8 ?? ?? ?? ?? 3B F8 8B 45 08 59 77 C4 8B C6 5B EB 02 33 C0 5F 5E 8B E5 5D C3 }
		$sq8 = { 55 8B EC 81 EC 50 02 00 00 53 56 57 6A 0A E8 ?? ?? ?? ?? 59 33 DB 6A 2E 5E 39 5D 14 0F 84 13 01 00 00 FF 75 08 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F0 59 59 85 F6 0F 84 F7 00 00 00 53 53 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 8D 8D B0 FD FF FF 51 56 FF D0 8B D8 83 FB FF 0F 84 CC 00 00 00 F6 85 B0 FD FF FF 10 0F 84 97 00 00 00 83 7D 1C 00 74 2E 8D 85 DC FD FF FF 68 ?? ?? ?? ?? 50 E8 0A ?? ?? ?? 59 59 85 C0 75 7A 8D 85 DC FD FF FF 68 ?? ?? ?? ?? 50 E8 F3 ?? ?? ?? 59 59 85 C0 75 63 8D 85 DC FD FF FF 50 E8 ?? ?? ?? ?? 59 83 F8 03 73 0C 6A 2E 58 66 39 85 DC FD FF FF 74 45 8D 85 DC FD FF FF 50 FF 75 08 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 89 45 14 85 C0 74 27 6A 01 6A 00 6A 01 FF 75 10 FF 75 0C 50 E8 14 FF FF FF FF 75 14 8B F8 E8 ?? ?? ?? ?? 83 C4 1C 85 FF 0F 85 EE 00 00 00 33 C0 50 50 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8D 8D B0 FD FF FF 51 53 FF D0 85 C0 0F 85 3B FF FF FF 53 E8 ?? ?? ?? ?? 59 56 E8 ?? ?? ?? ?? 59 33 DB 6A 2E 5E FF 75 0C FF 75 08 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F8 83 C4 0C 85 FF 0F 84 CF 00 00 00 53 53 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 8D 8D B0 FD FF FF 51 57 FF D0 8B D8 83 FB FF 0F 84 A6 00 00 00 8D 85 DC FD FF FF 50 E8 ?? ?? ?? ?? 59 83 F8 03 73 09 66 39 B5 DC FD FF FF 74 3E 83 BD B0 FD FF FF 10 75 06 83 7D 18 00 74 2F 8D 85 DC FD FF FF 50 FF 75 08 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F0 83 C4 0C 85 F6 74 12 83 7D 10 00 74 40 56 FF 55 10 56 E8 ?? ?? ?? ?? 59 59 33 C0 50 50 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8D 8D B0 FD FF FF 51 53 FF D0 85 C0 74 29 6A 2E 5E EB 85 56 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 59 59 8B C7 EB 22 57 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 59 59 8B C6 EB 10 53 E8 ?? ?? ?? ?? 59 57 E8 ?? ?? ?? ?? 59 33 C0 5F 5E 5B 8B E5 5D C3 }
		$sq9 = { 83 3D 14 ?? ?? ?? ?? 56 74 0A 8B 35 20 ?? ?? ?? 85 F6 75 66 53 57 BB E0 01 00 00 33 FF 53 89 3D 14 ?? ?? ?? E8 F0 F8 FF FF 33 F6 A3 14 ?? ?? ?? 46 59 85 C0 74 12 6A 78 57 50 89 35 20 ?? ?? ?? E8 A6 F8 FF FF 83 C4 0C 53 89 3D 18 ?? ?? ?? E8 C5 F8 FF FF A3 18 ?? ?? ?? 59 85 C0 74 14 6A 78 57 50 89 35 20 ?? ?? ?? E8 7E F8 FF FF 83 C4 0C EB 06 8B 35 20 ?? ?? ?? 5F 5B 8B C6 5E C3 }
		$sq10 = { 55 8B EC 51 51 83 65 FC 00 53 56 57 64 A1 30 00 00 00 89 45 FC 8B 45 FC 8B 40 0C 8B 58 0C 8B F3 8B 46 18 FF 76 28 89 45 F8 E8 CE FA FF FF 8B F8 59 85 FF 74 1F 6A 00 57 E8 32 01 00 00 57 E8 ?? ?? ?? ?? 03 C0 50 57 E8 71 FA FF FF 83 C4 14 39 45 08 74 11 8B 36 3B DE 75 C6 33 C0 5F 5E 5B 8B E5 5D C2 04 00 8B 45 F8 EB F2 }
		$sq11 = { A1 ?? ?? ?? ?? 85 C0 74 07 50 E8 ?? ?? ?? ?? 59 A1 ?? ?? ?? ?? 85 C0 74 07 50 E8 ?? ?? ?? ?? 59 A1 ?? ?? ?? ?? 85 C0 74 07 50 E8 ?? ?? ?? ?? 59 33 C0 A3 ?? ?? ?? ?? A3 ?? ?? ?? ?? A3 ?? ?? ?? ?? C3 }
		$sq12 = { 55 8B EC 56 8B 75 0C 57 85 F6 74 48 56 E8 ?? ?? ?? ?? 59 85 C0 74 3D 56 E8 ?? ?? ?? ?? 59 85 C0 74 32 83 65 0C 00 8D 45 0C 6A 01 50 56 E8 ?? ?? ?? ?? 8B F8 83 C4 0C 85 FF 74 19 8B 45 0C 85 C0 74 12 83 7D 14 00 74 12 39 45 14 73 0D 57 E8 ?? ?? ?? ?? 59 33 C0 5F 5E 5D C3 83 7D 10 00 74 1A 6A 00 6A 01 56 E8 ?? ?? ?? ?? 59 50 FF 75 08 E8 1F 00 00 00 8B 45 0C 83 C4 10 50 57 FF 75 08 E8 FF FE FF FF 57 8B F0 E8 ?? ?? ?? ?? 83 C4 10 8B C6 EB C3 }
		$sq13 = { 55 8B EC 83 EC 18 56 FF 75 08 E8 ?? ?? ?? ?? 50 89 45 F0 E8 ?? ?? ?? ?? 8B F0 59 59 85 F6 0F 84 C0 00 00 00 53 8B 5D 0C 33 C9 57 6A 04 5A 8B C3 F7 E2 0F 90 C1 F7 D9 0B C8 51 E8 ?? ?? ?? ?? 83 65 F4 00 8B F8 83 65 FC 00 59 85 DB 74 6D 8B 45 10 83 C0 FC FF 75 F0 83 C0 04 89 45 E8 6A 00 56 8B 00 89 45 EC E8 ?? ?? ?? ?? FF 75 F0 FF 75 08 56 E8 ?? ?? ?? ?? 83 65 F8 00 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4 20 EB 1F FF 75 EC 50 E8 ?? ?? ?? ?? 59 59 85 C0 75 32 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? FF 45 F8 59 59 85 C0 75 DD 8B 45 FC 40 89 45 FC 3B C3 8B 45 E8 72 99 56 E8 ?? ?? ?? ?? 59 39 5D F4 75 12 8B C7 EB 17 8B 45 FC 8B 4D F8 FF 45 F4 89 0C 87 EB D7 57 E8 ?? ?? ?? ?? 59 33 C0 5F 5B 5E 8B E5 5D C3 }
		$sq14 = { 55 8B EC 8B 45 0C 53 56 8B 75 08 57 8B 4E 04 03 C1 8D 3C 09 3B F8 77 06 8D B8 F4 01 00 00 33 C9 8B C7 6A 04 5A F7 E2 0F 90 C1 F7 D9 0B C8 51 E8 ?? ?? ?? ?? 8B D8 59 85 DB 74 26 57 6A 00 53 E8 ?? ?? ?? ?? FF 76 08 FF 36 53 E8 ?? ?? ?? ?? FF 36 E8 ?? ?? ?? ?? 33 C0 89 1E 83 C4 1C 89 7E 04 40 5F 5E 5B 5D C3 }
		$sq15 = { 55 8B EC 83 7D 0C 00 57 74 39 8B 7D 10 85 FF 74 32 56 8B 75 08 8B 46 08 03 C7 3B 46 04 76 09 57 56 E8 3F FF FF FF 59 59 8B 46 08 03 06 57 FF 75 0C 50 E8 ?? ?? ?? ?? 01 7E 08 83 C4 0C 33 C0 40 5E EB 02 33 C0 5F 5D C3 }

	condition:
		uint16( 0 ) == 0x5a4d and any of them
}

