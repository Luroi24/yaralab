rule MICROSOFT_Trojan_Win32_Plasrv : PLATINUM
{
	meta:
		description = "Hotpatching Injector"
		author = "Microsoft"
		id = "2a099b68-fb13-5926-8a86-4d788326609c"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L1-L19"
		license_url = "N/A"
		hash = "ff7f949da665ba8ce9fb01da357b51415634eaad"
		logic_hash = "5978502454d66a930a535ffe61d78f2106c3c17c8df9be1b22bc10ef900c891f"
		score = 75
		quality = 80
		tags = "PLATINUM"
		unpacked_sample_sha1 = "dff2fee984ba9f5a8f5d97582c83fca4fa1fe131"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$Section_name = ".hotp1"
		$offset_x59 = { C7 80 64 01 00 00 00 00 01 00 }

	condition:
		$Section_name and $offset_x59
}

rule MICROSOFT_Trojan_Win32_Platual : PLATINUM
{
	meta:
		description = "Installer component"
		author = "Microsoft"
		id = "ac963388-cc73-5842-96be-77349398efcc"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L21-L38"
		license_url = "N/A"
		hash = "e0ac2ae221328313a7eee33e9be0924c46e2beb9"
		logic_hash = "3692b5c1d873fb799b64ea69f3762177198dbb0fb971bc29bb80048c0de735d4"
		score = 75
		quality = 80
		tags = "PLATINUM"
		unpacked_sample_sha1 = "ccaf36c2d02c3c5ca24eeeb7b1eae7742a23a86a"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$class_name = "AVCObfuscation"
		$scrambled_dir = { A8 8B B8 E3 B1 D7 FE 85 51 32 3E C0 F1 B7 73 99 }

	condition:
		$class_name and $scrambled_dir
}

rule MICROSOFT_Trojan_Win32_Plaplex : PLATINUM
{
	meta:
		description = "Variant of the JPin backdoor"
		author = "Microsoft"
		id = "2d670c09-dc0a-556e-8d00-5f94e5907d99"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L40-L57"
		license_url = "N/A"
		hash = "ca3bda30a3cdc15afb78e54fa1bbb9300d268d66"
		logic_hash = "ff7b9a52befae5f22f7c6093af44bef4a4cf271548c1caf22f30d3c8aec42de4"
		score = 75
		quality = 80
		tags = "PLATINUM"
		unpacked_sample_sha1 = "2fe3c80e98bbb0cf5a0c4da286cd48ec78130a24"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$class_name1 = "AVCObfuscation"
		$class_name2 = "AVCSetiriControl"

	condition:
		$class_name1 and $class_name2
}

rule MICROSOFT_Trojan_Win32_Dipsind_B : PLATINUM
{
	meta:
		description = "Dipsind Family"
		author = "Microsoft"
		id = "513c18a6-af25-58ad-9232-9a089f4ced3d"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L59-L77"
		license_url = "N/A"
		logic_hash = "1f99f298dc4d1483eb95cfb898dd9eee32b2f72a8da562f58a57f44559cbd2c7"
		score = 75
		quality = 80
		tags = "PLATINUM"
		sample_sha1 = "09e0dfbb5543c708c0dd6a89fd22bbb96dc4ca1c"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$frg1 = {8D 90 04 01 00 00 33 C0 F2 AE F7 D1 2B F9 8B C1 8B F7 8B FA C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 4D EC 8B 15 ?? ?? ?? ?? 89 91 ?? 07 00 00 }
		$frg2 = {68 A1 86 01 00 C1 E9 02 F3 AB 8B CA 83 E1 03 F3 AA}
		$frg3 = {C0 E8 07 D0 E1 0A C1 8A C8 32 D0 C0 E9 07 D0 E0 0A C8 32 CA 80 F1 63}

	condition:
		$frg1 and $frg2 and $frg3
}

rule MICROSOFT_Trojan_Win32_Plakeylog_B : PLATINUM
{
	meta:
		description = "Keylogger component"
		author = "Microsoft"
		id = "bc84ef20-f428-5f3d-bc88-ab14991a2350"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L79-L97"
		license_url = "N/A"
		hash = "0096a3e0c97b85ca75164f48230ae530c94a2b77"
		logic_hash = "288fb5a724baaa032ca36124cf803698e315aaf61662f999f3b894049ece63f2"
		score = 75
		quality = 80
		tags = "PLATINUM"
		unpacked_sample_sha1 = "6a1412daaa9bdc553689537df0a004d44f8a45fd"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$hook = {C6 06 FF 46 C6 06 25}
		$dasm_engine = {80 C9 10 88 0E 8A CA 80 E1 07 43 88 56 03 80 F9 05}

	condition:
		$hook and $dasm_engine
}

rule MICROSOFT_Trojan_Win32_Adupib : PLATINUM
{
	meta:
		description = "Adupib SSL Backdoor"
		author = "Microsoft"
		id = "4c5a63e5-7110-57e9-b939-df8999f317d3"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L99-L120"
		license_url = "N/A"
		hash = "d3ad0933e1b114b14c2b3a2c59d7f8a95ea0bcbd"
		logic_hash = "b83f642929a372a21e63055cd4adcab5d24b98b5a98b6fd0b35ee31e9f7f3b90"
		score = 75
		quality = 80
		tags = "PLATINUM"
		unpacked_sample_sha1 = "a80051d5ae124fd9e5cc03e699dd91c2b373978b"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$str1 = "POLL_RATE"
		$str2 = "OP_TIME(end hour)"
		$str3 = "%d:TCP:*:Enabled"
		$str4 = "%s[PwFF_cfg%d]"
		$str5 = "Fake_GetDlgItemTextW: ***value***"

	condition:
		$str1 and $str2 and $str3 and $str4 and $str5
}

rule MICROSOFT_Trojan_Win32_Plalsalog : PLATINUM
{
	meta:
		description = "Loader / possible incomplete LSA Password Filter"
		author = "Microsoft"
		id = "e5c7e07d-79e3-580f-ac24-28920a9b0e70"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L122-L140"
		license_url = "N/A"
		hash = "fa087986697e4117c394c9a58cb9f316b2d9f7d8"
		logic_hash = "58d937be220c0f356396c28367ab63ff4c4a6bf2cbf9e0ce8f8cac25e4fe3fec"
		score = 75
		quality = 80
		tags = "PLATINUM"
		unpacked_sample_sha1 = "29cb81dbe491143b2f8b67beaeae6557d8944ab4"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$str1 = {8A 1C 01 32 DA 88 1C 01 8B 74 24 0C 41 3B CE 7C EF 5B 5F C6 04 01 00 5E 81 C4 04 01 00 00 C3}
		$str2 = "PasswordChangeNotify"

	condition:
		$str1 and $str2
}

rule MICROSOFT_Trojan_Win32_Plagon : PLATINUM
{
	meta:
		description = "Dipsind variant"
		author = "Microsoft"
		id = "ae3b7eb0-d54e-5817-9484-c054cd27c1fd"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L142-L162"
		license_url = "N/A"
		hash = "48b89f61d58b57dba6a0ca857bce97bab636af65"
		logic_hash = "99e0d300f030bb6407de1fda488b47c73f8278e9c015bf779259ddf1b68903a2"
		score = 75
		quality = 78
		tags = "PLATINUM"
		unpacked_sample_sha1 = "6dccf88d89ad7b8611b1bc2e9fb8baea41bdb65a"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$str1 = "VPLRXZHTU"
		$str2 = {64 6F 67 32 6A 7E 6C}
		$str3 = "Dqpqftk(Wou\"Isztk)"
		$str4 = "StartThreadAtWinLogon"

	condition:
		$str1 and $str2 and $str3 and $str4
}

rule MICROSOFT_Trojan_Win32_Plakelog : PLATINUM
{
	meta:
		description = "Raw-input based keylogger"
		author = "Microsoft"
		id = "26f552e6-9abf-59ca-a8df-19473d6d775a"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L164-L184"
		license_url = "N/A"
		hash = "3907a9e41df805f912f821a47031164b6636bd04"
		logic_hash = "e18cae8bb2a79f7d39a80669896b1f7a7c1726f14192abcc91388fd53781ffef"
		score = 75
		quality = 80
		tags = "PLATINUM"
		unpacked_sample_sha1 = "960feeb15a0939ec0b53dcb6815adbf7ac1e7bb2"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$str1 = "<0x02>" wide
		$str2 = "[CTR-BRK]" wide
		$str3 = "[/WIN]" wide
		$str4 = {8A 16 8A 18 32 DA 46 88 18 8B 15 08 E6 42 00 40 41 3B CA 72 EB 5E 5B}

	condition:
		$str1 and $str2 and $str3 and $str4
}

rule MICROSOFT_Trojan_Win32_Plainst : PLATINUM
{
	meta:
		description = "Installer component"
		author = "Microsoft"
		id = "41a4770a-b4d8-5ddc-8b4f-a4e87a1f3923"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L186-L204"
		license_url = "N/A"
		hash = "99c08d31af211a0e17f92dd312ec7ca2b9469ecb"
		logic_hash = "5fa8e52c044e05d96c2c09b69ef884ed0ea863ceb3ba00cdf243a4907050de69"
		score = 75
		quality = 80
		tags = "PLATINUM"
		unpacked_sample_sha1 = "dcb6cf7cf7c8fdfc89656a042f81136bda354ba6"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$str1 = {66 8B 14 4D 18 50 01 10 8B 45 08 66 33 14 70 46 66 89 54 77 FE 66 83 7C 77 FE 00 75 B7 8B 4D FC 89 41 08 8D 04 36 89 41 0C 89 79 04}
		$str2 = {4b D391 49 A1 80 91 42 83 B6 33 28 36 6B 90 97}

	condition:
		$str1 and $str2
}

rule MICROSOFT_Trojan_Win32_Plagicom : PLATINUM
{
	meta:
		description = "Installer component"
		author = "Microsoft"
		id = "86ef6fbf-cd39-533f-893c-72f22d73c99a"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L206-L225"
		license_url = "N/A"
		hash = "99dcb148b053f4cef6df5fa1ec5d33971a58bd1e"
		logic_hash = "d2645ecc3b4400af7d9949eeca01b1ed5d74516010658c66934772e04040d9cf"
		score = 75
		quality = 80
		tags = "PLATINUM"
		unpacked_sample_sha1 = "c1c950bc6a2ad67488e675da4dfc8916831239a7"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$str1 = {C6 44 24 ?? 68 C6 44 24 ?? 4D C6 44 24 ?? 53 C6 44 24 ?? 56 C6 44 24 ?? 00}
		$str2 = "OUEMM/EMM"
		$str3 = {85 C9 7E 08 FE 0C 10 40 3B C1 7C F8 C3}

	condition:
		$str1 and $str2 and $str3
}

rule MICROSOFT_Trojan_Win32_Plaklog : PLATINUM
{
	meta:
		description = "Hook-based keylogger"
		author = "Microsoft"
		id = "4faffe66-63fc-5498-be59-dbbbb909ad74"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L227-L246"
		license_url = "N/A"
		hash = "831a5a29d47ab85ee3216d4e75f18d93641a9819"
		logic_hash = "af8dd0749d07f0b99cf3dd24bc144d38fe6db00f699bc7f45f197ac6e1663cad"
		score = 75
		quality = 80
		tags = "PLATINUM"
		unpacked_sample_sha1 = "e18750207ddbd939975466a0e01bd84e75327dda"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$str1 = "++[%s^^unknown^^%s]++"
		$str2 = "vtfs43/emm"
		$str3 = {33 C9 39 4C 24 08 7E 10 8B 44 24 04 03 C1 80 00 08 41 3B 4C 24 08 7C F0 C3}

	condition:
		$str1 and $str2 and $str3
}

rule MICROSOFT_Trojan_Win32_Plapiio : PLATINUM
{
	meta:
		description = "JPin backdoor"
		author = "Microsoft"
		id = "538086b5-eb06-5e41-90d4-ab8f2b001c42"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L248-L267"
		license_url = "N/A"
		hash = "3119de80088c52bd8097394092847cd984606c88"
		logic_hash = "580fb1377d98e7ffcb9823b5c485ff536813e3df5d8bded745373b2a3a82fcfd"
		score = 75
		quality = 80
		tags = "PLATINUM"
		unpacked_sample_sha1 = "3acb8fe2a5eb3478b4553907a571b6614eb5455c"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$str1 = "ServiceMain"
		$str2 = "Startup"
		$str3 = {C6 45 ?? 68 C6 45 ?? 4D C6 45 ?? 53 C6 45 ?? 56 C6 45 ?? 6D C6 45 ?? 6D}

	condition:
		$str1 and $str2 and $str3
}

rule MICROSOFT_Trojan_Win32_Plabit : PLATINUM
{
	meta:
		description = "Installer component"
		author = "Microsoft"
		id = "cee48cbb-f980-50cc-b28a-2e80e7f1798b"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L269-L287"
		license_url = "N/A"
		logic_hash = "35f12d45c8ee5f8e2b0bcd57ae14c0ba52670abc1212f94aa276efbbe1043146"
		score = 75
		quality = 80
		tags = "PLATINUM"
		sample_sha1 = "6d1169775a552230302131f9385135d385efd166"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$str1 = {4b D3 91 49 A1 80 91 42 83 B6 33 28 36 6B 90 97}
		$str2 = "GetInstanceW"
		$str3 = {8B D0 83 E2 1F 8A 14 0A 30 14 30 40 3B 44 24 04 72 EE}

	condition:
		$str1 and $str2 and $str3
}

rule MICROSOFT_Trojan_Win32_Placisc2 : PLATINUM
{
	meta:
		description = "Dipsind variant"
		author = "Microsoft"
		id = "a5557cfa-354c-5913-9b63-f53ffb294796"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L289-L309"
		license_url = "N/A"
		hash = "bf944eb70a382bd77ee5b47548ea9a4969de0527"
		logic_hash = "6629ca96c73e48bc14c811df781973f8040f88bcbf9eda601e9f5db86e11c20b"
		score = 75
		quality = 80
		tags = "PLATINUM"
		unpacked_sample_sha1 = "d807648ddecc4572c7b04405f496d25700e0be6e"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$str1 = {76 16 8B D0 83 E2 07 8A 4C 14 24 8A 14 18 32 D1 88 14 18 40 3B C7 72 EA }
		$str2 = "VPLRXZHTU"
		$str3 = "%d) Command:%s"
		$str4 = {0D 0A 2D 2D 2D 2D 2D 09 2D 2D 2D 2D 2D 2D 0D 0A}

	condition:
		$str1 and $str2 and $str3 and $str4
}

rule MICROSOFT_Trojan_Win32_Placisc3 : PLATINUM
{
	meta:
		description = "Dipsind variant"
		author = "Microsoft"
		id = "f2089236-8227-5042-9086-fb77aebd147f"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L311-L329"
		license_url = "N/A"
		hash = "1b542dd0dacfcd4200879221709f5fa9683cdcda"
		logic_hash = "3a1afe737c08b4d9149380e04f5d6240a00b237822c3c82d82eccf5412cb05d1"
		score = 75
		quality = 80
		tags = "PLATINUM"
		unpacked_sample_sha1 = "bbd4992ee3f3a3267732151636359cf94fb4575d"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$str1 = {BA 6E 00 00 00 66 89 95 ?? ?? FF FF B8 73 00 00 00 66 89 85 ?? ?? FF FF B9 64 00 00 00 66 89 8D ?? ?? FF FF BA 65 00 00 00 66 89 95 ?? ?? FF FF B8 6C 00 00 00}
		$str2 = "VPLRXZHTU"
		$str3 = {8B 44 24 ?? 8A 04 01 41 32 C2 3B CF 7C F2 88 03}

	condition:
		$str1 and $str2 and $str3
}

rule MICROSOFT_Trojan_Win32_Placisc4 : PLATINUM
{
	meta:
		description = "Installer for Dipsind variant"
		author = "Microsoft"
		id = "04770059-06ca-5315-a7b3-0e9fbcecfc57"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L331-L350"
		license_url = "N/A"
		hash = "3d17828632e8ff1560f6094703ece5433bc69586"
		logic_hash = "4fa4f48d6747cde6d635eca2f5277da7be17473a561828eafa604fbc2801073a"
		score = 75
		quality = 80
		tags = "PLATINUM"
		unpacked_sample_sha1 = "2abb8e1e9cac24be474e4955c63108ff86d1a034"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$str1 = {8D 71 01 8B C6 99 BB 0A00 00 00 F7 FB 0F BE D2 0F BE 04 39 2B C2 88 04 39 84 C0 74 0A}
		$str2 = {6A 04 68 00 20 00 00 68 00 00 40 00 6A 00 FF D5}
		$str3 = {C6 44 24 ?? 64 C6 44 24 ?? 6F C6 44 24 ?? 67 C6 44 24 ?? 32 C6 44 24 ?? 6A}

	condition:
		$str1 and $str2 and $str3
}

rule MICROSOFT_Trojan_Win32_Plakpers : PLATINUM
{
	meta:
		description = "Injector / loader component"
		author = "Microsoft"
		id = "d37c6ac5-ca46-5fb2-80bd-ab63c8dbcd21"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L352-L371"
		license_url = "N/A"
		hash = "fa083d744d278c6f4865f095cfd2feabee558056"
		logic_hash = "d3705a34232ba2b00786b32f84823d3a6b037ed6a5882983e69addc020bc0b35"
		score = 75
		quality = 80
		tags = "PLATINUM"
		unpacked_sample_sha1 = "3a678b5c9c46b5b87bfcb18306ed50fadfc6372e"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$str1 = "MyFileMappingObject"
		$str2 = "[%.3u]  %s  %s  %s [%s:" wide
		$str3 = "%s\\{%s}\\%s" wide

	condition:
		$str1 and $str2 and $str3
}

rule MICROSOFT_Trojan_Win32_Plainst2 : PLATINUM
{
	meta:
		description = "Zc tool"
		author = "Microsoft"
		id = "7202eeb5-269d-5e9a-9a93-bdf489639e74"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L373-L392"
		license_url = "N/A"
		hash = "3f2ce812c38ff5ac3d813394291a5867e2cddcf2"
		logic_hash = "4dc897a598fd491694f8fe3ec4ae9278dc341ffd9f95f416eb5e98fb5aa200e4"
		score = 75
		quality = 80
		tags = "PLATINUM"
		unpacked_sample_sha1 = "88ff852b1b8077ad5a19cc438afb2402462fbd1a"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$str1 = "Connected [%s:%d]..."
		$str2 = "reuse possible: %c"
		$str3 = "] => %d%%\x0a"

	condition:
		$str1 and $str2 and $str3
}

rule MICROSOFT_Trojan_Win32_Plakpeer : PLATINUM
{
	meta:
		description = "Zc tool v2"
		author = "Microsoft"
		id = "e573279b-4a7b-5e15-8ab2-a77cd98a8b6e"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L394-L414"
		license_url = "N/A"
		hash = "2155c20483528377b5e3fde004bb604198463d29"
		logic_hash = "cc34ce9f12c95133872783090efd5813d3e2f44a1c726d29b2ba834509c9a1d5"
		score = 75
		quality = 55
		tags = "PLATINUM"
		unpacked_sample_sha1 = "dc991ef598825daabd9e70bac92c79154363bab2"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$str1 = "@@E0020(%d)" wide
		$str2 = /exit.{0,3}@exit.{0,3}new.{0,3}query.{0,3}rcz.{0,3}scz/ wide
		$str3 = "---###---" wide
		$str4 = "---@@@---" wide

	condition:
		$str1 and $str2 and $str3 and $str4
}

rule SIGNATURE_BASE_Trojan_Win32_Adupib_1 : PLATINUM
{
	meta:
		description = "Adupib SSL Backdoor"
		author = "Microsoft"
		id = "fb3b10a4-66d7-50ec-b6a5-b3c5c382ef01"
		date = "2016-04-12"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_ms_platinum.yara#L101-L122"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		hash = "d3ad0933e1b114b14c2b3a2c59d7f8a95ea0bcbd"
		logic_hash = "4d93b6a041468b51763d9497acf3d01ee59ac05f1807a6b140c557ef96d26df9"
		score = 75
		quality = 85
		tags = "PLATINUM"
		unpacked_sample_sha1 = "a80051d5ae124fd9e5cc03e699dd91c2b373978b"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$str1 = "POLL_RATE"
		$str2 = "OP_TIME(end hour)"
		$str3 = "%d:TCP:*:Enabled"
		$str4 = "%s[PwFF_cfg%d]"
		$str5 = "Fake_GetDlgItemTextW: ***value***="

	condition:
		$str1 and $str2 and $str3 and $str4 and $str5
}

