rule R3C0NST_Exploit_Outlook_CVE_2023_23397 : CVE_2023_23397 FILE
{
	meta:
		description = "Detects Outlook appointments exploiting CVE-2023-23397"
		author = "Frank Boldewin"
		id = "7e355e5f-93ca-561d-9a12-f73f1d429e4d"
		date = "2023-03-19"
		modified = "2023-03-25"
		reference = "https://www.mdsec.co.uk/2023/03/exploiting-cve-2023-23397-microsoft-outlook-elevation-of-privilege-vulnerability/"
		source_url = "https://github.com/fboldewin/YARA-rules//blob/54e9e6899b258b72074b2b4db6909257683240c2/Exploit_Outlook_CVE_2023_23397.yar#L1-L30"
		license_url = "N/A"
		logic_hash = "1847e8223b2f6d3ec5108e15ee46ef031ee1e26d3a5e8ed4a70c77b031f6a5b6"
		score = 75
		quality = 86
		tags = "CVE-2023-23397, FILE"
		Author = "Frank Boldewin (@r3c0nst)"
		Hash1 = "078b5023cae7bd784a84ec4ee8df305ee7825025265bf2ddc1f5238c3e432f5f"
		Hash2 = "a034427fd8524fd62380c881c30b9ab483535974ddd567556692cffc206809d1"
		Hash3 = "e7a1391dd53f349094c1235760ed0642519fd87baf740839817d47488b9aef02"
		Hash4 = "1543677037fa339877e1d6ef2d077f94613afbcd6434d7181a18df74aca7742b"

	strings:
		$ipmtask = "IPM.Task" wide ascii
		$ipmappointment = "IPM.Appointment" wide ascii
		$ipmtaskb64 = "IPM.Task" base64 base64wide
		$ipmappointmentb64 = "IPM.Appointment" base64 base64wide
		$unc_path1 = { 5C 00 5C 00 (3? 00 2E|3? 00 3? 00 2E|3? 00 3? 00 3? 00 2E) 00 (3? 00 2E|3? 00 3? 00 2E|3? 00 3? 00 3? 00 2E) 00 (3? 00 2E|3? 00 3? 00 2E|3? 00 3? 00 3? 00 2E) 00 (3? 00|3? 00 3? 00|3? 00 3? 00 3? 00) }
		$unc_path2 = { 5C 5C (3? 2E|3? 3? 2E|3? 3? 3? 2E) (3? 2E|3? 3? 2E|3? 3? 3? 2E) (3? 2E|3? 3? 2E|3? 3? 3? 2E) (3?|3? 3?|3? 3? 3?) }
		$unc_a = "\x00\x00\x00\x5c\x5c" base64
		$unc_w = "\x00\x00\x5c\x00\x5c" base64wide
		$mail1 = "from:" ascii wide nocase
		$mail2 = "received:" ascii wide nocase

	condition:
		(( uint32be( 0 ) == 0xD0CF11E0 or uint32be( 0 ) == 0x789F3E22 ) or ( all of ( $mail* ) ) ) and ( ( $ipmtask or $ipmappointment ) or ( $ipmtaskb64 or $ipmappointmentb64 ) ) and ( ( $unc_path1 or $unc_path2 ) or ( $unc_a or $unc_w ) )
}

rule DELIVRTO_SUSP_Msg_CVE_2023_23397_Mar23 : CVE_2023_23397 FILE
{
	meta:
		description = "MSG file with a PidLidReminderFileParameter property, potentially exploiting CVE-2023-23397"
		author = "delivr.to"
		id = "a0ede2d3-7789-5662-9575-5d0a5cf4457c"
		date = "2023-03-15"
		modified = "2023-03-15"
		reference = "https://www.mdsec.co.uk/2023/03/exploiting-cve-2023-23397-microsoft-outlook-elevation-of-privilege-vulnerability/"
		source_url = "https://github.com/delivr-to/detections/blob/376762d71eb1777874d366136595994378416ef5/yara-rules/msg_cve_2023_23397.yar#L1-L20"
		license_url = "N/A"
		logic_hash = "0476cf7f93c4f6cc48c19933f31360b62fe5e339f6a2a31dee8ad95f83ce67d7"
		score = 60
		quality = 80
		tags = "CVE-2023-23397, FILE"

	strings:
		$app = { 02 20 06 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
		$rfp = { 1F 85 00 00 }

	condition:
		uint32be( 0 ) == 0xD0CF11E0 and uint32be( 4 ) == 0xA1B11AE1 and $app and $rfp
}

rule SIGNATURE_BASE_SUSP_EXPL_Msg_CVE_2023_23397_Mar23 : CVE_2023_23397 FILE
{
	meta:
		description = "MSG file with a PidLidReminderFileParameter property, potentially exploiting CVE-2023-23397"
		author = "delivr.to, modified by Florian Roth, Nils Kuhnert, Arnim Rupp, marcin@ulikowski.pl"
		id = "0a4d7bbe-1e17-5240-ad0f-29511752b267"
		date = "2023-03-15"
		modified = "2024-12-03"
		reference = "https://www.mdsec.co.uk/2023/03/exploiting-cve-2023-23397-microsoft-outlook-elevation-of-privilege-vulnerability/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_outlook_cve_2023_23397.yar#L1-L39"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		hash = "47fee24586cd2858cfff2dd7a4e76dc95eb44c8506791ccc2d59c837786eafe3"
		hash = "582442ee950d546744f2fa078adb005853a453e9c7f48c6c770e6322a888c2cf"
		hash = "6c0087a5cbccb3c776a471774d1df10fe46b0f0eb11db6a32774eb716e1b7909"
		hash = "7fb7a2394e03cc4a9186237428a87b16f6bf1b66f2724aea1ec6a56904e5bfad"
		hash = "eedae202980c05697a21a5c995d43e1905c4b25f8ca2fff0c34036bc4fd321fa"
		logic_hash = "fbbbaf5cd858078adddc80b9c9c56cb448613da28206a91778d22cd1cf64655e"
		score = 60
		quality = 85
		tags = "CVE-2023-23397, FILE"

	strings:
		$psetid_app = { 02 20 06 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
		$psetid_meeting = { 90 DA D8 6E 0B 45 1B 10 98 DA 00 AA 00 3F 13 05 }
		$psetid_task = { 03 20 06 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
		$rfp = { 1F 85 00 00 }
		$u1 = { 00 00 5C 00 5C 00 }
		$fp_msi1 = {84 10 0C 00 00 00 00 00 C0 00 00 00 00 00 00 46}
		$fp_asd = "theme/theme1.xml"

	condition:
		uint32be( 0 ) == 0xD0CF11E0 and uint32be( 4 ) == 0xA1B11AE1 and 1 of ( $psetid* ) and $rfp and $u1 and not 1 of ( $fp* )
}

rule SIGNATURE_BASE_EXPL_SUSP_Outlook_CVE_2023_23397_Exfil_IP_Mar23 : CVE_2023_23397 FILE
{
	meta:
		description = "Detects suspicious .msg file with a PidLidReminderFileParameter property exploiting CVE-2023-23397 (modified delivr.to rule - more specific = less FPs but limited to exfil using IP addresses, not FQDNs)"
		author = "delivr.to, Florian Roth, Nils Kuhnert, Arnim Rupp, marcin@ulikowski.pl"
		id = "d85bf1d9-aebe-5f8c-9dd4-c509f64e221a"
		date = "2023-03-15"
		modified = "2023-03-18"
		reference = "https://www.mdsec.co.uk/2023/03/exploiting-cve-2023-23397-microsoft-outlook-elevation-of-privilege-vulnerability/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_outlook_cve_2023_23397.yar#L41-L81"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		hash = "47fee24586cd2858cfff2dd7a4e76dc95eb44c8506791ccc2d59c837786eafe3"
		hash = "582442ee950d546744f2fa078adb005853a453e9c7f48c6c770e6322a888c2cf"
		hash = "6c0087a5cbccb3c776a471774d1df10fe46b0f0eb11db6a32774eb716e1b7909"
		hash = "7fb7a2394e03cc4a9186237428a87b16f6bf1b66f2724aea1ec6a56904e5bfad"
		hash = "eedae202980c05697a21a5c995d43e1905c4b25f8ca2fff0c34036bc4fd321fa"
		hash = "e7a1391dd53f349094c1235760ed0642519fd87baf740839817d47488b9aef02"
		logic_hash = "a8e8326f5aaa29b449f9203623e03d3d3a1d176bb764171d860afc510a1732e6"
		score = 75
		quality = 85
		tags = "CVE-2023-23397, FILE"

	strings:
		$psetid_app = { 02 20 06 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
		$psetid_meeting = { 90 DA D8 6E 0B 45 1B 10 98 DA 00 AA 00 3F 13 05 }
		$psetid_task = { 03 20 06 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
		$rfp = { 1F 85 00 00 }
		$u1 = { 5C 00 5C 00 (3? 00 2E|3? 00 3? 00 2E|3? 00 3? 00 3? 00 2E) 00 (3? 00 2E|3? 00 3? 00 2E|3? 00 3? 00 3? 00 2E) 00 (3? 00 2E|3? 00 3? 00 2E|3? 00 3? 00 3? 00 2E) 00 (3? 00 3? 00 3? 00|3? 00 3? 00|3? 00) }
		$u2 = { 00 5C 5C (3? 2E|3? 3? 2E|3? 3? 3? 2E) (3? 2E|3? 3? 2E|3? 3? 3? 2E) (3? 2E|3? 3? 2E|3? 3? 3? 2E) (3? 3? 3?|3? 3?|3?) }
		$fp_msi1 = {84 10 0C 00 00 00 00 00 C0 00 00 00 00 00 00 46}

	condition:
		( uint16( 0 ) == 0xCFD0 and 1 of ( $psetid* ) or uint32be( 0 ) == 0x789F3E22 ) and any of ( $u* ) and $rfp and not 1 of ( $fp* )
}

rule SIGNATURE_BASE_EXPL_SUSP_Outlook_CVE_2023_23397_SMTP_Mail_Mar23 : CVE_2023_23397
{
	meta:
		description = "Detects suspicious *.eml files that include TNEF content that possibly exploits CVE-2023-23397. Lower score than EXPL_SUSP_Outlook_CVE_2023_23397_Exfil_IP_Mar23 as we're only looking for UNC prefix."
		author = "Nils Kuhnert"
		id = "922fae73-520d-5659-8331-f242c7c55810"
		date = "2023-03-17"
		modified = "2023-03-24"
		reference = "https://twitter.com/wdormann/status/1636491612686622723"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_outlook_cve_2023_23397.yar#L83-L112"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "a361eb3abf98655f43efff2a5399f112d9ac2d23df85a642ab744c78e98330e0"
		score = 60
		quality = 85
		tags = "CVE-2023-23397"

	strings:
		$mail1 = { 0A 46 72 6F 6D 3A 20 }
		$mail2 = { 0A 54 6F 3A }
		$mail3 = { 0A 52 65 63 65 69 76 65 64 3A }
		$tnef1 = "Content-Type: application/ms-tnef" ascii
		$tnef2 = "\x78\x9f\x3e\x22" base64
		$ipm1 = "IPM.Task" base64
		$ipm2 = "IPM.Appointment" base64
		$unc = "\x00\x00\x00\x5c\x5c" base64

	condition:
		all of ( $mail* ) and all of ( $tnef* ) and 1 of ( $ipm* ) and $unc
}

