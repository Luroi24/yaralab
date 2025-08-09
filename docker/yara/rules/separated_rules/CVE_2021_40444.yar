rule SIGNATURE_BASE_EXPL_CVE_2021_40444_Document_Rels_XML : CVE_2021_40444 FILE
{
	meta:
		description = "Detects indicators found in weaponized documents that exploit CVE-2021-40444"
		author = "Jeremy Brown / @alteredbytes"
		id = "812bb68e-71ea-5a9a-8d39-ab99fdaa6c58"
		date = "2021-09-10"
		modified = "2023-12-05"
		reference = "https://twitter.com/AlteredBytes/status/1435811407249952772"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_cve_2021_40444.yar#L6-L25"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "b05c3b33c3cab2c9109d808ed197758bc987f07beee77e1f61094715e0c1a1e7"
		score = 75
		quality = 85
		tags = "CVE-2021-40444, FILE"

	strings:
		$b1 = "/relationships/oleObject" ascii
		$b2 = "/relationships/attachedTemplate" ascii
		$c1 = "Target=\"mhtml:http" nocase
		$c2 = "!x-usc:http" nocase
		$c3 = "TargetMode=\"External\"" nocase

	condition:
		uint32( 0 ) == 0x6D783F3C and filesize < 10KB and 1 of ( $b* ) and all of ( $c* )
}

rule SIGNATURE_BASE_EXPL_MAL_Maldoc_OBFUSCT_MHTML_Sep21_1 : CVE_2021_40444 FILE
{
	meta:
		description = "Detects suspicious office reference files including an obfuscated MHTML reference exploiting CVE-2021-40444"
		author = "Florian Roth (Nextron Systems)"
		id = "781cfd61-d5ac-58e5-868f-dbd2a2df3500"
		date = "2021-09-18"
		modified = "2023-12-05"
		reference = "https://twitter.com/decalage2/status/1438946225190014984?s=20"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_cve_2021_40444.yar#L27-L41"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		hash = "84674acffba5101c8ac518019a9afe2a78a675ef3525a44dceddeed8a0092c69"
		logic_hash = "11a73572970d2d85d308330119a2c5243f2848ae78a861decdb0cdbde0d9d1c2"
		score = 90
		quality = 85
		tags = "CVE-2021-40444, FILE"

	strings:
		$h1 = "<?xml " ascii wide
		$s1 = "109;&#104;&#116;&#109;&#108;&#58;&#104;&#116;&#109;&#108" ascii wide

	condition:
		filesize < 25KB and all of them
}

rule SIGNATURE_BASE_EXPL_XML_Encoded_CVE_2021_40444 : CVE_2021_40444 FILE
{
	meta:
		description = "Detects possible CVE-2021-40444 with no encoding, HTML/XML entity (and hex notation) encoding, or all 3"
		author = "James E.C, Proofpoint"
		id = "4bf9ec64-c662-5c8f-9e58-12a7412ef07d"
		date = "2021-09-18"
		modified = "2021-09-19"
		reference = "https://twitter.com/sudosev/status/1439205606129377282"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_cve_2021_40444.yar#L44-L61"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		hash = "13de9f39b1ad232e704b5e0b5051800fcd844e9f661185ace8287a23e9b3868e"
		hash = "84674acffba5101c8ac518019a9afe2a78a675ef3525a44dceddeed8a0092c69"
		logic_hash = "feaeadd8e7e262f191ea0c2f85377531208262e5ac19d6706703e62cf8b4ec90"
		score = 70
		quality = 60
		tags = "CVE-2021-40444, FILE"

	strings:
		$h1 = "<?xml " ascii wide
		$t_xml_r = /Target[\s]{0,20}=[\s]{0,20}\["']([Mm]|&#(109|77|x6d|x4d);)([Hh]|&#(104|72|x68|x48);)([Tt]|&#(116|84|x74|x54);)([Mm]|&#(109|77|x6d|x4d);)([Ll]|&#(108|76|x6c|x4c);)(:|&#58;|&#x3a)/
		$t_mode_r = /TargetMode[\s]{0,20}=[\s]{0,20}\["']([Ee]|&#(x45|x65|69|101);)([Xx]|&#(x58|x78|88|120);)([Tt]|&#(x74|x54|84|116);)/

	condition:
		filesize < 500KB and $h1 and all of ( $t_* )
}

