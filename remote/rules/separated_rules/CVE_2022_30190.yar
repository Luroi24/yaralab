rule SIGNATURE_BASE_SUSP_PS1_Msdt_Execution_May22 : CVE_2022_30190 FILE
{
	meta:
		description = "Detects suspicious calls of msdt.exe as seen in CVE-2022-30190 / Follina exploitation"
		author = "Nasreddine Bencherchali, Christian Burkard"
		id = "d48d9ac9-7d3e-51c9-b017-22829ae5ecfd"
		date = "2022-05-31"
		modified = "2025-03-21"
		reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/gen_doc_follina.yar#L2-L36"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "9b8a061de4210d23e58b5190a300ee331273fc98f357156a0bb1d79f9f2b49b1"
		score = 65
		quality = 85
		tags = "CVE-2022-30190, FILE"

	strings:
		$a = "PCWDiagnostic" ascii wide fullword
		$sa1 = "msdt.exe" ascii wide
		$sa2 = "msdt " ascii wide
		$sa3 = "ms-msdt" ascii wide
		$sb1 = "/af " ascii wide
		$sb2 = "-af " ascii wide
		$sb3 = "IT_BrowseForFile=" ascii wide
		$fp1 = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00
               46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00
               00 00 70 00 63 00 77 00 72 00 75 00 6E 00 2E 00
               65 00 78 00 65 00 }
		$fp2 = "FilesFullTrust" wide
		$fp3 = "Cisco Spark" ascii wide
		$fp4 = "author: " ascii

	condition:
		filesize < 10MB and $a and 1 of ( $sa* ) and 1 of ( $sb* ) and not 1 of ( $fp* ) and not uint8( 0 ) == 0x7B
}

rule SIGNATURE_BASE_SUSP_Doc_Wordxmlrels_May22 : CVE_2022_30190 FILE
{
	meta:
		description = "Detects a suspicious pattern in docx document.xml.rels file as seen in CVE-2022-30190 / Follina exploitation"
		author = "Tobias Michalski, Christian Burkard, Wojciech Cieslak"
		id = "304c4816-b2f6-5319-9fe9-8f74bdb82ad0"
		date = "2022-05-30"
		modified = "2022-06-20"
		reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/gen_doc_follina.yar#L38-L60"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		hash = "62f262d180a5a48f89be19369a8425bec596bc6a02ed23100424930791ae3df0"
		logic_hash = "c9846f8c2c1724792de14ab4de0064f951a8faaf01cc27d873e600f29d59c842"
		score = 70
		quality = 85
		tags = "CVE-2022-30190, FILE"

	strings:
		$a1 = "<Relationships" ascii
		$a2 = "TargetMode=\"External\"" ascii
		$x1 = ".html!" ascii
		$x2 = ".htm!" ascii
		$x3 = "%2E%68%74%6D%6C%21" ascii
		$x4 = "%2E%68%74%6D%21" ascii

	condition:
		filesize < 50KB and all of ( $a* ) and 1 of ( $x* )
}

rule SIGNATURE_BASE_SUSP_Doc_RTF_Externalresource_May22 : CVE_2022_30190 FILE
{
	meta:
		description = "Detects a suspicious pattern in RTF files which downloads external resources as seen in CVE-2022-30190 / Follina exploitation"
		author = "Tobias Michalski, Christian Burkard"
		id = "71bb97e0-ec12-504c-a1f6-25039ac91c86"
		date = "2022-05-30"
		modified = "2022-05-31"
		reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/gen_doc_follina.yar#L62-L78"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "c841e0c1ff78bf8dade5f573a7452b16a7f447cfc19417704b727684a8f3d3ff"
		score = 70
		quality = 85
		tags = "CVE-2022-30190, FILE"

	strings:
		$s1 = " LINK htmlfile \"http" ascii
		$s2 = ".html!\" " ascii

	condition:
		uint32be( 0 ) == 0x7B5C7274 and filesize < 300KB and all of them
}

rule SIGNATURE_BASE_EXPL_Follina_CVE_2022_30190_Msdt_Msprotocoluri_May22 : CVE_2022_30190 FILE
{
	meta:
		description = "Detects the malicious usage of the ms-msdt URI as seen in CVE-2022-30190 / Follina exploitation"
		author = "Tobias Michalski, Christian Burkard"
		id = "62e67c25-a420-5dac-9d1c-b0648ea6b574"
		date = "2022-05-30"
		modified = "2022-07-18"
		reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/gen_doc_follina.yar#L80-L98"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "d56820737951f97606749c74025589e6a8ecbe70cfff069492368b2ba8528a7d"
		score = 80
		quality = 60
		tags = "CVE-2022-30190, FILE"
		hash1 = "4a24048f81afbe9fb62e7a6a49adbd1faf41f266b5f9feecdceb567aec096784"
		hash2 = "778cbb0ee4afffca6a0b788a97bc2f4855ceb69ddc5eaa230acfa2834e1aeb07"

	strings:
		$re1 = /location\.href\s{0,20}=\s{0,20}"ms-msdt:/
		$a1 = "%6D%73%2D%6D%73%64%74%3A%2F" ascii

	condition:
		filesize > 3KB and filesize < 100KB and 1 of them
}

rule SIGNATURE_BASE_SUSP_DOC_RTF_Externalresource_EMAIL_Jun22 : CVE_2022_30190 FILE
{
	meta:
		description = "Detects a suspicious pattern in RTF files which downloads external resources as seen in CVE-2022-30190 / Follina exploitation inside e-mail attachment"
		author = "Christian Burkard"
		id = "3ddc838c-8520-5572-9652-8cb823f83e27"
		date = "2022-06-01"
		modified = "2025-03-21"
		reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/gen_doc_follina.yar#L194-L220"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "73e76bd80f77640c0d8d47ebb7903eb9cc23336fbe653e7d008cae6a0de7c45b"
		score = 70
		quality = 85
		tags = "CVE-2022-30190, FILE"

	strings:
		$sa1 = "PFJlbGF0aW9uc2hpcH" ascii
		$sa2 = "xSZWxhdGlvbnNoaXBz" ascii
		$sa3 = "8UmVsYXRpb25zaGlwc" ascii
		$sb1 = "VGFyZ2V0TW9kZT0iRXh0ZXJuYWwi" ascii
		$sb2 = "RhcmdldE1vZGU9IkV4dGVybmFsI" ascii
		$sb3 = "UYXJnZXRNb2RlPSJFeHRlcm5hbC" ascii
		$sc1 = "Lmh0bWwhI" ascii
		$sc2 = "5odG1sIS" ascii
		$sc3 = "uaHRtbCEi" ascii

	condition:
		filesize < 400KB and 1 of ( $sa* ) and 1 of ( $sb* ) and 1 of ( $sc* )
}

rule SIGNATURE_BASE_SUSP_Msdt_Artefact_Jun22_2 : CVE_2022_30190 FILE
{
	meta:
		description = "Detects suspicious pattern in msdt diagnostics log (e.g. CVE-2022-30190 / Follina exploitation)"
		author = "Christian Burkard"
		id = "aa2a4bd7-2094-5652-a088-f58d0c7d3f62"
		date = "2022-06-01"
		modified = "2022-07-29"
		reference = "https://twitter.com/nas_bench/status/1531718490494844928"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/gen_doc_follina.yar#L222-L241"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "e18f6405f0411128335336e65dda4ed2b6be6e9ad47b94646ececf0479fbe967"
		score = 75
		quality = 85
		tags = "CVE-2022-30190, FILE"

	strings:
		$a1 = "<ScriptError><Data id=\"ScriptName\" name=\"Script\">TS_ProgramCompatibilityWizard.ps1" ascii
		$x1 = "/../../" ascii
		$x2 = "$(Invoke-Expression" ascii
		$x3 = "$(IEX(" ascii nocase

	condition:
		uint32( 0 ) == 0x6D783F3C and $a1 and 1 of ( $x* )
}

rule SIGNATURE_BASE_SUSP_LNK_Follina_Jun22 : CVE_2022_30190 FILE
{
	meta:
		description = "Detects LNK files with suspicious Follina/CVE-2022-30190 strings"
		author = "Paul Hager"
		id = "d331d584-2ab3-5275-b435-6129c7291417"
		date = "2022-06-02"
		modified = "2025-03-21"
		reference = "https://twitter.com/gossithedog/status/1531650897905950727"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/gen_doc_follina.yar#L243-L261"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "0b63bb266b968987b2b5a83c9429e96acbd57e12178e4f5fd5894b23d1aaa237"
		score = 75
		quality = 85
		tags = "CVE-2022-30190, FILE"

	strings:
		$sa1 = "msdt.exe" ascii wide
		$sa2 = "msdt " ascii wide
		$sa3 = "ms-msdt:" ascii wide
		$sb = "IT_BrowseForFile=" ascii wide

	condition:
		filesize < 5KB and uint16( 0 ) == 0x004c and uint32( 4 ) == 0x00021401 and 1 of ( $sa* ) and $sb
}

