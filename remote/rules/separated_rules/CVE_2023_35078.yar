rule SIGNATURE_BASE_LOG_EXPL_Ivanti_EPMM_Mobileiron_Core_CVE_2023_35078_Jul23_1 : CVE_2023_35078
{
	meta:
		description = "Detects the successful exploitation of Ivanti Endpoint Manager Mobile (EPMM) / MobileIron Core CVE-2023-35078"
		author = "Florian Roth"
		id = "44cca0b5-3851-5786-82fd-ce3ccb566453"
		date = "2023-07-25"
		modified = "2023-12-05"
		reference = "Ivanti Endpoint Manager Mobile (EPMM) CVE-2023-35078 - Analysis Guidance"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_ivanti_epmm_mobileiron_cve_2023_35078.yar#L2-L14"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "ebc59032b7450aa438ca30170560c95550cda6ff7774b8ce1486309716da9e6c"
		score = 75
		quality = 60
		tags = "CVE-2023-35078"

	strings:
		$xr1 = /\/mifs\/aad\/api\/v2\/[^\n]{1,300} 200 [1-9][0-9]{0,60} /

	condition:
		$xr1
}

rule SIGNATURE_BASE_MAL_WAR_Ivanti_EPMM_Mobileiron_Mi_War_Aug23 : CVE_2023_35078 FILE
{
	meta:
		description = "Detects WAR file found in the Ivanti EPMM / MobileIron Core compromises exploiting CVE-2023-35078"
		author = "Florian Roth"
		id = "cd16cf29-a90d-5c3f-b66f-e9264dbf79fb"
		date = "2023-08-01"
		modified = "2023-12-05"
		reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-213a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_ivanti_epmm_mobileiron_cve_2023_35078.yar#L16-L32"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "0083727e34118d628c8507459bfb7f949f11af8197e201066e29e263e2c3f944"
		score = 85
		quality = 85
		tags = "CVE-2023-35078, FILE"
		hash1 = "6255c75e2e52d779da39367e7a7d4b8d1b3c9c61321361952dcc05819251a127"

	strings:
		$s1 = "logsPaths.txt" ascii fullword
		$s2 = "keywords.txtFirefox" ascii

	condition:
		uint16( 0 ) == 0x4b50 and filesize < 20KB and all of them
}

rule SIGNATURE_BASE_MAL_WAR_Ivanti_EPMM_Mobileiron_Logclear_JAVA_Aug23 : CVE_2023_35078 FILE
{
	meta:
		description = "Detects LogClear.class found in the Ivanti EPMM / MobileIron Core compromises exploiting CVE-2023-35078"
		author = "Florian Roth"
		id = "e1ef3bf3-0107-5ba6-a49f-71e079851a4f"
		date = "2023-08-01"
		modified = "2023-12-05"
		reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-213a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_ivanti_epmm_mobileiron_cve_2023_35078.yar#L34-L53"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "c42c2eca784d7089aab56addca11bad658a4a6c34a81ae823bd0c3dad41a1c99"
		score = 80
		quality = 85
		tags = "CVE-2023-35078, FILE"
		hash1 = "deb381c25d7a511b9eb936129eeba2c0341cff7f4bd2168b05e40ab2ee89225e"

	strings:
		$s1 = "logsPaths.txt" ascii fullword
		$s2 = "log file: %s, not read" ascii fullword
		$s3 = "/tmp/.time.tmp" ascii fullword
		$s4 = "readKeywords" ascii fullword
		$s5 = "\"----------------  ----------------" ascii fullword

	condition:
		uint16( 0 ) == 0xfeca and filesize < 20KB and 4 of them or all of them
}

