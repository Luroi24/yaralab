rule SIGNATURE_BASE_VULN_LNX_OMI_RCE_CVE_2021_386471_Sep21 : CVE_2021_38647 FILE
{
	meta:
		description = "Detects a Linux OMI version vulnerable to CVE-2021-38647 (OMIGOD) which enables an unauthenticated RCE"
		author = "Christian Burkard"
		id = "ca49f0cc-ea33-559c-bd4f-306a01315fce"
		date = "2021-09-16"
		modified = "2023-12-05"
		reference = "https://www.wiz.io/blog/secret-agent-exposes-azure-customers-to-unauthorized-code-execution"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/vul_cve_2021_386471_omi.yar#L1-L37"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "99fddcf763f41a08a8ef8240d544ef67b840a1b5ae709bd7efbcbcad8268e8a5"
		score = 50
		quality = 85
		tags = "CVE-2021-38647, FILE"

	strings:
		$a1 = "/opt/omi/bin/omiagent" ascii fullword
		$s1 = "OMI-1.6.8-0 - " ascii
		$s2 = "OMI-1.6.6-0 - " ascii
		$s3 = "OMI-1.6.4-1 - " ascii
		$s4 = "OMI-1.6.4-0 - " ascii
		$s5 = "OMI-1.6.2-0 - " ascii
		$s6 = "OMI-1.6.1-0 - " ascii
		$s7 = "OMI-1.5.0-0 - " ascii
		$s8 = "OMI-1.4.4-0 - " ascii
		$s9 = "OMI-1.4.3-2 - " ascii
		$s10 = "OMI-1.4.3-1 - " ascii
		$s11 = "OMI-1.4.3-0 - " ascii
		$s12 = "OMI-1.4.2-5 - " ascii
		$s13 = "OMI-1.4.2-4 - " ascii
		$s14 = "OMI-1.4.2-3 - " ascii
		$s15 = "OMI-1.4.2-2 - " ascii
		$s16 = "OMI-1.4.2-1 - " ascii
		$s17 = "OMI-1.4.1-1 - " ascii
		$s18 = "OMI-1.4.1-0 - " ascii
		$s19 = "OMI-1.4.0-6 - " ascii

	condition:
		uint32be( 0 ) == 0x7f454c46 and $a1 and 1 of ( $s* )
}

