rule SIGNATURE_BASE_APT_HAFNIUM_Forensicartefacts_WER_Mar21_1 : CVE_2021_26857 FILE
{
	meta:
		description = "Detects a Windows Error Report (WER) that indicates and exploitation attempt of the Exchange server as described in CVE-2021-26857 after the corresponding patches have been applied. WER files won't be written upon successful exploitation before applying the patch. Therefore, this indicates an unsuccessful attempt."
		author = "Florian Roth (Nextron Systems)"
		id = "06771101-10ce-5d6b-99f7-a321aade7f69"
		date = "2021-03-07"
		modified = "2023-12-05"
		reference = "https://twitter.com/cyb3rops/status/1368471533048446976"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_hafnium.yar#L235-L250"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "2e135cb47f9fb5ca19ee1058fa6b4f39c098d2dfbab69bc19e80412ab695f126"
		score = 40
		quality = 85
		tags = "CVE-2021-26857, FILE"

	strings:
		$s1 = "AppPath=c:\\windows\\system32\\inetsrv\\w3wp.exe" wide fullword
		$s7 = ".Value=w3wp#MSExchangeECPAppPool" wide

	condition:
		uint16( 0 ) == 0xfeff and filesize < 8KB and all of them
}

