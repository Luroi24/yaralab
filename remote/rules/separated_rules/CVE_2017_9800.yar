rule SIGNATURE_BASE_Git_CVE_2017_9800_Poc : CVE_2017_9800 FILE
{
	meta:
		description = "Detects a CVE-2017-9800 exploitation attempt"
		author = "Florian Roth (Nextron Systems)"
		id = "1692eec4-a9af-5d00-97b8-badbe0ba0711"
		date = "2017-08-11"
		modified = "2023-12-05"
		reference = "https://twitter.com/mzbat/status/895811803325898753"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/exploit_cve_2017_9800.yar#L2-L17"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "1cfd0c5cb255d3ca63917c41c092df70d68b04f5d210a66abd5e35e509ff4beb"
		score = 60
		quality = 85
		tags = "CVE-2017-9800, FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "git clone ssh://-oProxyCommand=" ascii
		$s2 = "git clone http://-" ascii
		$s3 = "git clone https://-" ascii

	condition:
		filesize < 200KB and 1 of them
}

