rule SIGNATURE_BASE_Office_As_MHTML : CVE_2012_0158 FILE
{
	meta:
		description = "Detects an Microsoft Office saved as a MHTML file (false positives are possible but rare; many matches on CVE-2012-0158)"
		author = "Florian Roth (Nextron Systems)"
		id = "21c0c3da-7295-54ad-9947-557a3180af3a"
		date = "2015-05-28"
		modified = "2023-12-05"
		reference = "https://www.trustwave.com/Resources/SpiderLabs-Blog/Malicious-Macros-Evades-Detection-by-Using-Unusual-File-Format/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/general_officemacros.yar#L28-L50"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "d5836a9c627e2e6833ea9e27526c76c00fc1fcf1fca8ea10777aa6f4bcc25053"
		score = 40
		quality = 85
		tags = "CVE-2012-0158, FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "8391d6992bc037a891d2e91fd474b91bd821fe6cb9cfc62d1ee9a013b18eca80"
		hash2 = "1ff3573fe995f35e70597c75d163bdd9bed86e2238867b328ccca2a5906c4eef"
		hash3 = "d44a76120a505a9655f0224c6660932120ef2b72fee4642bab62ede136499590"
		hash4 = "5b8019d339907ab948a413d2be4bdb3e5fdabb320f5edc726dc60b4c70e74c84"

	strings:
		$s1 = "Content-Transfer-Encoding: base64" ascii fullword
		$s2 = "Content-Type: application/x-mso" ascii fullword
		$x1 = "QWN0aXZlTWltZQA" ascii
		$x2 = "0M8R4KGxGuE" ascii

	condition:
		uint32be( 0 ) == 0x4d494d45 and all of ( $s* ) and 1 of ( $x* )
}

