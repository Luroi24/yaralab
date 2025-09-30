rule VOLEXITY_Apt_Webshell_Aspx_Glasstoken : UTA0178 FILE MEMORY
{
	meta:
		description = "Detection for a custom webshell seen on Exchange server. The webshell contains two functions, the first is to act as a Tunnel, using code borrowed from reGeorg, the second is custom code to execute arbitrary .NET code."
		author = "threatintel@volexity.com"
		id = "2f07748a-a52f-5ac7-9d3e-50fd3ecea271"
		date = "2023-12-12"
		modified = "2024-09-30"
		reference = "TIB-20231215"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-01-10 Ivanti Connect Secure/indicators/yara.yar#L26-L52"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "6b8183ac1e87a86c58760db51f767ed278cc0c838ed89e7435af7d0373e58b26"
		score = 75
		quality = 30
		tags = "UTA0178, FILE, MEMORY"
		hash1 = "26cbb54b1feb75fe008e36285334d747428f80aacdb57badf294e597f3e9430d"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 9994
		version = 6

	strings:
		$s1 = "=Convert.FromBase64String(System.Text.Encoding.Default.GetString(" ascii
		$re = /Assembly\.Load\(errors\)\.CreateInstance\("[a-z0-9A-Z]{4,12}"\).GetHashCode\(\);/

	condition:
		for any i in ( 0 .. math.min ( #s1 , 100 ) ) : ( $re in ( @s1 [ i ] .. @s1 [ i ] + 512 ) )
}

