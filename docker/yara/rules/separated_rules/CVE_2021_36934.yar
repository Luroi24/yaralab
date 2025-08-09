rule DITEKSHEN_INDICATOR_TOOL_EXP_Serioussam01 : CVE_2021_36934 FILE
{
	meta:
		description = "Detect tool variants potentially exploiting SeriousSAM / HiveNightmare CVE-2021-36934"
		author = "ditekSHen"
		id = "e8f24ae4-48fb-5ee7-9e8e-0d144bb3b046"
		date = "2024-09-25"
		modified = "2024-09-25"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/indicator_tools.yar#L1082-L1104"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "8b9de87dc073e6ba3eb36dd57b31e9749849c2e277f2bcd1c98ffc2d02861e10"
		score = 75
		quality = 25
		tags = "CVE-2021-36934, FILE"

	strings:
		$s1 = "VolumeShadowCopy" fullword wide
		$s2 = "\\\\?\\GLOBALROOT\\Device\\" fullword wide
		$s3 = "{0}\\{1}$:aad3b435b51404eeaad3b435b51404ee:{2}" fullword wide
		$s4 = "ASPNET_WP_PASSWORD" fullword wide
		$s5 = "<ParseSam>b__" ascii
		$s6 = "<DumpSecret" ascii
		$s7 = "<ParseSecret" ascii
		$s8 = "LsaSecretBlob" fullword ascii
		$s9 = "systemHive" fullword ascii
		$s10 = "ImportHiveDump" fullword ascii
		$s11 = "FindShadowVolumes" fullword ascii
		$s12 = "GetBootKey" fullword ascii
		$r1 = "[*] SAM" wide
		$r2 = "[*] SYSTEM" wide
		$r3 = "[*] SECURITY" wide

	condition:
		uint16( 0 ) == 0x5a4d and ( 6 of ( $s* ) or ( all of ( $r* ) and 3 of ( $s* ) ) )
}

