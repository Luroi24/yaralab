rule SIGNATURE_BASE_RAT_Clientmesh : TORCT
{
	meta:
		description = "Detects ClientMesh RAT"
		author = "Kevin Breen <kevin@techanarchy.net> (slightly modified by Florian Roth to improve performance)"
		id = "351df33e-d3a1-5fe8-be38-edb43bc5d38f"
		date = "2014-01-06"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/ClientMesh"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/gen_rats_malwareconfig.yar#L208-L228"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "671da9586110726b1646d4365ccaa87982ec7c86b7d4d80b99dbb444496b936c"
		score = 75
		quality = 85
		tags = "TORCT"
		family = "torct"

	strings:
		$string1 = "machinedetails"
		$string2 = "MySettings"
		$string3 = "sendftppasswords"
		$string4 = "sendbrowserpasswords"
		$string5 = "arma2keyMass"
		$string6 = "keylogger"

	condition:
		all of them
}

