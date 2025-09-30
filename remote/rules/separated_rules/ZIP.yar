rule SIGNATURE_BASE_MAL_ZIP_Socgholish_Mar21_1 : ZIP JS SOCGHOLISH FILE
{
	meta:
		description = "Triggers on small zip files with typical SocGholish JS files in it"
		author = "Nils Kuhnert"
		id = "da35eefd-b34d-59cd-8afc-da9c78ace96e"
		date = "2021-03-29"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/crime_socgholish.yar#L1-L22"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		hash = "4f6566c145be5046b6be6a43c64d0acae38cada5eb49b2f73135b3ac3d6ba770"
		hash = "54f756fbf8c20c76af7c9f538ff861690800c622d1c9db26eb3afedc50835b09"
		hash = "dfdbec1846b74238ba3cfb8c7580c64a0fa8b14b6ed2b0e0e951cc6a9202dd8d"
		logic_hash = "6621b029f65720e468bd167fcd7429a1f7ba8975298ddbd913b13fbe9e117df2"
		score = 75
		quality = 35
		tags = "ZIP, JS, SOCGHOLISH, FILE"

	strings:
		$a1 = /\.[a-z0-9]{6}\.js/ ascii
		$a2 = "Chrome" ascii
		$a3 = "Opera" ascii
		$b1 = "Firefox.js" ascii
		$b2 = "Edge.js" ascii

	condition:
		uint16( 0 ) == 0x4b50 and filesize < 1600 and ( 2 of ( $a* ) or any of ( $b* ) )
}

