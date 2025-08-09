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

rule SIGNATURE_BASE_EXT_MAL_JS_Socgholish_Mar21_1 : JS SOCGHOLISH FILE
{
	meta:
		description = "Triggers on SocGholish JS files"
		author = "Nils Kuhnert"
		id = "3ed7d2da-569b-5851-a821-4a3cda3e13ce"
		date = "2021-03-29"
		modified = "2023-01-02"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/crime_socgholish.yar#L25-L51"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		hash = "7ccbdcde5a9b30f8b2b866a5ca173063dec7bc92034e7cf10e3eebff017f3c23"
		hash = "f6d738baea6802cbbb3ae63b39bf65fbd641a1f0d2f0c819a8c56f677b97bed1"
		hash = "c7372ffaf831ad963c0a9348beeaadb5e814ceeb878a0cc7709473343d63a51c"
		logic_hash = "08218ae952577a6ac936de875236cdc3ae32e3aaccd2196b7f43e80d7e748584"
		score = 75
		quality = 85
		tags = "JS, SOCGHOLISH, FILE"

	strings:
		$s1 = "new ActiveXObject('Scripting.FileSystemObject');" ascii
		$s2 = "['DeleteFile']" ascii
		$s3 = "['WScript']['ScriptFullName']" ascii
		$s4 = "['WScript']['Sleep'](1000)" ascii
		$s5 = "new ActiveXObject('MSXML2.XMLHTTP')" ascii
		$s6 = "this['eval']" ascii
		$s7 = "String['fromCharCode']"
		$s8 = "2), 16)," ascii
		$s9 = "= 103," ascii
		$s10 = "'00000000'" ascii

	condition:
		filesize > 3KB and filesize < 5KB and 8 of ( $s* )
}

