rule SIGNATURE_BASE_APT_Liudoor : WIN32_DLL
{
	meta:
		description = "Detects Liudoor daemon backdoor"
		author = "RSA FirstWatch"
		id = "cf7e08b8-2ccd-5828-917b-11340b4a86b1"
		date = "2015-07-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_terracotta_liudoor.yar#L1-L25"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "6f60002d0173a8ebd2b407e79377d4816e699742aedb1e0649b08fd4ca6cf359"
		score = 75
		quality = 85
		tags = "WIN32 DLL"
		hash0 = "78b56bc3edbee3a425c96738760ee406"
		hash1 = "5aa0510f6f1b0e48f0303b9a4bfc641e"
		hash2 = "531d30c8ee27d62e6fbe855299d0e7de"
		hash3 = "2be2ac65fd97ccc97027184f0310f2f3"
		hash4 = "6093505c7f7ec25b1934d3657649ef07"
		type = "Win32 DLL"

	strings:
		$string0 = "Succ"
		$string1 = "Fail"
		$string2 = "pass"
		$string3 = "exit"
		$string4 = "svchostdllserver.dll"
		$string5 = "L$,PQR"
		$string6 = "0/0B0H0Q0W0k0"
		$string7 = "QSUVWh"
		$string8 = "Ht Hu["

	condition:
		all of them
}

