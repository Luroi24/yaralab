rule SYNACKTIV_SYNACKTIV_WEBSHELL_ASPX_Suo5_May25 : WEBSHELL COMMODITY FILE
{
	meta:
		description = "Detects the .NET version of the suo5 webshell"
		author = "Synacktiv, Maxence Fossat [@cybiosity]"
		id = "d30a7232-f00b-45ab-9419-f43b1611445a"
		date = "2025-05-12"
		modified = "2025-05-12"
		reference = "https://www.synacktiv.com/en/publications/open-source-toolset-of-an-ivanti-csa-attacker"
		source_url = "https://github.com/synacktiv/synacktiv-rules/blob/81b4591c31165a77783671ea63d64ac79c2e84c7/2025/offensive_tools/webshell_aspx_suo5.yar#L1-L46"
		license_url = "https://github.com/synacktiv/synacktiv-rules/blob/81b4591c31165a77783671ea63d64ac79c2e84c7/LICENSE.md"
		hash = "06710575d20cacd123f83eb82994879367e07f267e821873bf93f4db6312a97b"
		hash = "e6979d7df0876679fc2481aa68fcec5b6ddc82d854f63da2bddb674064384f9a"
		hash = "3bbbef1b4ead98c61fba60dd6291fe1ff08f5eac54d820e47c38d348e4a7b1ec"
		hash = "345c383dd439eb523b01e1087a0866e13f04ff53bb8cc11f3c70b4a382f10c7e"
		hash = "838840dd76ff34cee45996fdc9a87856c9a0f14138e65cb9eb6603ed157d1515"
		hash = "d9657ac8dd562bdd39e8fcc1fff37ddced10f7f3f118d9cd4da6118a223dcc45"
		logic_hash = "68dc29b2cedc26e638eaa12bf2a2d0415de323097baf5ea61dba52bd20b5beee"
		score = 75
		quality = 80
		tags = "WEBSHELL, COMMODITY, FILE"
		license = "DRL-1.1"
		tlp = "TLP:CLEAR"
		pap = "PAP:CLEAR"

	strings:
		$user_agent = ".Equals(\"Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.1.2.3\")" ascii
		$header = "Response.AddHeader(\"X-Accel-Buffering\", \"no\")" ascii
		$xor = /= \(byte\)\(\w{1,1023}\[\w{1,1023}\] \^ \w{1,1023}\);/
		$s1 = "Request.Headers.Get(\"User-Agent\")" ascii
		$s2 = "if (Request.ContentType.Equals(\"application/plain\"))" ascii
		$s3 = "Response.ContentType = \"application/octet-stream\";" ascii
		$s4 = "= Request.BinaryRead(Request.ContentLength);" ascii
		$s5 = "= Response.OutputStream;" ascii
		$s6 = "new TcpClient()" ascii
		$s7 = ".BeginConnect(" ascii
		$s8 = ".GetStream().Write(" ascii
		$s9 = "new BinaryWriter(" ascii
		$s10 = "new BinaryReader(" ascii
		$s11 = ".ReadBytes(4)" ascii
		$s12 = "BitConverter.GetBytes((Int32)" ascii
		$s13 = "BitConverter.ToInt32(" ascii
		$s14 = "Array.Reverse(" ascii
		$s15 = "new Random().NextBytes(" ascii

	condition:
		filesize < 100KB and ( $user_agent or ( ( $header or $xor ) and 8 of ( $s* ) ) or 12 of ( $s* ) )
}

rule SIGNATURE_BASE_APT_WEBSHELL_Tiny_Webshell : APT HAFNIUM WEBSHELL FILE
{
	meta:
		description = "Detects WebShell Injection"
		author = "Markus Neis,Swisscom"
		id = "aa2fcecc-4c8b-570d-a81a-5dfb16c04e05"
		date = "2021-03-05"
		modified = "2023-12-05"
		reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_hafnium.yar#L67-L82"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		hash = "099c8625c58b315b6c11f5baeb859f4c"
		logic_hash = "9309f9b57353b6fe292048d00794699a8637a3e6e429c562fb36c7e459003a3b"
		score = 75
		quality = 85
		tags = "APT, HAFNIUM, WEBSHELL, FILE"

	strings:
		$x1 = "<%@ Page Language=\"Jscript\" Debug=true%>"
		$s1 = "=Request.Form(\""
		$s2 = "eval("

	condition:
		filesize < 300 and all of ( $s* ) and $x1
}

rule SIGNATURE_BASE_WEBSHELL_ASPX_Simpleseesharp : WEBSHELL UNCLASSIFIED FILE
{
	meta:
		description = "A simple ASPX Webshell that allows an attacker to write further files to disk."
		author = "threatintel@volexity.com"
		id = "469fdf5c-e09e-5d44-a2e6-0864dcd0e18a"
		date = "2021-03-01"
		modified = "2023-12-05"
		reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_hafnium.yar#L121-L136"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		hash = "893cd3583b49cb706b3e55ecb2ed0757b977a21f5c72e041392d1256f31166e2"
		logic_hash = "6f62249a68bae94e5cbdb4319ea5cde9dc071ec7a4760df3aafe78bc1e072c30"
		score = 75
		quality = 85
		tags = "WEBSHELL, UNCLASSIFIED, FILE"

	strings:
		$header = "<%@ Page Language=\"C#\" %>"
		$body = "<% HttpPostedFile thisFile = Request.Files[0];thisFile.SaveAs(Path.Combine"

	condition:
		$header at 0 and $body and filesize < 1KB
}

rule SIGNATURE_BASE_Webshell_And_Exploit_CN_APT_HK : WEBSHELL
{
	meta:
		description = "Webshell and Exploit Code in relation with APT against Honk Kong protesters"
		author = "Florian Roth (Nextron Systems)"
		id = "eb37a22b-4e8a-5986-bd47-4ef5b4986f47"
		date = "2014-10-10"
		modified = "2025-03-29"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/thor-webshells.yar#L9044-L9059"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "ec3f1e985585e1bf77a46e971a20cd127064a64467761a5a570548dd63ec57e2"
		score = 50
		quality = 85
		tags = "WEBSHELL"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$a0 = "<script language=javascript src=http://java-se.com/o.js</script>" fullword
		$s0 = "<span style=\"font:11px Verdana;\">Password: </span><input name=\"password\" type=\"password\" size=\"20\">"
		$s1 = "<input type=\"hidden\" name=\"doing\" value=\"login\">"

	condition:
		$a0 or ( all of ( $s* ) )
}

