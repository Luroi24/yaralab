rule SYNACKTIV_SYNACKTIV_HKTL_Tunnel_GO_Iox_May25 : COMMODITY FILE
{
	meta:
		description = "Detects the iox tunneling tool used for port forwarding and SOCKS5 proxy"
		author = "Synacktiv, Maxence Fossat [@cybiosity]"
		id = "407d4f90-a281-4f0c-8d8e-ebe45217d3d9"
		date = "2025-05-12"
		modified = "2025-05-12"
		reference = "https://www.synacktiv.com/en/publications/open-source-toolset-of-an-ivanti-csa-attacker"
		source_url = "https://github.com/synacktiv/synacktiv-rules/blob/81b4591c31165a77783671ea63d64ac79c2e84c7/2025/offensive_tools/hktl_tunnel_go_iox.yar#L1-L49"
		license_url = "https://github.com/synacktiv/synacktiv-rules/blob/81b4591c31165a77783671ea63d64ac79c2e84c7/LICENSE.md"
		hash = "0500c9d0b91e62993447cdcf5f691092aff409eca24080ce149f34e48a0445e0"
		hash = "13c1cfb12017aa138e2f8d788dcd867806cc8fd6ae05c3ab7d886c18bcd4c48a"
		hash = "1a9524a2c39e76e0ea85abba1f0ddddc5d0d0a3a601a1b75e8d224ad93968b5e"
		hash = "1bd710dc054716bf5553abd05d282d9aeb7eb30a76320bd6be4ce2efc04b20bc"
		hash = "328570168780a5dd39e1b49db00430c02d3292ff1e8b14ff6aacce40d90d908f"
		hash = "35d83137ea70e94187a9ad9b7fa2d7b6c6b9128eb9d104380f2ac525784b9a78"
		hash = "4806fd64647e02a34dd49f9057c6bf95325dcc923764ff2ef61cbbab40ca8c48"
		hash = "4c4ec3314afe4284e4cf8bf2fdfb402820932ddcf16913a88a2b7c1d55a12a90"
		hash = "4d49ceb20ad85b117dd30f317977526e73cb5dd622705277b5cbc691972abb4b"
		hash = "63d32b6b29e5d4f8aab4b59681d853e481e858cbf1acfcb190469d8881f47aa6"
		hash = "92cc697b909c398de8533499271c9d3c2425a71feaa0d70bac7428d90423ddff"
		hash = "9480d060de29548bcf961267cec1e8c926b99dc93b65fd696bbedd308ad9f85f"
		hash = "a4139ffd12565edf5291dc5580a70e600f76695b03376e5c0130ade18a6a7bcd"
		hash = "aeddd8240c09777a84bb24b5be98e9f5465dc7638bec41fb67bbc209c3960ae1"
		hash = "b9c40960259b9b14d80c8b1cb3438913f8550fe56dbdfe314b53c7ceae77ccb0"
		hash = "ba661b3f18fa7865503523ce514367e05626c088a34c6c29269e3bde57d00ec3"
		hash = "c061952d49f03acf9e464ab927b0b6b3bc38da8caaf077e70ace77116b6d1b8c"
		hash = "c1ca82411e293ec5d16a8f81ed9466972a8ead23bd4080aaf9505baccce575ba"
		hash = "c6cf82919b809967d9d90ea73772a8aa1c1eb3bc59252d977500f64f1a0d6731"
		hash = "c8b40fbb5cd27f42c143c35b67c700f7ea42a2084418c5e2da82fb0ac094f966"
		hash = "cd5bbcf663f06003637e4aab348bbec3d4a47e53e8fa85826e161d34b86e93f8"
		hash = "d879ff9275cd62f4e7935261e17461d3a3cd1a29d65a5688bd382c47ae680ad6"
		hash = "e92c85b36d0848171ada787862413e0edd8291c8ae6a43e13b075b9ccbd53434"
		hash = "f22f2932c02bbd47ea556e15a51c20301ca7084c4b943672ade70bc49dc3e0c4"
		logic_hash = "39b68d6920b83e36942456b8ff0eeff18ae280e13e86df916c3586922d79aba8"
		score = 75
		quality = 80
		tags = "COMMODITY, FILE"
		license = "DRL-1.1"
		tlp = "TLP:CLEAR"
		pap = "PAP:CLEAR"

	strings:
		$s1 = "Forward UDP traffic between %s (encrypted: %v) and %s (encrypted: %v)"
		$s2 = "Open pipe: %s <== FWD ==> %s"
		$s3 = "Reverse socks5 server handshake ok from %s (encrypted: %v)"
		$s4 = "Recv exit signal from remote, exit now"
		$s5 = "socks consult transfer mode or parse target: %s"

	condition:
		( uint16be( 0 ) == 0x4d5a or uint32be( 0 ) == 0x7f454c46 or uint32be( 0 ) == 0xcffaedfe or uint32be( 0 ) == 0xcefaedfe ) and filesize < 5MB and all of them
}

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

rule SYNACKTIV_SYNACKTIV_HKTL_Tunnel_X64_GO_Iox_May25 : COMMODITY FILE
{
	meta:
		description = "Detects the 64-bits version of the iox tunneling tool used for port forwarding and SOCKS5 proxy"
		author = "Synacktiv, Maxence Fossat [@cybiosity]"
		id = "0b5a4689-58ea-45d5-aa14-a1455276352a"
		date = "2025-05-12"
		modified = "2025-05-12"
		reference = "https://www.synacktiv.com/en/publications/open-source-toolset-of-an-ivanti-csa-attacker"
		source_url = "https://github.com/synacktiv/synacktiv-rules/blob/81b4591c31165a77783671ea63d64ac79c2e84c7/2025/offensive_tools/hktl_tunnel_x64_go_iox.yar#L1-L96"
		license_url = "https://github.com/synacktiv/synacktiv-rules/blob/81b4591c31165a77783671ea63d64ac79c2e84c7/LICENSE.md"
		hash = "0500c9d0b91e62993447cdcf5f691092aff409eca24080ce149f34e48a0445e0"
		hash = "13c1cfb12017aa138e2f8d788dcd867806cc8fd6ae05c3ab7d886c18bcd4c48a"
		hash = "1a9524a2c39e76e0ea85abba1f0ddddc5d0d0a3a601a1b75e8d224ad93968b5e"
		hash = "1bd710dc054716bf5553abd05d282d9aeb7eb30a76320bd6be4ce2efc04b20bc"
		hash = "2457a3241ec13c77b4132d6c5923e63b51a4d05a96dc0ae249c92a43ed9c7c04"
		hash = "328570168780a5dd39e1b49db00430c02d3292ff1e8b14ff6aacce40d90d908f"
		hash = "39d51ef91e189de44696ac67590b4251a6a320719668399127096dc57cbecba3"
		hash = "4c4ec3314afe4284e4cf8bf2fdfb402820932ddcf16913a88a2b7c1d55a12a90"
		hash = "4d1e87b372af0f52b9e2d7a2ac1d223575d29de5e3c0570a96b0d2ff346214f0"
		hash = "4d49ceb20ad85b117dd30f317977526e73cb5dd622705277b5cbc691972abb4b"
		hash = "5138090aee794a08de4b0482bbe58adbd918467d14dedf51961963b324e63f89"
		hash = "63d32b6b29e5d4f8aab4b59681d853e481e858cbf1acfcb190469d8881f47aa6"
		hash = "79d6dfacfa0e0e5bc48d8d894dae261b9412b9c04a39b6ebf992cb8a5a40de95"
		hash = "82aec8846232a43a77e2b5c5a80de523b2c7f912d60bce3ac28242156395b9d0"
		hash = "92cc697b909c398de8533499271c9d3c2425a71feaa0d70bac7428d90423ddff"
		hash = "9e3cba612d5f69e27534e3d2ceb7bb6067d44ac93e5b1e74bf994a94dfd706b6"
		hash = "a4139ffd12565edf5291dc5580a70e600f76695b03376e5c0130ade18a6a7bcd"
		hash = "a8bda8e1d39ee61998381a2f0bfeb7069b19035551b8895eb48642bf98ade3d1"
		hash = "aeddd8240c09777a84bb24b5be98e9f5465dc7638bec41fb67bbc209c3960ae1"
		hash = "b9c40960259b9b14d80c8b1cb3438913f8550fe56dbdfe314b53c7ceae77ccb0"
		hash = "c061952d49f03acf9e464ab927b0b6b3bc38da8caaf077e70ace77116b6d1b8c"
		hash = "c1ca82411e293ec5d16a8f81ed9466972a8ead23bd4080aaf9505baccce575ba"
		hash = "c6cf82919b809967d9d90ea73772a8aa1c1eb3bc59252d977500f64f1a0d6731"
		hash = "c8b40fbb5cd27f42c143c35b67c700f7ea42a2084418c5e2da82fb0ac094f966"
		hash = "d3190648bc428640a721b7d3c2b05c56e855355e8b44561e3b701e80e97f7ea7"
		hash = "d879ff9275cd62f4e7935261e17461d3a3cd1a29d65a5688bd382c47ae680ad6"
		hash = "d9e868af5567a8c823f48f0f30440f1a9d77b52b2e6d785e116c450c48df9fc6"
		logic_hash = "adf3e21aa146b3def9baa73829126d8738db9cedb96e783a6baa589c77d7d518"
		score = 75
		quality = 80
		tags = "COMMODITY, FILE"
		license = "DRL-1.1"
		tlp = "TLP:CLEAR"
		pap = "PAP:CLEAR"

	strings:
		$expand_key = {
            ( 48 8B 84 24 | 48 8B 9C 24 | 48 8B 8C 24 | 48 8B BC 24 | 48 8B B4 24 | 4C 8B 84 24 | 4C 8B 8C 24 | 4C 8B 94 24 | 4C 8B 9C 24 ) ?? ?? ?? ??
            ( 48 83 F8 20 | 48 83 FB 20 | 48 83 F9 20 | 48 83 FF 20 | 48 83 FE 20 | 49 83 F8 20 | 49 83 F9 20 | 49 83 FA 20 | 49 83 FB 20 )
            ( 0F 8D ?? ?? ?? ?? | 7D ?? )
            ( 48 89 ?? | 49 89 ?? | 4C 89 ?? | 4D 89 ?? )
            ( 48 83 E0 1F | 48 83 E3 1F | 48 83 E1 1F | 48 83 E7 1F | 48 83 E6 1F | 49 83 E0 1F | 49 83 E1 1F | 49 83 E2 1F | 49 83 E3 1F | 83 E0 1F | 83 E3 1F | 83 E1 1F | 83 E7 1F | 83 E6 1F | 41 83 E0 1F | 41 83 E1 1F | 41 83 E2 1F | 41 83 E3 1F )
            ( 83 C0 E0 | 83 C3 E0 | 83 C1 E0 | 83 C7 E0 | 83 C6 E0 | 41 83 C0 E0 | 41 83 C1 E0 | 41 83 C2 E0 | 41 83 C3 E0 )
            ( F7 D8 | F7 DB | F7 D9 | F7 DF | F7 DE | 41 F7 D8 | 41 F7 D9 | 41 F7 DA | 41 F7 DB )
        }
		$shuffle = {
            ( 44 0F B6 04 | 44 0F B6 0C | 44 0F B6 14 | 44 0F B6 1C | 44 0F B6 44 | 44 0F B6 4C | 44 0F B6 54 | 44 0F B6 5C | 46 0F B6 04 | 46 0F B6 0C | 46 0F B6 14 | 46 0F B6 1C | 46 0F B6 44 | 46 0F B6 4C | 46 0F B6 54 | 46 0F B6 5C ) [1-2]
            ( 45 0F AF C0 | 45 0F AF C1 | 45 0F AF C2 | 45 0F AF C3 | 45 0F AF C8 | 45 0F AF C9 | 45 0F AF CA | 45 0F AF CB | 45 0F AF D0 | 45 0F AF D1 | 45 0F AF D2 | 45 0F AF D3 | 45 0F AF D8 | 45 0F AF D9 | 45 0F AF DA | 45 0F AF DB | 44 0F AF C0 | 44 0F AF C1 | 44 0F AF C2 | 44 0F AF C3 | 44 0F AF C8 | 44 0F AF C9 | 44 0F AF CA | 44 0F AF CB | 44 0F AF D0 | 44 0F AF D1 | 44 0F AF D2 | 44 0F AF D3 | 44 0F AF D8 | 44 0F AF D9 | 44 0F AF DA | 44 0F AF DB )
            [0-4]
            ( 41 B8 | 41 B9 | 41 BA | 41 BB ) FF FF FF FF
            ( 45 0F B6 C0 | 45 0F B6 C1 | 45 0F B6 C2 | 45 0F B6 C3 | 45 0F B6 C8 | 45 0F B6 C9 | 45 0F B6 CA | 45 0F B6 CB | 45 0F B6 D0 | 45 0F B6 D1 | 45 0F B6 D2 | 45 0F B6 D3 | 45 0F B6 D8 | 45 0F B6 D9 | 45 0F B6 DA | 45 0F B6 DB )
            [0-4]
            ( 41 89 D0 | 41 89 D1 | 41 89 D2 | 41 89 D3 | 89 D0 | 89 D1 | 89 D2 | 89 D3 )
            31 D2
            ( 66 41 F7 F0 | 66 41 F7 F1 | 66 41 F7 F2 | 66 41 F7 F3 )
            ( 41 0F AF D0 | 41 0F AF D1 | 41 0F AF D2 | 41 0F AF D3 | 44 0F AF C2 | 44 0F AF CA | 44 0F AF D2 | 44 0F AF DA | 0F AF D0 | 0F AF D1 | 0F AF D2 | 0F AF D3 | 0F AF C2 | 0F AF CA | 0F AF D2 | 0F AF DA )
            ( 31 ?? | 41 31 ?? | 44 31 ?? | 45 31 ?? )
            ( 31 ?? | 41 31 ?? | 44 31 ?? | 45 31 ?? )
            ( 44 88 04 ?F | 44 88 0C ?F | 44 88 14 ?F | 44 88 1C ?F | 44 88 04 ?7 | 44 88 0C ?7 | 44 88 14 ?7 | 44 88 1C ?7 | 88 04 ?F | 88 0C ?F | 88 14 ?F | 88 1C ?F | 88 04 ?7 | 88 0C ?7 | 88 14 ?7 | 88 1C ?7 | 44 88 04 3? | 44 88 0C 3? | 44 88 14 3? | 44 88 1C 3? | 88 04 3? | 88 0C 3? | 88 14 3? | 88 1C 3? )
        }

	condition:
		( uint16be( 0 ) == 0x4d5a or uint32be( 0 ) == 0x7f454c46 or uint32be( 0 ) == 0xcffaedfe ) and filesize < 5MB and all of them
}

rule SIGNATURE_BASE_HKTL_Win_Cobaltstrike : COMMODITY
{
	meta:
		description = "The CobaltStrike malware family."
		author = "threatintel@volexity.com"
		id = "113ba304-261f-5c59-bc56-57515c239b6d"
		date = "2021-05-25"
		modified = "2023-12-05"
		reference = "https://www.volexity.com/blog/2021/05/27/suspected-apt29-operation-launches-election-fraud-themed-phishing-campaigns/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_cobaltstrike.yar#L104-L122"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		hash = "b041efb8ba2a88a3d172f480efa098d72eef13e42af6aa5fb838e6ccab500a7c"
		logic_hash = "1e8a68050ff25f77e903af2e0a85579be1af77c64684e42e8f357eee4ae59377"
		score = 75
		quality = 85
		tags = "COMMODITY"

	strings:
		$s1 = "%s (admin)" fullword
		$s2 = {48 54 54 50 2F 31 2E 31 20 32 30 30 20 4F 4B 0D 0A 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 61 70 70 6C 69 63 61 74 69 6F 6E 2F 6F 63 74 65 74 2D 73 74 72 65 61 6D 0D 0A 43 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 3A 20 25 64 0D 0A 0D 0A 00}
		$s3 = "%02d/%02d/%02d %02d:%02d:%02d" fullword
		$s4 = "%s as %s\\%s: %d" fullword
		$s5 = "%s&%s=%s" fullword
		$s6 = "rijndael" fullword
		$s7 = "(null)"

	condition:
		all of them
}

