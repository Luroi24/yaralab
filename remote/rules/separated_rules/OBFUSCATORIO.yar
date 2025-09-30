rule SECUINFRA_MAL_Agenttesla_Stage_1 : JAVASCRIPT AGENTTESLA OBFUSCATORIO FILE
{
	meta:
		description = "Detects the first stage of AgentTesla (JavaScript)"
		author = "SECUINFRA Falcon Team"
		id = "0a098f27-8dbc-5749-9a0d-fd0198184c7a"
		date = "2022-02-27"
		modified = "2022-02-27"
		reference = "https://bazaar.abuse.ch/sample/bd257d674778100639b298ea35550bf3bcb8b518978c502453e9839846f9bbec/"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Dropper/agent_tesla.yar#L1-L18"
		license_url = "N/A"
		hash = "bd257d674778100639b298ea35550bf3bcb8b518978c502453e9839846f9bbec"
		logic_hash = "7c21f80a02aa161ffb2edf47aff796f22aff2a563abcb0097cc86371c05e516d"
		score = 75
		quality = 45
		tags = "JAVASCRIPT, AGENTTESLA, OBFUSCATORIO, FILE"

	strings:
		$mz = "TVq"
		$a1 = ".jar"
		$a2 = "bin.base64"
		$a3 = "appdata"
		$a4 = "skype.exe"

	condition:
		filesize < 500KB and $mz and 3 of ( $a* )
}

