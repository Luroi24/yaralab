rule VOLEXITY_Apt_Malware_Linux_Disgomoji_Modules : TRANSPARENTJASMINE FILE MEMORY
{
	meta:
		description = "Detects DISGOMOJI modules using strings in the ELF."
		author = "threatintel@volexity.com"
		id = "b9e4ecdc-9b02-546f-9b79-947cb6b1f99a"
		date = "2024-02-22"
		modified = "2024-07-05"
		reference = "TIB-20240229"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L1-L24"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "7880288e3230b688b780bdfbac2b0761fd7831b7df233672c2242c21a86e1297"
		score = 75
		quality = 80
		tags = "TRANSPARENTJASMINE, FILE, MEMORY"
		hash1 = "2abaae4f6794131108adf5b42e09ee5ce24769431a0e154feabe6052cfe70bf3"
		os = "linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10270
		version = 6

	strings:
		$s1 = "discord-c2/test/main/finalizing/Deliveries/ob_Delivery.go" wide ascii
		$s2 = "discord-c2/test/main/finalizing/WAN_Conf.go" wide ascii

	condition:
		any of them
}

rule VOLEXITY_Apt_Malware_Linux_Disgomoji_Loader : TRANSPARENTJASMINE FILE MEMORY
{
	meta:
		description = "Detects DISGOMOJI loader using strings in the ELF."
		author = "threatintel@volexity.com"
		id = "6d7848db-f1a5-5ccc-977a-7597b966a31c"
		date = "2024-02-22"
		modified = "2024-07-05"
		reference = "TIB-20240229"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L25-L47"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "d9be4846bab5fffcfd60eaec377443819404f30ec088905c2ee26bd3b7525832"
		score = 75
		quality = 80
		tags = "TRANSPARENTJASMINE, FILE, MEMORY"
		hash1 = "51a372fee89f885741515fa6fdf0ebce860f98145c9883f2e3e35c0fe4432885"
		os = "linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10269
		version = 7

	strings:
		$s1 = "discord-c2/test/main/delievery.go" wide ascii

	condition:
		$s1
}

rule VOLEXITY_Apt_Malware_Linux_Disgomoji_Debug_String : TRANSPARENTJASMINE FILE MEMORY
{
	meta:
		description = "Detects DISGOMOJI using strings in the ELF."
		author = "threatintel@volexity.com"
		id = "eed2468f-7e50-5f3e-946a-277c10984823"
		date = "2024-02-22"
		modified = "2024-11-27"
		reference = "TIB-20240229"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L48-L71"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "6bb130eead39bd8128983e0f2e76cfeff8865ce8ed3cb73b132ed32d68fc0db0"
		score = 75
		quality = 80
		tags = "TRANSPARENTJASMINE, FILE, MEMORY"
		hash1 = "d9f29a626857fa251393f056e454dfc02de53288ebe89a282bad38d03f614529"
		os = "linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10268
		version = 9

	strings:
		$s1 = "discord-c2/test/main/payload.go" wide ascii
		$s2 = "Desktop/Golang_Dev/Discord"

	condition:
		any of them
}

rule VOLEXITY_Apt_Malware_Linux_Disgomoji_2 : TRANSPARENTJASMINE FILE MEMORY
{
	meta:
		description = "Detects DISGOMOJI malware using strings in the ELF."
		author = "threatintel@volexity.com"
		id = "609beb47-5e93-5f69-b89d-2cf62f20851a"
		date = "2024-02-22"
		modified = "2024-07-05"
		reference = "TIB-20240229"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L72-L103"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "e03a774cca2946c1becdbd775ef465033dae089d578ea18a4f43fd7bdae9168e"
		score = 75
		quality = 80
		tags = "TRANSPARENTJASMINE, FILE, MEMORY"
		hash1 = "d9f29a626857fa251393f056e454dfc02de53288ebe89a282bad38d03f614529"
		os = "linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10266
		version = 9

	strings:
		$s1 = "downloadFileFromURL" wide ascii
		$s2 = "createCronJob" wide ascii
		$s3 = "findAndSendFiles" wide ascii
		$s4 = "updateLogFile" wide ascii
		$s5 = "handleZipFile" wide ascii
		$s6 = "takeScreenshot" wide ascii
		$s7 = "zipFirefoxProfile" wide ascii
		$s8 = "zipDirectoryWithParts" wide ascii
		$s9 = "uploadAndSendToOshi" wide ascii
		$s10 = "uploadAndSendToLeft" wide ascii

	condition:
		7 of them
}

rule VOLEXITY_Apt_Malware_Linux_Disgomoji_1 : TRANSPARENTJASMINE FILE MEMORY
{
	meta:
		description = "Detects GOMOJI malware using strings in the ELF."
		author = "threatintel@volexity.com"
		id = "f6643e9a-ca41-57e0-9fce-571d340f1cfe"
		date = "2024-02-22"
		modified = "2024-07-05"
		reference = "TIB-20240229"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L104-L131"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "dd3535079881ae9cfe25c129803668cb595be89b7f62eb82af19cc3839f92b6d"
		score = 75
		quality = 80
		tags = "TRANSPARENTJASMINE, FILE, MEMORY"
		hash1 = "d9f29a626857fa251393f056e454dfc02de53288ebe89a282bad38d03f614529"
		os = "linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10265
		version = 7

	strings:
		$s1 = "Session *%s* opened!" wide ascii
		$s2 = "uevent_seqnum.sh" wide ascii
		$s3 = "Error downloading shell script: %v" wide ascii
		$s4 = "Error setting execute permissions: %v" wide ascii
		$s5 = "Error executing shell script: %v" wide ascii
		$s6 = "Error creating Discord session" wide ascii

	condition:
		4 of them
}

rule VOLEXITY_Apt_Malware_Linux_Disgomoji_Bogus_Strings : TRANSPARENTJASMINE FILE
{
	meta:
		description = "Detects the DISGOMOJI malware using bogus strings introduced in the newer version."
		author = "threatintel@volexity.com"
		id = "ecff8d3c-d4fe-5b6d-a227-6ff531cf8e2b"
		date = "2024-03-14"
		modified = "2024-07-05"
		reference = "TIB-20240318"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L132-L159"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "0d8a2b371ffb182e60a8cc0cc500d1a9f906718a55f23f35f6c12f7faabbe971"
		score = 75
		quality = 80
		tags = "TRANSPARENTJASMINE, FILE"
		hash1 = "8c8ef2d850bd9c987604e82571706e11612946122c6ab089bd54440c0113968e"
		os = "linux"
		os_arch = "all"
		scan_context = "file"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10341
		version = 5

	strings:
		$s1 = "Graphics Display Rendering" wide ascii
		$s2 = "Error fetching Repository Key: %v" wide ascii
		$s3 = "Error reading Repository Key: %v" wide ascii
		$s4 = "Error fetching dpkg: %v" wide ascii
		$s5 = "GNU Drivers Latest version v1.4.2" wide ascii
		$s6 = "ps_output.txt" wide ascii

	condition:
		all of them
}

rule VOLEXITY_Apt_Malware_Linux_Disgomoji_Script_Uevent_Seqnum : TRANSPARENTJASMINE FILE
{
	meta:
		description = "Detects a script deployed as part of DISGOMOJI malware chain."
		author = "threatintel@volexity.com"
		id = "9df61164-6a92-5042-ba4f-64dc7e998283"
		date = "2024-03-07"
		modified = "2024-07-05"
		reference = "TIB-20240318"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L160-L187"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "e390e83d9fc15499c9f32ad47d1c526273105602bda7b3532720b0a3f6abc835"
		score = 75
		quality = 80
		tags = "TRANSPARENTJASMINE, FILE"
		hash1 = "98b24fb7aaaece7556aea2269b4e908dd79ff332ddaa5111caec49123840f364"
		os = "linux"
		os_arch = "all"
		scan_context = "file"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10314
		version = 6

	strings:
		$s1 = "USB_DIR=\"/media/$USER\"" wide ascii
		$s2 = "RECORD_FILE=\"record.txt\"" wide ascii
		$s3 = "copy_files()" wide ascii
		$s4 = "Check for connected USB drives" wide ascii
		$s5 = "Check if filename already exists in record.txt" wide ascii
		$s6 = "Function to copy files from USB drive to destination folder" wide ascii

	condition:
		3 of them
}

rule VOLEXITY_Apt_Malware_Linux_Disgomoji_Script_Lan_Conf : TRANSPARENTJASMINE FILE
{
	meta:
		description = "Detects a script deployed as part of DISGOMOJI malware chain."
		author = "threatintel@volexity.com"
		id = "b338b3cf-22ce-5767-bdea-503e883bc84b"
		date = "2024-03-07"
		modified = "2024-07-05"
		reference = "TIB-20240318"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L188-L215"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "2a19d5cff7adc9b1b92538a5df4e3cadea694f925f65080f5093fc5425e840f4"
		score = 75
		quality = 80
		tags = "TRANSPARENTJASMINE, FILE"
		hash1 = "0b5cf9bd917f0af03dd694ff4ce39b0b34a97c9f41b87feac1dc884a684f60ef"
		os = "linux"
		os_arch = "all"
		scan_context = "file"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10312
		version = 7

	strings:
		$s1 = "add_lan_conf_cron_if_not_exists" wide ascii
		$s2 = "download_if_not_exists" wide ascii
		$s3 = "add_cron_if_not_exists" wide ascii
		$s4 = "uevent_seqnum.sh" wide ascii
		$s5 = "$HOME/.x86_64-linux-gnu" wide ascii
		$s6 = "lanConfScriptPath" wide ascii

	condition:
		4 of them
}

