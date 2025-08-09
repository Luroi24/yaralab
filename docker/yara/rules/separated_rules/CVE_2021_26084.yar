rule SIGNATURE_BASE_LOG_EXPL_Confluence_RCE_CVE_2021_26084_Sep21 : LOG CVE_2021_26084
{
	meta:
		description = "Detects exploitation attempts against Confluence servers abusing a RCE reported as CVE-2021-26084"
		author = "Florian Roth (Nextron Systems)"
		id = "bbf98ce4-d32b-541a-b727-bc35c9aaef53"
		date = "2021-09-01"
		modified = "2023-12-05"
		reference = "https://github.com/httpvoid/writeups/blob/main/Confluence-RCE.md"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_cve_2021_26084_confluence_log.yar#L2-L24"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "04542570b4814efde3d96ba5be8b5f9fd6e3c51be09f0e8a1c4eba45bfd8f5ff"
		score = 55
		quality = 60
		tags = "LOG, CVE-2021-26084"

	strings:
		$xr1 = /isSafeExpression Unsafe clause found in \['[^\n]{1,64}\\u0027/ ascii wide
		$xs1 = "[util.velocity.debug.DebugReferenceInsertionEventHandler] referenceInsert resolving reference [$!queryString]"
		$xs2 = "userName: anonymous | action: createpage-entervariables ognl.ExpressionSyntaxException: Malformed OGNL expression: '\\' [ognl.TokenMgrError: Lexical error at line 1"
		$sa1 = "GET /pages/doenterpagevariables.action"
		$sb1 = "%5c%75%30%30%32%37"
		$sb2 = "\\u0027"
		$sc1 = " ERROR "
		$sc2 = " | userName: anonymous | action: createpage-entervariables"
		$re1 = /\[confluence\.plugins\.synchrony\.SynchronyContextProvider\] getContextMap (\n )?-- url: \/pages\/createpage-entervariables\.action/

	condition:
		1 of ( $x* ) or ( $sa1 and 1 of ( $sb* ) ) or ( all of ( $sc* ) and $re1 )
}

