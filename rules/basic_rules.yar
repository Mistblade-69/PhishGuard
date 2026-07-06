/*
    basic_rules.yar
    Starter YARA rule set for PhishGuard's malware_scanner.py.
    Covers: the EICAR test signature (for pipeline testing) plus a handful
    of generic, high-signal indicators commonly seen in malicious
    attachments (macro droppers, embedded PowerShell/JS, PE headers
    disguised with non-exe extensions).

    These are intentionally broad/starter rules -- expand with more
    specific families as needed.
*/

rule EICAR_Test_File
{
    meta:
        severity = "high"
        description = "Standard EICAR antivirus test signature -- used to validate scanner is working, not real malware"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_PE_Header_Mismatch
{
    meta:
        severity = "high"
        description = "File contains a Windows PE executable header (MZ/PE) -- suspicious if extension doesn't indicate an executable"
    strings:
        $mz = { 4D 5A }
        $pe = "PE\x00\x00"
    condition:
        $mz at 0 and $pe
}

rule Office_Macro_AutoExec
{
    meta:
        severity = "medium"
        description = "Office document contains auto-executing macro functions -- common in malicious docm/xlsm droppers"
    strings:
        $auto1 = "AutoOpen" nocase
        $auto2 = "AutoExec" nocase
        $auto3 = "Document_Open" nocase
        $auto4 = "Workbook_Open" nocase
    condition:
        any of them
}

rule Embedded_PowerShell_Command
{
    meta:
        severity = "high"
        description = "Contains PowerShell invocation patterns commonly used in malicious macros/scripts to download or execute payloads"
    strings:
        $ps1 = "powershell" nocase
        $ps2 = "-EncodedCommand" nocase
        $ps3 = "IEX(" nocase
        $ps4 = "Invoke-Expression" nocase
        $ps5 = "DownloadString" nocase
    condition:
        any of them
}

rule Suspicious_JavaScript_In_Document
{
    meta:
        severity = "medium"
        description = "Contains embedded JavaScript execution patterns often abused in malicious PDFs/attachments"
    strings:
        $js1 = "eval(" nocase
        $js2 = "unescape(" nocase
        $js3 = "app.alert(" nocase
        $js4 = "this.exportDataObject" nocase
    condition:
        any of them
}

rule Suspicious_Shell_Commands
{
    meta:
        severity = "medium"
        description = "Contains OS-level shell command patterns often used to drop/execute payloads"
    strings:
        $cmd1 = "cmd.exe /c" nocase
        $cmd2 = "wscript.shell" nocase
        $cmd3 = "certutil -decode" nocase
        $cmd4 = "rundll32" nocase
    condition:
        any of them
}
