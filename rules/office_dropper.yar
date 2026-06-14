/*
    office_dropper.yar
    Original YARA heuristics for weaponised document droppers (Office macros and
    malicious PDFs). Complements the olevba macro layer: olevba parses VBA
    semantically, while these rules catch indicator strings directly in the file
    bytes (useful for OOXML containers and PDFs). Written from scratch.
*/

rule Office_Macro_AutoExec_Execution
{
    meta:
        author      = "hybrid-ransomware-detector"
        description = "VBA auto-run trigger combined with a process/shell primitive"
        severity    = "high"
    strings:
        $a1 = "AutoOpen"        nocase wide ascii
        $a2 = "Auto_Open"       nocase wide ascii
        $a3 = "Document_Open"   nocase wide ascii
        $a4 = "Workbook_Open"   nocase wide ascii
        $a5 = "AutoExec"        nocase wide ascii
        $x1 = "Shell"           nocase wide ascii
        $x2 = "WScript.Shell"   nocase wide ascii
        $x3 = "CreateObject"    nocase wide ascii
        $x4 = "powershell"      nocase wide ascii
        $x5 = "cmd.exe"         nocase wide ascii
    condition:
        (any of ($a*)) and (any of ($x*))
}

rule Office_Macro_Payload_Download
{
    meta:
        author      = "hybrid-ransomware-detector"
        description = "VBA networking primitives used to pull a remote payload"
        severity    = "high"
    strings:
        $n1 = "URLDownloadToFile" nocase wide ascii
        $n2 = "MSXML2.XMLHTTP"    nocase wide ascii
        $n3 = "WinHttp.WinHttpRequest" nocase wide ascii
        $n4 = "ADODB.Stream"      nocase wide ascii
        $h1 = "http://"           nocase wide ascii
        $h2 = "https://"          nocase wide ascii
    condition:
        (any of ($n*)) and (any of ($h*))
}

rule PDF_AutoLaunch_Action
{
    meta:
        author      = "hybrid-ransomware-detector"
        description = "PDF that auto-runs JavaScript or launches an external program"
        severity    = "medium"
    strings:
        $pdf  = "%PDF-"
        $oa   = "/OpenAction"
        $aa   = "/AA"
        $js   = "/JavaScript"
        $js2  = "/JS"
        $lnch = "/Launch"
    condition:
        $pdf at 0 and (($oa or $aa) and ($js or $js2 or $lnch))
}

rule Embedded_Executable_In_Document
{
    meta:
        author      = "hybrid-ransomware-detector"
        description = "Windows PE (MZ...PE) header bytes embedded inside a document"
        severity    = "high"
    strings:
        // MZ DOS header followed (loosely) by the PE signature.
        $mz = { 4D 5A }
        $pe = "PE\x00\x00"
        $dos_stub = "This program cannot be run in DOS mode"
    condition:
        $mz at 0 and ($pe or $dos_stub)
}
