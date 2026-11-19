// PATHOS YARA rules (Apache-2.0), compiled into the worker-binary image
// together with the ReversingLabs YARA rules.

rule PATHOS_EICAR_Test_File : test
{
    meta:
        description = "EICAR anti-malware test file (a harmless file that malware scanners detect by agreement)"
        severity    = "low"
        reference   = "https://www.eicar.org/download-anti-malware-testfile/"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar at 0 or ($eicar and filesize < 128)
}
