// Règles YARA d'exemple pour Sentinelle (SENTINELLE_YARA_DIR=./yara.d).
// Signatures défensives classiques ; ajoutez les vôtres dans ce dossier.

rule eicar_test_file
{
    meta:
        description = "Fichier de test antivirus EICAR (inoffensif, sert à valider la chaîne de détection)"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}

rule mimikatz_strings
{
    meta:
        description = "Chaînes caractéristiques de mimikatz (vol d'identifiants)"
        attack = "T1003"
    strings:
        $a = "sekurlsa::logonpasswords" ascii wide nocase
        $b = "gentilkiwi" ascii wide nocase
        $c = "lsadump::sam" ascii wide nocase
    condition:
        2 of them
}
