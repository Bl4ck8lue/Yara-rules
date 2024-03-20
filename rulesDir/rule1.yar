rule learn_yara_qwe {
    meta:
        author="ilya"
        description="Check data on qwe"
    strings:
	    $a={59 61 6E 64 65 78 20}
    condition:
	    $a
}
