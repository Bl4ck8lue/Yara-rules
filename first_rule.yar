rule learn_yara {
    strings:
	    $a="lmn"
    condition:
	    $a
}