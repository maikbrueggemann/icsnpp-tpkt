@TEST-DOC: Check that the TPKT analyzer is available.

@TEST-EXEC: zeek -NN | grep -Eqi 'ANALYZER_TPKT'
