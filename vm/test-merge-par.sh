#!/bin/sh
fail=false
test_page_merge()
{
	make build/tests/vm/page-merge-par.result
	if make build/tests/vm/page-merge-par.result | grep -q FAIL; then
		exit 1
	fi
	rm build/tests/vm/page-merge-par.output
	rm build/tests/vm/page-merge-par.result
}

test_check()
{
	make check
	make clean
}

a=0
while [ $a -lt 50 ]
do
	#test_page_merge
	test_check
done

