
all: ex_original.s
	gcc ex_original.s -pie -o ex
	@./ex > out.txt
clean:
	rm -f ex out.txt
	rm -fr ex.unstripped ex.s *.old*  dl_files *.gtirb
check:
	./ex > /tmp/res.txt
	@ diff out.txt /tmp/res.txt && echo TEST OK
