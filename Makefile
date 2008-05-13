all:
	make -C rehash
	make -C susanin
	make -C library
	make -C client

clean:
	make -C rehash clean
	make -C susanin clean
	make -C library clean
	make -C client clean