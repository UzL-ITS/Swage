## start configuration

PROFILE=release

## end configuration

CARGO_FLAGS=--profile=${PROFILE}

all:
	make -C victims
	cargo build ${CARGO_FLAGS}

clean:
	make -C victims clean
	cargo clean ${CARGO_FLAGS}

hammer_jit.o.objdump: hammer_jit.o
	objdump -b binary -m i386:x86-64 -D hammer_jit.o > hammer_jit.o.objdump

# Shorthand target to rebuild all READMEs in all subdirectories containing a mod.rs file
readme:
	cargo readme --no-title > README.md
	for dir in $$(find . -type f -name mod.rs -exec dirname {} \;); do \
		echo "# Module $$dir" > $$dir/README.md; \
		cargo readme --input $$dir/mod.rs >> $$dir/README.md --no-title; \
	done
