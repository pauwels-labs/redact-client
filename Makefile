run:
	cargo run

build:
	cargo b

build-release:
	cargo b --release

test:
	cargo tarpaulin --out html
