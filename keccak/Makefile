REBAR = ./rebar3

.PHONY: build run test elvis

build:
	$(REBAR) compile

clean:
	$(REBAR) clean

run:
	$(REBAR) shell

test:
	$(REBAR) ct

install:
	$(REBAR) get-deps
