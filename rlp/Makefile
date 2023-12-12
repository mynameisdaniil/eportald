REBAR = ./rebar3
ELVIS = ./elvis

.PHONY: build run test elvis

build:
	$(REBAR) compile

clean:
	$(REBAR) clean

run:
	$(REBAR) shell

test:
	$(REBAR) ct

elvis:
	$(ELVIS) rock

install:
	$(REBAR) get-deps
