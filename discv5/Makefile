REBAR = ./rebar3
ELVIS = ./elvis

.PHONY: build run test elvis

build:
	$(REBAR) compile

run:
	$(REBAR) shell

test:
	$(REBAR) eunit

elvis:
	$(ELVIS) rock

install:
	$(REBAR) get-deps

clean:
	$(REBAR) clean
