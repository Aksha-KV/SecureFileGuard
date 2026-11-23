CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Isrc -MMD -MP
LIB_SRCS = src/guard_v0.cpp src/guard_v1.cpp src/guard_v2.cpp src/guard_v3.cpp src/guard_v4.cpp

TARGETS = build/guard_cli build/toctou_race build/run_tests

all: $(TARGETS)

build/guard_cli: cli/guard_cli.cpp $(LIB_SRCS)
	@mkdir -p build
	$(CXX) $(CXXFLAGS) $^ -o $@

build/toctou_race: demo/toctou_race.cpp $(LIB_SRCS)
	@mkdir -p build
	$(CXX) $(CXXFLAGS) $^ -pthread -o $@

build/run_tests: tests/run_tests.cpp tests/test_cases.cpp $(LIB_SRCS)
	@mkdir -p build
	$(CXX) $(CXXFLAGS) $^ -o $@

-include build/*.d

test: all
	@bash scripts/run_all_tests.sh

run: all
	python3 server/app.py

clean:
	rm -rf build runtime results/results.csv

.PHONY: all test run clean
