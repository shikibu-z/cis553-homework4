BUILD_DIR = build
PCAP_DIR = pcaps
LOG_DIR = logs

TOPO = configs/topology.json
P4C = p4c-bm2-ss
P4C_ARGS = --std p4-16 --p4runtime-file $(basename $@).p4info --p4runtime-format text --target bmv2 --arch v1model
RUN_SCRIPT = utils/run_exercise.py
RUN_SCRIPT_NO_TERM = utils/run_exercise.py -n
BMV2_SWITCH_EXE = simple_switch_grpc

source := $(wildcard *.p4)
outfile := $(source:.p4=.json)

compiled_json := $(BUILD_DIR)/$(outfile)

# Define NO_P4 to start BMv2 without a program
ifndef NO_P4
run_args += -j $(compiled_json)
endif

# Set BMV2_SWITCH_EXE to override the BMv2 target
ifdef BMV2_SWITCH_EXE
run_args += -b $(BMV2_SWITCH_EXE)
endif

all: run

run_no_term: build
	sudo python $(RUN_SCRIPT_NO_TERM) -t $(TOPO) $(run_args)

run: build
	sudo python $(RUN_SCRIPT) -t $(TOPO) $(run_args)

stop:
	sudo pkill -f control_plane.py
	sudo mn -c

build: dirs $(compiled_json)

$(BUILD_DIR)/%.json: %.p4
	$(P4C) $(P4C_ARGS) -o $@ $<

dirs:
	mkdir -p $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)

clean: stop
	rm -f *.pcap
	rm -f utils/*.pyc
	rm -rf $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)
