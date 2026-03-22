# NetMan Makefile

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
CXXFLAGS += $(shell pkg-config --cflags gtkmm-4.0 vte-2.91-gtk4)
LDFLAGS = $(shell pkg-config --libs gtkmm-4.0 vte-2.91-gtk4)

SRC_DIR = src
OBJ_DIR = obj
BIN = netman

SRCS = $(SRC_DIR)/main.cpp \
       $(SRC_DIR)/app.cpp \
       $(SRC_DIR)/core/state.cpp \
       $(SRC_DIR)/core/security_manager.cpp \
       $(SRC_DIR)/helpers/exec.cpp \
       $(SRC_DIR)/net/interfaces.cpp \
       $(SRC_DIR)/net/scanner.cpp \
       $(SRC_DIR)/net/iptables.cpp \
       $(SRC_DIR)/net/mac_spoofer.cpp \
       $(SRC_DIR)/net/hotspot.cpp \
       $(SRC_DIR)/ui/general_tab.cpp \
       $(SRC_DIR)/ui/firewall_tab.cpp \
       $(SRC_DIR)/ui/hotspot_tab.cpp \
       $(SRC_DIR)/ui/pxe_tab.cpp \
       $(SRC_DIR)/ui/bridge_tab.cpp \
       $(SRC_DIR)/ui/tools_tab.cpp \
       $(SRC_DIR)/ui/mac_spoofer_tab.cpp \
       $(SRC_DIR)/ui/log_panel.cpp

OBJS = $(SRCS:$(SRC_DIR)/%.cpp=$(OBJ_DIR)/%.o)

.PHONY: all clean

all: $(BIN)

$(BIN): $(OBJS)
	$(CXX) $(OBJS) -o $@ $(LDFLAGS)
	@echo "Build complete: ./$(BIN)"

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -I$(SRC_DIR) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR) $(BIN)

# Debug build
debug: CXXFLAGS += -g -DDEBUG
debug: clean all
