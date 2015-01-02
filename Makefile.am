# Course:   SÌùovÈ aplikace a spr·va sÌtÌ
# Project:  Projekt - Sniffer CDP a LLDP
# Author:   Radim Loskot, xlosko01@stud.fit.vutbr.cz
# Date:     11. 11. 2011
# 
# Usage:
#	- make            compile project - release version
#	- make pack       packs all required files to compile this project    
#	- make clean      clean temp compilers files    
#	- make clean-all  clean all compilers files - includes project    
#	- make clean-outp clean output project files 
#

# output project and package filename
SRC_DIR=src
OBJ_DIR=objs
TARGET=sniffer
PACKAGE_NAME=sniffer
PACKAGE_FILES=$(SRC_DIR) Makefile Makefile.am run_make.sh manual.pdf Readme

# C++ compiler and flags
CXX=g++
CXXFLAGS=$(CXXOPT) -std=c++98 -Wall -pedantic -W
LIBS=-lpcap

# Project files
OBJ_FILES=cdp_lldp_sniffer.o network.o
OBJ_LIB_FILES=sniffers.o
OBJ_LIB_SNIFFERS_FILES=cdp_sniffer.o lldp_sniffer.o sniffer.o
OBJ_LIB_SNIFFERS_PACKETS_FILES=packet.o cdp_packet.o lldp_packet.o llc_packet.o tlv.o sysinfo.o
OBJ_LIB_SNIFFERS_PACKETS_FRAMES_FILES=frame.o ethernet_frame.o data.o 
SRC_FILES=cdp_lldp_sniffer.cpp network.cpp network.h
SRC_LIB_FILES=sniffers.cpp sniffers.h
SRC_LIB_SNIFFERS_FILES=cdp_sniffer.cpp cdp_sniffer.h lldp_sniffer.cpp lldp_sniffer.h sniffer.cpp sniffer.h
SRC_LIB_SNIFFERS_PACKETS_FILES=packet.cpp packet.h cdp_packet.cpp cdp_packet.h lldp_packet.cpp lldp_packet.h llc_packet.cpp llc_packet.h tlv.cpp tlv.h sysinfo.cpp sysinfo.h
SRC_LIB_SNIFFERS_PACKETS_FRAMES_FILES=frame.cpp frame.h ethernet_frame.cpp ethernet_frame.h data.cpp data.h

# Substitute the path
SRC=$(patsubst %,$(SRC_DIR)/%,$(SRC_FILES)) $(patsubst %,$(SRC_DIR)/lib/%,$(SRC_LIB_FILES)) $(patsubst %,$(SRC_DIR)/lib/sniffers/%,$(SRC_LIB_SNIFFERS_FILES)) $(patsubst %,$(SRC_DIR)/lib/sniffers/packets/%,$(SRC_LIB_SNIFFERS_PACKETS_FILES)) $(patsubst %,$(SRC_DIR)/lib/sniffers/packets/frames/%,$(SRC_LIB_SNIFFERS_PACKETS_FRAMES_FILES))

OBJ=$(patsubst %,$(OBJ_DIR)/%,$(OBJ_FILES)) $(patsubst %,$(OBJ_DIR)/lib/%,$(OBJ_LIB_FILES)) $(patsubst %,$(OBJ_DIR)/lib/sniffers/%,$(OBJ_LIB_SNIFFERS_FILES)) $(patsubst %,$(OBJ_DIR)/lib/sniffers/packets/%,$(OBJ_LIB_SNIFFERS_PACKETS_FILES)) $(patsubst %,$(OBJ_DIR)/lib/sniffers/packets/frames/%,$(OBJ_LIB_SNIFFERS_PACKETS_FRAMES_FILES))

# Universal rule
$(OBJ_DIR)/%.o : $(SRC_DIR)/%.cpp
	$(CXX) -c -o $@ $< $(CXXFLAGS)

# START RULE
all: | $(OBJ_DIR) $(TARGET)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)/lib/sniffers/packets/frames

cdp_lldp_sniffer.o:cdp_lldp_sniffer.cpp lib/sniffers.h network.h
sniffers.o:sniffers.cpp sniffers.h cdp_sniffer.h lldp_sniffer.h
cdp_sniffer.o:cdp_sniffer.cpp cdp_sniffer.h packets/cdp_packet.h
lldp_sniffer.o:lldp_sniffer.cpp lldp_sniffer.h packets/lldp_packet.h
sniffer.o:sniffer.cpp sniffer.h
cdp_packet.o:cdp_packet.cpp cdp_packet.h sysinfo.h frames/ethernet_frame.h protocols.h llc_packet.h
llc_packet.o:llc_packet.cpp llc_packet.h frames/ethernet_frame.h protocols.h
lldp_packet.o:lldp_packet.cpp lldp_packet.h sysinfo.h frames/ethernet_frame.h protocols.h
packet.o:packet.cpp packet.h
sysinfo.o:sysinfo.cpp sysinfo.h
tlv.o:tlv.cpp tlv.h frames/data.h
ethernet_frame.o:ethernet_frame.cpp ethernet_frame.h frame.h
frame.o:frame.cpp frame.h
data.o:data.cpp data.h

# Linking of modules into release program
$(TARGET): $(OBJ)
	$(CXX) -o $@ $^ $(FLAGS) $(LIBS)
	
.PHONY: clean clean-all clean-outp pack

pack:
	tar -cvf $(PACKAGE_NAME).tar $(PACKAGE_FILES)

clean:
	rm -rf $(OBJ_DIR)

clean-outp:								# project doesnt produce any
	

clean-all: clean clean-outp
	rm -rf $(TARGET)