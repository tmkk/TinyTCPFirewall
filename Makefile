EXEEXT = .exe
TARGET = TinyTCPFirewall$(EXEEXT)

SOURCES  = main.cpp TTFPacketCapture.cpp TTFSessionManager.cpp TTFSession.cpp TTFIniManager.cpp log.cpp
CXXFLAGS = -Wall -O2 -DWINVER=0x501
INCLUDE  =

OBJECTS = $(SOURCES:.cpp=.o)

all : $(TARGET)

$(TARGET) : $(OBJECTS)
	$(CXX) $(OBJECTS) -o $(TARGET) -lws2_32 -lIphlpapi -static-libgcc -static-libstdc++

.SUFFIXES: .cpp .o
.cpp.o:
	$(CXX) $(CXXFLAGS) $(INCLUDE) -c $<

depend:
	$(CXX) -MM $(INCLUDE) $(CXXFLAGS) $(SOURCES) > dependencies

clean :
	rm -f $(OBJECTS) $(TARGET)

include dependencies

