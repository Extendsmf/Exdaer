CXX = g++
CXXFLAGS = -std=c++17 -Wall -O2

INCLUDES = -Iincludes -Isrc 

LDFLAGS = $(shell pkg-config --libs protobuf grpc++) -pthread

TARGET = agent

SRCS = src/agent.cpp src/telemetry.pb.cc src/telemetry.grpc.pb.cc
OBJS = src/agent.o src/telemetry.pb.o src/telemetry.grpc.pb.o

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS) $(LDFLAGS)

src/%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

src/%.o: src/%.cc
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@
	
clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean