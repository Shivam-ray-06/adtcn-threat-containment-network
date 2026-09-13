#!/bin/bash
# build.sh — compiles the Java backend and all three C++ programs.
# Run this once (and again any time you edit source) before using run instructions in README.md.
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Building Java backend ==="
cd backend-java
mkdir -p out
javac -d out src/adtcn/*.java
cd ..
echo "Java backend compiled -> backend-java/out"

echo ""
echo "=== Building C++ endpoint agent ==="
cd agent-cpp
g++ -O2 -std=c++17 -I../common-cpp endpoint_agent.cpp -o endpoint_agent
cd ..
echo "endpoint_agent compiled -> agent-cpp/endpoint_agent"

echo ""
echo "=== Building C++ network sensor ==="
cd network-cpp
g++ -O2 -std=c++17 -I../common-cpp network_sensor.cpp -o network_sensor
cd ..
echo "network_sensor compiled -> network-cpp/network_sensor"

echo ""
echo "=== Building C++ attack simulator ==="
cd simulator-cpp
g++ -O2 -std=c++17 -I../common-cpp attack_simulator.cpp -o attack_simulator
cd ..
echo "attack_simulator compiled -> simulator-cpp/attack_simulator"

echo ""
echo "=== All builds complete ==="
echo "Next: see README.md for run instructions."
