#!/bin/bash

# PyPhish Development Runner
# This script runs both the Flask server and the Firefox extension

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}PyPhish Development Environment${NC}"
echo "=================================="

# Check if we're in the right directory
if [ ! -f "main.py" ]; then
    echo -e "${RED}Error: main.py not found. Please run this script from the pf directory.${NC}"
    exit 1
fi

# Check if web-ext is installed
if ! command -v web-ext &> /dev/null; then
    echo -e "${YELLOW}Warning: web-ext not found. Installing globally...${NC}"
    npm install -g web-ext
fi

# Check if Python is available
if ! command -v python &> /dev/null && ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python not found. Please install Python 3.${NC}"
    exit 1
fi

PYTHON_CMD=$(command -v python3 || command -v python)

# Check if Flask is installed
if ! $PYTHON_CMD -c "import flask" 2>/dev/null; then
    echo -e "${YELLOW}Flask not found. Installing dependencies...${NC}"
    if [ -f "pyproject.toml" ]; then
        if command -v uv &> /dev/null; then
            uv sync
        else
            pip install -e .
        fi
    else
        pip install flask
    fi
fi

echo ""
echo -e "${GREEN}Starting Flask server...${NC}"

# Start Flask server in background
$PYTHON_CMD main.py &
FLASK_PID=$!

# Function to cleanup on exit
cleanup() {
    echo ""
    echo -e "${YELLOW}Shutting down...${NC}"
    kill $FLASK_PID 2>/dev/null || true
    exit 0
}

trap cleanup EXIT INT TERM

# Wait for Flask to start
echo -e "${YELLOW}Waiting for Flask server to start...${NC}"
sleep 3

# Check if Flask is running
if ! kill -0 $FLASK_PID 2>/dev/null; then
    echo -e "${RED}Error: Flask server failed to start${NC}"
    exit 1
fi

# Test if Flask is responding
if curl -s http://localhost:5000/health > /dev/null; then
    echo -e "${GREEN}✓ Flask server is running on http://localhost:5000${NC}"
else
    echo -e "${YELLOW}Warning: Flask server started but not responding to health check${NC}"
fi

echo ""
echo -e "${GREEN}Starting Firefox extension...${NC}"

# Check if Firefox path exists
FIREFOX_PATH="/Applications/Firefox.app/Contents/MacOS/firefox"
if [ ! -f "$FIREFOX_PATH" ]; then
    echo -e "${YELLOW}Firefox not found at default location. Trying system default...${NC}"
    web-ext run --source-dir extension/
else
    web-ext run --source-dir extension/ --firefox-binary "$FIREFOX_PATH"
fi

# Keep script running
wait $FLASK_PID
