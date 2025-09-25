#!/bin/bash

# Advanced Web Penetration Testing Tool - Startup Script
echo "🔒 Advanced Web Penetration Testing Tool - Starting..."

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

# Check Python version
python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "❌ Python version $python_version is installed, but $required_version or higher is required."
    exit 1
fi

echo "✅ Python $python_version detected"

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔄 Activating virtual environment..."
source venv/bin/activate

# Install requirements
echo "📥 Installing dependencies..."
pip install -r requirements.txt --quiet

# Create necessary directories
mkdir -p logs
mkdir -p results
mkdir -p temp

echo "🚀 Starting Advanced Web Penetration Testing Tool..."
echo "🌐 Open your browser and navigate to: http://localhost:5000"
echo "📖 Documentation: See README.md for usage instructions"
echo "⚠️  Legal Notice: Ensure you have permission to test target systems"
echo ""

# Start the Flask application
python3 pentest_app.py
