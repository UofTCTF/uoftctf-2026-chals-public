#!/bin/bash

echo "🔨 Compiling Kotlin/Wasm project..."

# Clean and compile
echo "📦 Running Gradle build..."
GRADLE_OUTPUT=$(./gradlew wasmWasiNodeProductionRun 2>&1)
GRADLE_EXIT_CODE=$?

echo "$GRADLE_OUTPUT"

# Check if the error is the expected "Cannot find module" error
if echo "$GRADLE_OUTPUT" | grep -q "Error: Cannot find module"; then
    echo "📋 Expected 'Cannot find module' error detected - treating as success"
    GRADLE_EXIT_CODE=0
fi

if [ $GRADLE_EXIT_CODE -ne 0 ]; then
    echo "❌ Compilation failed!"
    exit 1
fi

echo "🔍 Looking for compiled executable..."
EXECUTABLE_PATH=$(find build -name "rev-wasm.mjs" | grep -v test | head -1)

if [ -z "$EXECUTABLE_PATH" ]; then
    echo "❌ Could not find compiled executable!"
    exit 1
fi

echo "✅ Compilation successful!"
echo "📁 Executable found at: $EXECUTABLE_PATH"
echo ""
echo "🚀 To test manually:"
echo "   echo \"0QGFCBREENDFDONZRC39BDS3DMEH3E\" | node $EXECUTABLE_PATH"
echo ""
echo "🧪 To run automated tests:"
echo "   ./check-logic.sh"