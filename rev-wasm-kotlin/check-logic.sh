#!/bin/bash

echo "🧪 Testing password verification logic..."

# Find the executable
EXECUTABLE_PATH=$(find dist -name "runner.mjs" | grep -v test | head -1)

if [ -z "$EXECUTABLE_PATH" ]; then
    echo "❌ Could not find compiled executable!"
    echo "💡 Run ./compile.sh first to build the project"
    exit 1
fi

echo "📁 Using executable: $EXECUTABLE_PATH"
echo ""

# Test correct password
echo "✅ Testing correct password..."
CORRECT_OUTPUT=$(echo "0QGFCBREENDFDONZRC39BDS3DMEH3E" | node "$EXECUTABLE_PATH" 2>&1)
CORRECT_EXIT_CODE=$?

echo "=== FULL OUTPUT ==="
echo "$CORRECT_OUTPUT"
echo "==================="

if [ $CORRECT_EXIT_CODE -ne 0 ]; then
    echo "   fail: unknown runtime error raised"
    echo "$CORRECT_OUTPUT"
    exit 1
fi

CORRECT_RESULT=$(echo "$CORRECT_OUTPUT" | grep "Password:")
if [[ "$CORRECT_RESULT" == *"Password: CORRECT"* ]]; then
    echo "   ✅ PASS: Correct password accepted"
else
    echo "   ❌ FAIL: Correct password rejected"
    echo "   Output: $CORRECT_RESULT"
    exit 1
fi

# Test incorrect passwords
echo ""
echo "❌ Testing incorrect passwords..."

TEST_CASES=(
    "wrongpassword"
    "0QGFCBREENDFDONZRC39BDS3DMEH3F"  # Last char wrong
    "1QGFCBREENDFDONZRC39BDS3DMEH3E"  # First char wrong
    "short"
    "0QGFCBREENDFDONZRC39BDS3DMEH3E123"  # Too long
    ""
    "abcdefghijklmnopqrstuvwxyz1234"
)

FAIL_COUNT=0
for password in "${TEST_CASES[@]}"; do
    TEST_OUTPUT=$(echo "$password" | node "$EXECUTABLE_PATH" 2>&1)
    TEST_EXIT_CODE=$?
    
    if [ $TEST_EXIT_CODE -ne 0 ]; then
        echo "   fail: unknown runtime error raised for password \"$password\""
        echo "$TEST_OUTPUT"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        continue
    fi
    
    RESULT=$(echo "$TEST_OUTPUT" | grep "Password:")
    if [[ "$RESULT" == *"INCORRECT"* ]]; then
        echo "   ✅ PASS: \"$password\" correctly rejected"
    else
        echo "   ❌ FAIL: \"$password\" incorrectly accepted"
        echo "   Output: $RESULT"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
done

echo ""
if [ $FAIL_COUNT -eq 0 ]; then
    echo "🎉 All tests passed!"
    echo "✅ Password verification logic is working correctly"
else
    echo "❌ $FAIL_COUNT test(s) failed!"
    exit 1
fi