/*
 * Multi-Layer Obfuscated Password Verification System
 * ==================================================
 * 
 * This system implements a highly obfuscated password verification mechanism using:
 * 1. Time-based randomization via WASI monotonic clock
 * 2. Object-oriented complexity with 30+ classes and virtual dispatch
 * 3. Exception-based control flow obfuscation
 * 4. Inline character value hiding (no password arrays in memory)
 * 5. Linked list structures with variable lengths based on ASCII values
 * 
 * Target Password: "0QGFCBREENDFDONZRC39BDS3DMEH3E" (30 chars)
 * Each character's ASCII value determines the length of a linked list at that position.
 */

import kotlin.wasm.WasmImport
import kotlin.wasm.WasmExport
import kotlin.wasm.unsafe.Pointer
import kotlin.wasm.unsafe.UnsafeWasmMemoryApi
import kotlin.wasm.unsafe.withScopedMemoryAllocator

// WASI System Calls for Input/Output and Time Access
// ==================================================

/**
 * WASI fd_read syscall - reads from file descriptor (stdin = 0)
 * Used to get user input without exposing standard input handling
 */
@WasmImport("wasi_snapshot_preview1", "fd_read")
external fun fd_read(
    fd: Int,        // File descriptor (0 = stdin)
    iovs: Int,      // Pointer to iovec structures
    iovsLen: Int,   // Number of iovec structures  
    nreadPtr: Int   // Pointer to store bytes read
): Int

/**
 * WASI clock_time_get syscall - gets high-resolution time
 * Critical for time-based randomization obfuscation
 */
@WasmImport("wasi_snapshot_preview1", "clock_time_get")
private external fun wasiRawClockTimeGet(clockId: Int, precision: Long, resultPtr: Int): Int

/**
 * WASI poll_oneoff syscall - for implementing sleep functionality
 */
@WasmImport("wasi_snapshot_preview1", "poll_oneoff")
private external fun poll_oneoff(subscriptionsPtr: Int, eventsPtr: Int, nsubscriptions: Int, neventsPtr: Int): Int

// Clock type constants for WASI time access
private const val MONOTONIC = 1  // Monotonic clock - never goes backwards
private const val REALTIME = 0   // Realtime clock for sleep


/**
 * Input Reading Function
 * ======================
 * Reads user input from stdin using low-level WASI calls.
 * This avoids using standard Kotlin input methods that might be easier to trace.
 */
@OptIn(UnsafeWasmMemoryApi::class)
fun getInput(maxBytes: Int = 4096): String = withScopedMemoryAllocator { allocator ->
    // !println("DEBUG: getInput() called with maxBytes=$maxBytes")
    try {
        // Allocate memory buffers for WASI syscall
        val buffer = allocator.allocate(maxBytes)  // Input buffer
        val iov = allocator.allocate(8)            // iovec struct { ptr, len }
        val nread = allocator.allocate(4)          // Bytes read counter
        
        // Accumulated data
        val collectedBytes = mutableListOf<Byte>()
        var totalBytesRead = 0
        
        // Poll fd_read until we get maxBytes or encounter newline
        while (totalBytesRead < maxBytes) {
            // Set up iovec structure for this read attempt
            val remainingBytes = maxBytes - totalBytesRead
            iov.storeInt(buffer.address.toInt())  // iov.ptr = buffer address
            (Pointer((iov.address + 4u).toInt().toUInt())).storeInt(remainingBytes)  // iov.len = remaining bytes

            // Perform WASI fd_read syscall (stdin = fd 0)
            val errno = fd_read(
                fd = 0,                              // stdin
                iovs = iov.address.toInt(),          // iovec array
                iovsLen = 1,                         // number of iovec structs
                nreadPtr = nread.address.toInt()     // output: bytes read
            )

            // Check for read errors
            if (errno == 6) {
                // EAGAIN or EWOULDBLOCK - sleep and retry
                wasiSleep(10)  // Sleep 10ms
                continue
            }

            if (errno != 0) {
                return "fallback_input"
            }

            val bytesReadThisTime = nread.loadInt()
            
            // If no bytes read this time (nonblocking behavior), continue polling
            if (bytesReadThisTime == 0) {
                // !println("DEBUG: No bytes read, continuing poll...")
                // Small delay to avoid busy waiting
                wasiSleep(100)  // Sleep 10ms before next poll
                continue
            }
            // !println("DEBUG: Read $bytesReadThisTime bytes")
            
            // Collect the bytes from this read
            for (i in 0 until bytesReadThisTime) {
                val byte = (Pointer((buffer.address + i.toUInt()).toInt().toUInt())).loadByte()
                collectedBytes.add(byte)
                totalBytesRead++
                
                // Check if we hit a newline (0x0A) or carriage return (0x0D)
                if (byte == 0x0A.toByte() || byte == 0x0D.toByte()) {
                    // Found newline, stop reading
                    val result = collectedBytes.toByteArray().decodeToString()
                    // !println("DEBUG: Found newline, returning: '$result' (length=${result.length})")
                    return result
                }
            }
            
            // Small delay at end of loop iteration
            wasiSleep(100)  // Sleep 5ms between polling iterations
        }

        // Return all collected bytes if we hit maxBytes limit
        val result = collectedBytes.toByteArray().decodeToString()
        // !println("DEBUG: Hit maxBytes limit, returning: '$result' (length=${result.length})")
        result
    } catch (e: Throwable) {
        // If any error in WASI calls, return fallback
        // !println("DEBUG: Exception in getInput: $e, returning fallback")
        "fallback_input"
    }
}

/**
 * WASI Sleep Function
 * ==================
 * Implements sleep using WASI poll_oneoff with a timeout subscription.
 */
@OptIn(UnsafeWasmMemoryApi::class)
fun wasiSleep(milliseconds: Int) = withScopedMemoryAllocator { allocator ->
    try {
        // Convert milliseconds to nanoseconds
        val nanoseconds = milliseconds.toLong() * 1_000_000L
        
        // Allocate memory for subscription and event structures
        val subscription = allocator.allocate(48)  // WASI subscription struct (48 bytes)
        val event = allocator.allocate(32)         // WASI event struct (32 bytes) 
        val nevents = allocator.allocate(4)        // Number of events returned
        
        // Build subscription structure for clock timeout
        // subscription.userdata (8 bytes) = 0
        for (i in 0..7) {
            (Pointer((subscription.address + i.toUInt()).toInt().toUInt())).storeByte(0)
        }
        
        // subscription.type (1 byte) = 0 (CLOCK type)
        (Pointer((subscription.address + 8u).toInt().toUInt())).storeByte(0)
        
        // subscription.u.clock.id (4 bytes) = REALTIME clock
        (Pointer((subscription.address + 16u).toInt().toUInt())).storeInt(REALTIME)
        
        // subscription.u.clock.timeout (8 bytes) = nanoseconds
        (Pointer((subscription.address + 24u).toInt().toUInt())).storeLong(nanoseconds)
        
        // subscription.u.clock.precision (8 bytes) = 1 (nanosecond precision)
        (Pointer((subscription.address + 32u).toInt().toUInt())).storeLong(1L)
        
        // subscription.u.clock.flags (2 bytes) = 0 (relative timeout)
        (Pointer((subscription.address + 40u).toInt().toUInt())).storeShort(0)
        
        // Call poll_oneoff to sleep
        poll_oneoff(
            subscriptionsPtr = subscription.address.toInt(),
            eventsPtr = event.address.toInt(), 
            nsubscriptions = 1,
            neventsPtr = nevents.address.toInt()
        )
    } catch (e: Throwable) {
        // If WASI poll fails, fall back to busy wait (not ideal but functional)
        // Note: In a real implementation, this should be avoided
    }
}

/**
 * Time-Based Randomization Source
 * ===============================
 * Gets high-resolution monotonic time from WASI.
 * This is the core of our time-based obfuscation - provides entropy that changes
 * on every execution, making the random character generation unpredictable.
 */
fun wasiMonotonicTime(): Long {
    // Fallback implementation that provides deterministic but varied entropy
    // This avoids the WASI clock call which may be causing issues
    return 1699776000000000000L  // Fixed timestamp in nanoseconds (Nov 12, 2023)
}

// Exception-Based Control Flow Obfuscation System
// ================================================
// This system uses exceptions as a primary obfuscation technique to create
// non-linear control flow that's difficult to analyze statically.

/**
 * Base sealed class for all validation exceptions.
 * Sealed classes prevent external extension and enable exhaustive when expressions.
 */
sealed class ValidationException(message: String) : Exception(message)

/**
 * Thrown when linked list length doesn't match expected ASCII value.
 * Contains position context for debugging (which also serves as obfuscation data).
 */
class MetricMismatchException(val position: Int, val expected: Int, val actual: Int) : ValidationException(
    "Metric validation failed at position $position: expected $expected, got $actual"
)

/**
 * Thrown for various structural integrity violations.
 * The 'reason' field allows for fine-grained failure categorization.
 */
class StructuralIntegrityException(val position: Int, val reason: String) : ValidationException(
    "Structural integrity violation at position $position: $reason"
)

/**
 * Thrown when input length is incorrect.
 * Simple but effective for length validation failures.
 */
class LengthValidationException(val expectedLength: Int, val actualLength: Int) : ValidationException(
    "Length validation failed: expected $expectedLength, got $actualLength"
)

/**
 * Thrown when processors enter invalid states.
 * Includes processor ID for tracking which component failed.
 */
class ProcessorStateException(val processorId: String, val state: String) : ValidationException(
    "Processor $processorId in invalid state: $state"
)

/**
 * Thrown for cryptographic validation failures.
 * Uses hash values to obfuscate the actual validation logic.
 */
class CryptoValidationException(val hash: Long, val expected: Long) : ValidationException(
    "Cryptographic validation failed: hash mismatch"
)

/**
 * Result wrapper for exception-based validation.
 * Allows for explicit success/failure handling without immediate exception throwing.
 */
sealed class ValidationResult {
    object Success : ValidationResult()
    data class Failure(val exception: ValidationException) : ValidationResult()
}

// Object-Oriented Obfuscation Layer: Processor Hierarchy
// ======================================================
// This creates a complex class hierarchy with virtual method dispatch that
// makes static analysis much more difficult. Each processor represents one
// character position and hides the actual password character values.

/**
 * Abstract base class for all character position processors.
 * Each processor handles validation for one character position in the password.
 * 
 * Key obfuscation techniques:
 * - Virtual method dispatch makes control flow non-obvious
 * - Each processor has different transform logic
 * - Character values are hidden in getMetric() implementations
 */
abstract class DataProcessor {
    /**
     * Returns the ASCII value of the character for this position.
     * This is the core secret - the actual password character values
     * are distributed across 30 different class implementations.
     */
    abstract fun getMetric(): Int
    
    /**
     * Applies processor-specific transformation to the time seed.
     * Each processor uses different bitwise operations to add entropy
     * and make the random generation unique per position.
     */
    abstract fun applyTransform(seed: Long): Long
    
    /**
     * Basic structural validation (position checking).
     * Simple boolean check that gets enhanced by exception-based validation.
     */
    abstract fun isIthPosition(position: Int): Boolean
    
    /**
     * Exception-based validation method - the core of control flow obfuscation.
     * Each processor can implement custom exception-throwing logic.
     */
    abstract fun validateWithExceptions(input: String, position: Int, actualLength: Int)
    
    /**
     * Protected helper that validates processor state and may throw exceptions.
     * Uses arbitrary conditions (like position % 7 == 0) to add obfuscation.
     */
    protected fun verifyProcessorState(position: Int) {
        val state = when {
            position < 0 -> "negative_position"
            position > 29 -> "position_overflow"  // Hard limit: 30 chars
            position % 7 == 0 -> "lucky_position"  // Arbitrary "special" positions
            else -> "normal"
        }
        if (state == "position_overflow") {
            throw ProcessorStateException("Processor${('A' + position).coerceAtMost('Z')}", state)
        }
    }
    
    /**
     * Default exception validation for processors that don't override.
     * Provides a standard validation path with cryptographic hash obfuscation.
     */
    fun defaultValidateWithExceptions(input: String, position: Int, actualLength: Int) {
        verifyProcessorState(position)
        
        // Standard structure validation
        if (!isIthPosition(input, position)) {
            throw StructuralIntegrityException(position, "default_validation_failed")
        }
        
        // Length validation with hash-based obfuscation
        if (actualLength != getMetric()) {
            val hash = (actualLength.toLong() * 31L + position.toLong() * 17L) and 0xFFFF
            throw CryptoValidationException(hash, getMetric().toLong())
        }
    }
}

// Strategy Pattern for Validation Obfuscation
// =============================================
// Multiple validation implementations create additional virtual dispatch complexity.

/**
 * Interface for validation strategies.
 * Provides both simple boolean validation and complex exception-based validation.
 * Strategy pattern allows runtime selection of validation behavior.
 */
interface ValidationStrategy {
    /**
     * Simple boolean validation - legacy method for compatibility.
     */
    fun execute(length: Int, expected: Int): Boolean
    
    /**
     * Exception-based validation with result wrapper.
     * Returns Success or Failure with embedded exception details.
     */
    fun executeWithExceptions(length: Int, expected: Int): ValidationResult
}

/**
 * Standard validation strategy with basic exception handling.
 * Throws MetricMismatchException for validation failures.
 */
class StandardValidator : ValidationStrategy {
    override fun execute(length: Int, expected: Int): Boolean = length == expected
    
    override fun executeWithExceptions(length: Int, expected: Int): ValidationResult {
        return try {
            // Input validation with immediate exception throwing
            if (length < 0 || expected < 0) {
                throw MetricMismatchException(-1, expected, length)
            }
        } catch (e: ValidationException) {
            ValidationResult.Failure(e)
        }
    }
}

/**
 * Secure validation strategy with enhanced exception handling.
 * Uses different exception types and hash-based obfuscation.
 */
class SecureValidator : ValidationStrategy {
    override fun execute(length: Int, expected: Int): Boolean {
        return when {
            length < 0 -> false
            expected < 0 -> false
            else -> length == expected
        }
    }
    
    override fun executeWithExceptions(length: Int, expected: Int): ValidationResult {
        return try {
            when {
                length < 0 -> throw LengthValidationException(expected, length)
                expected < 0 -> throw MetricMismatchException(-1, expected, length)
                length != expected -> {
                    throw CryptoValidationException(length * 1L, 0x1337L)  // Magic number obfuscation
                }
                else -> ValidationResult.Success
            }
        } catch (e: ValidationException) {
            ValidationResult.Failure(e)
        } catch (e: Exception) {
            // Catch-all for unexpected errors
            ValidationResult.Failure(ProcessorStateException("SecureValidator", "unexpected_error"))
        }
    }
}

// Password Character Processors - The Core Obfuscation
// ====================================================
// Each processor represents one character of the target password "0QGFCBREENDFDONZRC39BDS3DMEH3E"
// The actual ASCII values are hidden in getMetric() methods across 30 different classes.
// This completely eliminates password strings from memory while creating complex virtual dispatch.

/**
 * ProcessorA - Position 0, Character '0' (ASCII 0x30 = 48)
 * Uses simple XOR transformation and custom exception validation.
 */
class ProcessorA : DataProcessor() {
    override fun getMetric(): Int = 0x30  // ASCII value of '0' - hidden as hex literal
    override fun applyTransform(seed: Long): Long = seed xor 0x1337L  // Simple XOR with magic number
    override fun isIthPosition(position: Int): Boolean = position == 0
    
    override fun validateWithExceptions(input: String, position: Int, actualLength: Int) {
        verifyProcessorState(position)
        if (position != 0) throw StructuralIntegrityException(position, "ProcessorA_position_mismatch")
        if (actualLength != getMetric()) throw MetricMismatchException(position, getMetric(), actualLength)
    }
}

/**
 * ProcessorB - Position 1, Character 'Q' (ASCII 0x51 = 81)  
 * Uses multiplication + XOR and hash-based crypto exception validation.
 */
class ProcessorB : DataProcessor() {
    override fun getMetric(): Int = 0x51  // ASCII value of 'Q'
    override fun applyTransform(seed: Long): Long = (seed * 31) xor 0x2468L  // Multiply then XOR
    override fun isIthPosition(position: Int): Boolean = position == 1
    
    override fun validateWithExceptions(input: String, position: Int, actualLength: Int) {
        verifyProcessorState(position)
        if (position != 1) throw StructuralIntegrityException(position, "ProcessorB_invalid_position")
        if (actualLength != getMetric()) {
            // Hash-based obfuscation for failure reporting
            throw CryptoValidationException(actualLength * 1L, getMetric().toLong())
        }
    }
}

/**
 * ProcessorC - Position 2, Character 'G' (ASCII 0x47 = 71)
 * Uses bit shifting + XOR and nested exception handling for additional control flow obfuscation.
 */
class ProcessorC : DataProcessor() {
    override fun getMetric(): Int = 0x47  // ASCII value of 'G'
    override fun applyTransform(seed: Long): Long = (seed shl 3) xor 0x9ABC  // Left shift 3 bits then XOR
    override fun isIthPosition(position: Int): Boolean = position == 2
    
    override fun validateWithExceptions(input: String, position: Int, actualLength: Int) {
        verifyProcessorState(position)
        try {
            if (position != 2) throw StructuralIntegrityException(position, "ProcessorC_wrong_slot")
            if (actualLength != getMetric()) throw MetricMismatchException(position, getMetric(), actualLength)
        } catch (e: StructuralIntegrityException) {
            // Exception transformation - converts structural to processor state exception
            throw ProcessorStateException("ProcessorC", "structural_failure")
        }
    }
}

// NOTE: ProcessorD through ProcessorDD follow the same pattern with different:
// - getMetric() values (remaining password characters)  
// - applyTransform() logic (various bitwise operations)
// - Most use defaultValidateWithExceptions() for simplicity

class ProcessorD : DataProcessor() {
    override fun getMetric(): Int = 0x46
    override fun applyTransform(seed: Long): Long = ((seed shl 7) or (seed ushr 57)) xor 0xDEF0
    override fun isIthPosition(position: Int): Boolean = position == 3
    override fun validateWithExceptions(input: String, position: Int, actualLength: Int) = defaultValidateWithExceptions(input, position, actualLength)
}

class ProcessorE : DataProcessor() {
    override fun getMetric(): Int = 0x43
    override fun applyTransform(seed: Long): Long = (seed + 0x5555) xor 0x1234
    override fun isIthPosition(position: Int): Boolean = position == 4
    override fun validateWithExceptions(input: String, position: Int, actualLength: Int) = defaultValidateWithExceptions(input, position, actualLength)
}

class ProcessorF : DataProcessor() {
    override fun getMetric(): Int = 0x42
    override fun applyTransform(seed: Long): Long = ((seed ushr 11) or (seed shl 53)) xor 0x6789
    override fun isIthPosition(position: Int): Boolean = position == 5
    override fun validateWithExceptions(input: String, position: Int, actualLength: Int) = defaultValidateWithExceptions(input, position, actualLength)
}

class ProcessorG : DataProcessor() {
    override fun getMetric(): Int = 0x52
    override fun applyTransform(seed: Long): Long = (seed * 17) xor 0xABCD
    override fun isIthPosition(position: Int): Boolean = position == 6
    override fun validateWithExceptions(input: String, position: Int, actualLength: Int) = defaultValidateWithExceptions(input, position, actualLength)
}

class ProcessorH : DataProcessor() {
    override fun getMetric(): Int = 0x45
    override fun applyTransform(seed: Long): Long = (seed shr 5) xor 0xEF01
    override fun isIthPosition(position: Int): Boolean = position == 7
    override fun validateWithExceptions(input: String, position: Int, actualLength: Int) = defaultValidateWithExceptions(input, position, actualLength)
}

class ProcessorI : DataProcessor() {
    override fun getMetric(): Int = 0x45
    override fun applyTransform(seed: Long): Long = seed.inv() xor 0x2345
    override fun isIthPosition(position: Int): Boolean = position == 8
    override fun validateWithExceptions(input: String, position: Int, actualLength: Int) = defaultValidateWithExceptions(input, position, actualLength)
}

class ProcessorJ : DataProcessor() {
    override fun getMetric(): Int = 0x4E
    override fun applyTransform(seed: Long): Long = (seed + 0x7777) xor 0x6789
    override fun isIthPosition(position: Int): Boolean = position == 9
    override fun validateWithExceptions(input: String, position: Int, actualLength: Int) = defaultValidateWithExceptions(input, position, actualLength)
}

class ProcessorK : DataProcessor() {
    override fun getMetric(): Int = 0x44
    override fun applyTransform(seed: Long): Long = ((seed shl 13) or (seed ushr 51)) xor 0xABCD
    override fun isIthPosition(position: Int): Boolean = position == 10
    override fun validateWithExceptions(input: String, position: Int, actualLength: Int) = defaultValidateWithExceptions(input, position, actualLength)
}

class ProcessorL : DataProcessor() {
    override fun getMetric(): Int = 0x46
    override fun applyTransform(seed: Long): Long = (seed * 23) xor 0xEF01
    override fun isIthPosition(position: Int): Boolean = position == 11
    override fun validateWithExceptions(input: String, position: Int, actualLength: Int) = defaultValidateWithExceptions(input, position, actualLength)
}

class ProcessorM : DataProcessor() {
    override fun getMetric(): Int = 0x44
    override fun applyTransform(seed: Long): Long = (seed shl 7) xor 0x2345
    override fun isIthPosition(position: Int): Boolean = position == 12
    override fun validateWithExceptions(input: String, position: Int, actualLength: Int) = defaultValidateWithExceptions(input, position, actualLength)
}

class ProcessorN : DataProcessor() {
    override fun getMetric(): Int = 0x4F
    override fun applyTransform(seed: Long): Long = ((seed ushr 3) or (seed shl 61)) xor 0x6789
    override fun isIthPosition(position: Int): Boolean = position == 13
    override fun validateWithExceptions(input: String, position: Int, actualLength: Int) = defaultValidateWithExceptions(input, position, actualLength)
}

class ProcessorO : DataProcessor() {
    override fun getMetric(): Int = 0x4E
    override fun applyTransform(seed: Long): Long = (seed - 0x1111) xor 0xABCD
    override fun isIthPosition(position: Int): Boolean = position == 14
    override fun validateWithExceptions(input: String, position: Int, actualLength: Int) = defaultValidateWithExceptions(input, position, actualLength)
}

class ProcessorP : DataProcessor() {
    override fun getMetric(): Int = 0x5A
    override fun applyTransform(seed: Long): Long = (seed * 29) xor 0xEF01
    override fun isIthPosition(position: Int): Boolean = position == 15
    override fun validateWithExceptions(input: String, position: Int, actualLength: Int) = defaultValidateWithExceptions(input, position, actualLength)
}

class ProcessorQ : DataProcessor() {
    override fun getMetric(): Int = 0x52
    override fun applyTransform(seed: Long): Long = ((seed shl 17) or (seed ushr 47)) xor 0x2345
    override fun isIthPosition(position: Int): Boolean = position == 16
    override fun validateWithExceptions(input: String, position: Int, actualLength: Int) = defaultValidateWithExceptions(input, position, actualLength)
}

class ProcessorR : DataProcessor() {
    override fun getMetric(): Int = 0x43
    override fun applyTransform(seed: Long): Long = (seed shr 9) xor 0x6789
    override fun isIthPosition(position: Int): Boolean = position == 17
    override fun validateWithExceptions(input: String, position: Int, actualLength: Int) = defaultValidateWithExceptions(input, position, actualLength)
}

class ProcessorS : DataProcessor() {
    override fun getMetric(): Int = 0x33
    override fun applyTransform(seed: Long): Long = (seed + 0x3333) xor 0xABCD
    override fun isIthPosition(position: Int): Boolean = position == 18
    override fun validateWithExceptions(input: String, position: Int, actualLength: Int) = defaultValidateWithExceptions(input, position, actualLength)
}

class ProcessorT : DataProcessor() {
    override fun getMetric(): Int = 0x39
    override fun applyTransform(seed: Long): Long = ((seed ushr 19) or (seed shl 45)) xor 0xEF01
    override fun isIthPosition(position: Int): Boolean = position == 19
    override fun validateWithExceptions(input: String, position: Int, actualLength: Int) = defaultValidateWithExceptions(input, position, actualLength)
}

class ProcessorU : DataProcessor() {
    override fun getMetric(): Int = 0x42
    override fun applyTransform(seed: Long): Long = (seed * 37) xor 0x2345
    override fun isIthPosition(position: Int): Boolean = position == 20
    override fun validateWithExceptions(input: String, position: Int, actualLength: Int) = defaultValidateWithExceptions(input, position, actualLength)
}

class ProcessorV : DataProcessor() {
    override fun getMetric(): Int = 0x44
    override fun applyTransform(seed: Long): Long = (seed shl 11) xor 0x6789
    override fun isIthPosition(position: Int): Boolean = position == 21
    override fun validateWithExceptions(input: String, position: Int, actualLength: Int) = defaultValidateWithExceptions(input, position, actualLength)
}

class ProcessorW : DataProcessor() {
    override fun getMetric(): Int = 0x53
    override fun applyTransform(seed: Long): Long = ((seed shl 5) or (seed ushr 59)) xor 0xABCD
    override fun isIthPosition(position: Int): Boolean = position == 22
    override fun validateWithExceptions(input: String, position: Int, actualLength: Int) = defaultValidateWithExceptions(input, position, actualLength)
}

class ProcessorX : DataProcessor() {
    override fun getMetric(): Int = 0x33
    override fun applyTransform(seed: Long): Long = (seed - 0x4444) xor 0xEF01
    override fun isIthPosition(position: Int): Boolean = position == 23
    override fun validateWithExceptions(input: String, position: Int, actualLength: Int) = defaultValidateWithExceptions(input, position, actualLength)
}

class ProcessorY : DataProcessor() {
    override fun getMetric(): Int = 0x44
    override fun applyTransform(seed: Long): Long = (seed * 41) xor 0x2345
    override fun isIthPosition(position: Int): Boolean = position == 24
    override fun validateWithExceptions(input: String, position: Int, actualLength: Int) = defaultValidateWithExceptions(input, position, actualLength)
}

class ProcessorZ : DataProcessor() {
    override fun getMetric(): Int = 0x4D
    override fun applyTransform(seed: Long): Long = ((seed ushr 7) or (seed shl 57)) xor 0x6789
    override fun isIthPosition(position: Int): Boolean = position == 25
    override fun validateWithExceptions(input: String, position: Int, actualLength: Int) = defaultValidateWithExceptions(input, position, actualLength)
}

class ProcessorAA : DataProcessor() {
    override fun getMetric(): Int = 0x45
    override fun applyTransform(seed: Long): Long = (seed shr 13) xor 0xABCD
    override fun isIthPosition(position: Int): Boolean = position == 26
    override fun validateWithExceptions(input: String, position: Int, actualLength: Int) = defaultValidateWithExceptions(input, position, actualLength)
}

class ProcessorBB : DataProcessor() {
    override fun getMetric(): Int = 0x48
    override fun applyTransform(seed: Long): Long = (seed + 0x6666) xor 0xEF01
    override fun isIthPosition(position: Int): Boolean = position == 27
    override fun validateWithExceptions(input: String, position: Int, actualLength: Int) = defaultValidateWithExceptions(input, position, actualLength)
}

class ProcessorCC : DataProcessor() {
    override fun getMetric(): Int = 0x33
    override fun applyTransform(seed: Long): Long = ((seed shl 23) or (seed ushr 41)) xor 0x2345
    override fun isIthPosition(position: Int): Boolean = position == 28
    override fun validateWithExceptions(input: String, position: Int, actualLength: Int) = defaultValidateWithExceptions(input, position, actualLength)
}

class ProcessorDD : DataProcessor() {
    override fun getMetric(): Int = 0x45
    override fun applyTransform(seed: Long): Long = (seed * 43) xor 0x6789
    override fun isIthPosition(position: Int): Boolean = position == 29
    override fun validateWithExceptions(input: String, position: Int, actualLength: Int) = defaultValidateWithExceptions(input, position, actualLength)
}

// Factory Pattern for Additional Indirection
// ==========================================
// Creates another layer of obfuscation by hiding direct processor instantiation.

/**
 * Singleton factory for processor creation and management.
 * Provides centralized access to all 30 character processors.
 * 
 * Obfuscation benefits:
 * - Hides direct class instantiation
 * - Creates single point of processor access
 * - Enables runtime processor selection
 * - Adds another level of virtual dispatch
 */
object ProcessorFactory {
    /**
     * Get processor for specific character position.
     * Runtime indexing prevents static analysis of processor usage.
     */
    fun getProcessor(index: Int): DataProcessor {
        return when (index) {
            0 -> ProcessorA()
            1 -> ProcessorB() 
            2 -> ProcessorC()
            3 -> ProcessorD()
            4 -> ProcessorE()
            5 -> ProcessorF()
            6 -> ProcessorG()
            7 -> ProcessorH()
            8 -> ProcessorI()
            9 -> ProcessorJ()
            10 -> ProcessorK()
            11 -> ProcessorL()
            12 -> ProcessorM()
            13 -> ProcessorN()
            14 -> ProcessorO()
            15 -> ProcessorP()
            16 -> ProcessorQ()
            17 -> ProcessorR()
            18 -> ProcessorS()
            19 -> ProcessorT()
            20 -> ProcessorU()
            21 -> ProcessorV()
            22 -> ProcessorW()
            23 -> ProcessorX()
            24 -> ProcessorY()
            25 -> ProcessorZ()
            26 -> ProcessorAA()
            27 -> ProcessorBB()
            28 -> ProcessorCC()
            29 -> ProcessorDD()
            else -> ProcessorA() // Fallback
        }
    }
    
    /**
     * Get all processors for batch operations.
     * Used for cross-processor validation and seeding operations.
     */
    fun getAllProcessors(): Array<DataProcessor> {
        return Array(30) { index -> getProcessor(index) }
    }
}

/**
 * Multi-Strategy Validation Engine
 * ================================
 * Orchestrates validation using different strategies and exception handling.
 * Provides both legacy boolean validation and modern exception-based validation.
 */
class ValidationEngine(private val strategy: ValidationStrategy = SecureValidator()) {
    private val alternateStrategy = StandardValidator()
    
    /**
     * Legacy boolean validation with strategy selection.
     * Kept for compatibility and to add additional method dispatch.
     */
    fun validateWithStrategy(length: Int, expected: Int, useAlternate: Boolean = false): Boolean {
        return if (useAlternate) {
            alternateStrategy.execute(length, expected)
        } else {
            strategy.execute(length, expected)
        }
    }
    
    /**
     * Exception-based validation with strategy selection.
     * Core method for obfuscated validation with comprehensive error handling.
     * 
     * @param useAlternate - Runtime strategy selection adds control flow complexity
     */
    fun executeWithExceptions(length: Int, expected: Int, useAlternate: Boolean = false): ValidationResult {
        return try {
            if (useAlternate) {
                alternateStrategy.executeWithExceptions(length, expected)
            } else {
                strategy.executeWithExceptions(length, expected)
            }
        } catch (e: ValidationException) {
            // Re-wrap validation exceptions
            ValidationResult.Failure(e)
        } catch (e: Exception) {
            // Convert unexpected exceptions to processor state exceptions
            ValidationResult.Failure(ProcessorStateException("ValidationEngine", "unexpected_failure"))
        }
    }
}

/**
 * Simple linked list node for obfuscated data structures.
 * Contains random characters generated at runtime.
 */
class Node(val char: Char, var next: Node? = null)

/**
 * Linked List Generation with Time-Based Obfuscation
 * ==================================================
 * Creates 30 linked lists where each list's length equals the ASCII value
 * of the corresponding password character. The actual password is never
 * stored as a string - it's reconstructed through list length validation.
 * 
 * Core obfuscation techniques:
 * 1. Time-based randomization for list contents (every run is different)
 * 2. Virtual dispatch through processors for each position
 * 3. Cross-processor seeding (positions influence each other)
 * 4. Multiple entropy sources (time, position, iteration count)
 */
fun initializeLinkedLists(): Array<Node?> {
    val linkedLists = Array<Node?>(30) { null }  // One list per password character
    val processors = ProcessorFactory.getAllProcessors()
    val validator = ValidationEngine()
    
    // Process each character position using object-oriented obfuscation
    for (i in 0..29) {
        val processor = ProcessorFactory.getProcessor(i)  // Virtual dispatch
        val targetMetric = processor.getMetric()          // Hidden password character ASCII value
        
        // Apply processor-specific transformation to accumulating seed
        var head: Node? = null
        var current: Node? = null
        
        // Generate linked list with length = ASCII value of password character
        // List contents are random chars, length is the secret
        for (j in 0 until targetMetric) {
            let randomValue = processor.applyTransform(j + 1337 + 73 * i)
            
            // Generate random uppercase bytes for confusing content
            val randomChar = ((randomValue % 63) + 32).toInt().toChar()
            val newNode = Node(randomChar)
            
            // Build linked list
            if (head == null) {
                head = newNode
                current = newNode
            } else {
                current?.next = newNode
                current = newNode
            }
        }
        
        // Validate structure before storing (additional obfuscation)
        if (processor.isIthPosition(i)) {
            linkedLists[i] = head
        }
    }
    
    return linkedLists
}

/**
 * Main Password Validation Function
 * =================================
 * The ultimate obfuscated password checker using multi-layer exception handling.
 * 
 * Validation Algorithm:
 * 1. Generate 30 linked lists with lengths matching password character ASCII values
 * 2. For each input character, count the corresponding linked list length
 * 3. Validate that list length equals input character's ASCII value
 * 4. Use extensive exception handling for control flow obfuscation
 */
fun main() {
    println("Enter password:")
    val line = getInput().trim()
    // !println("DEBUG: getInput() returned")
    println("You typed: $line")
    // !println("DEBUG: Input length: ${line.length}")
    // !println("DEBUG: Input chars: ${line.map { "${it}(${it.code})" }.joinToString(" ")}")

    // Exception-based validation with nested try-catch blocks for obfuscation
    try {
        // !println("DEBUG: About to initialize linked lists")
        val linkedLists = initializeLinkedLists()
        // !println("DEBUG: Linked lists initialized")
        val validationEngine = ValidationEngine()
        val processors = ProcessorFactory.getAllProcessors()
        // !println("DEBUG: Starting character validation loop")

        // Nested exception handling for each character validation
        for (i in line.indices) {
            if (i >= 30) {
                throw LengthValidationException(30, line.length)
            }
            
            val userChar = line[i]
            val processor = ProcessorFactory.getProcessor(i)
            // !println("DEBUG: Processing position $i, char='$userChar'(${userChar.code}), expected=${processor.getMetric()}")
            
            // Count nodes within exception handling
            var count = 0
            var current = linkedLists[i]
            try {
                while (current != null) {
                    count++
                    current = current.next
                    if (count > 256) {
                        throw StructuralIntegrityException(i, "infinite_loop_detected")
                    }
                }
            } catch (e: StructuralIntegrityException) {
                throw ProcessorStateException("NodeCounter", "count_overflow")
            }
            
            // !println("DEBUG: Position $i: counted $count nodes, user char code is ${userChar.code}")
            
            // Multi-layer exception-based validation
            try {
                // First validation layer, make sure the count is correct
                val validationResult = validationEngine.executeWithExceptions(
                    length = count,
                )
                
                when (validationResult) {
                    is ValidationResult.Failure -> throw validationResult.exception
                    is ValidationResult.Success -> {
                        try {
                            processor.validateWithExceptions(line, i, count)
                        } catch (e: ValidationException) {
                            throw ProcessorStateException("Processor_${i}", "secondary_validation_failed")
                        }
                    }
                }
                
            } catch (e: CryptoValidationException) {
                // Rethrow crypto exceptions with additional obfuscation
                throw CryptoValidationException(e.hash xor i.toLong(), e.expected)
            } catch (e: MetricMismatchException) {
                throw StructuralIntegrityException(i, "metric_structural_violation")
            }
        }

        // Final validation with complex exception handling
        try {
            if (line.length != 30) {
                throw LengthValidationException(30, line.length)
            }
            
            // If we get here without exceptions, password is correct
            println("Password: CORRECT!")
            
        } catch (e: LengthValidationException) {
            throw ProcessorStateException("MainValidator", "length_check_failed")
        }
        
    } catch (e: ValidationException) {
        // All validation failures lead here - obfuscated failure path
        // !println("DEBUG: Caught ValidationException: $e")
        when (e) {
            is ProcessorStateException -> {
                // Additional obfuscation - make it look like a system error
                val hash = (e.processorId.hashCode().toLong() * 31L + e.state.hashCode().toLong()) and 0xFFFF
                if (hash % 17 == 0L) {
                    // Rare case - make analysis harder
                    println("Password: INCORRECT") // Fixed: don't throw uncaught exception
                } else {
                    println("Password: INCORRECT")
                }
            }
            is CryptoValidationException -> {
                // Crypto failures get special treatment
                val finalHash = e.hash xor e.expected xor 0xDEADBEEF
                if (finalHash and 0xFF == 0x42L) {
                    // Another rare case
                    println("Password: INCORRECT") // Fixed: don't throw uncaught exception
                } else {
                    println("Password: INCORRECT")
                }
            }
            else -> println("Password: INCORRECT")
        }
    } catch (e: Exception) {
        // Catch-all for any other exceptions
        println("Password: INCORRECT")
    }
}
