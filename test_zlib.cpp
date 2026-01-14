#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include "Services/zlib/zlib.h"

int main() {
    std::cout << "Testing zlib 1.3 compression/decompression..." << std::endl;

    // Test data
    std::string original = "Hello, this is a test string for zlib compression! Hello, this is a test string for zlib compression!";
    std::cout << "Original data: " << original << std::endl;
    std::cout << "Original size: " << original.size() << " bytes" << std::endl;

    // Compress
    uLong compressed_size = compressBound(original.size());
    std::vector<Bytef> compressed(compressed_size);

    int compress_result = compress(compressed.data(), &compressed_size,
                                   reinterpret_cast<const Bytef*>(original.data()), original.size());

    if (compress_result != Z_OK) {
        std::cerr << "Compression failed with error: " << compress_result << std::endl;
        return 1;
    }

    std::cout << "Compressed size: " << compressed_size << " bytes" << std::endl;
    std::cout << "Compression ratio: " << (original.size() * 100.0 / compressed_size) << "%" << std::endl;

    // Decompress
    uLong decompressed_size = original.size() * 2; // Give some extra space
    std::vector<Bytef> decompressed(decompressed_size);

    int decompress_result = uncompress(decompressed.data(), &decompressed_size,
                                       compressed.data(), compressed_size);

    if (decompress_result != Z_OK) {
        std::cerr << "Decompression failed with error: " << decompress_result << std::endl;
        return 1;
    }

    std::string result(reinterpret_cast<char*>(decompressed.data()), decompressed_size);
    std::cout << "Decompressed data: " << result << std::endl;
    std::cout << "Decompressed size: " << decompressed_size << " bytes" << std::endl;

    // Verify
    if (original == result) {
        std::cout << "✅ SUCCESS: Compression and decompression worked correctly!" << std::endl;
        return 0;
    } else {
        std::cerr << "❌ FAILURE: Decompressed data doesn't match original!" << std::endl;
        return 1;
    }
}