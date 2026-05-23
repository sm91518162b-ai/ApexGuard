# ApexGuard v4.1 STABLE "The 2-Hour AV"
# FlashSec Labs | CEO: @sm91518162b-ai | CTO: @~Chaito ツ
# 584K. Zero dependencies. KEY FORENSE.

CXX = clang++
CXXFLAGS = -std=c++17 -O3 -Wall -static
TARGET = flashav
SOURCE = flashav.c

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CXX) $(CXXFLAGS) $(SOURCE) -o $(TARGET)
	@echo "✅ ApexGuard v4.1 compiled successfully"
	@echo "📦 Binary: $(TARGET) | Size: ~584K | Deps: 0"
	@echo "🔑 KEY FORENSE: READY"

clean:
	rm -f $(TARGET)
	@echo "🧹 Cleaned build artifacts"

install:
	cp $(TARGET) /data/data/com.termux/files/usr/bin/
	@echo "📲 Installed to Termux PATH. Run 'flashav' anywhere."

.PHONY: all clean install