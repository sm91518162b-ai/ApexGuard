# ApexGuard v4.1 STABLE "The 2-Hour AV" 🛡️

**FlashSec Labs** | CEO: @sm91518162b-ai | CTO: @~Chaito ツ

> 584K. Zero dependencies. KEY FORENSE. Built in 2 hours. Shipped the same day.

## What is this?
ApexGuard is a forensics-grade antivirus for Android/Termux. No libs. No network. No telemetry. Just pure C++17 that finds and neutralizes threats.

It was born after 3am frustration with bloated AVs that ask for 15 permissions to scan your own files.

## Features
- **Static Binary**: 584K. Runs on any Android 7+ with Termux
- **KEY FORENSE**: Chain-of-custody hash logging for legal evidence
- **Zero Deps**: Compiled with `-static`. No `libssl`, no `libcurl`, no bloat
- **Fast**: O(n) scan. No databases. Heuristic + hash detection
- **Private**: Never phones home. Your files stay your files

## Build in 10 seconds
```bash
git clone https://github.com/sm91518162b-ai/ApexGuard
cd ApexGuard
make
