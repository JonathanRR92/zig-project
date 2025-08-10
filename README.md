# Zig Dirhasher

A multi-threaded directory hashing tool written in Zig.  
Supports:
- Recursive file scanning
- SHA256 hashing
- JSON output
- Path exclusion patterns
- Absolute or relative paths
- Configurable thread count
- Live progress display

## Usage

```bash
zig build-exe main.zig

example input 

.\main.exe --threads 8 --json --abs --exclude ".mp4" "C:/Path/To/Folder"


Flag	Description
--json	Output in JSON format
--abs	Use absolute paths
--exclude PATTERN	Skip files/dirs containing PATTERN
--threads N	Number of worker threads
[DIR]	One or more directories to scan (defaults to current directory)

Example JSON output 

[
  {"path":"example.txt","hash":"abc123..."},
  {"path":"subdir/image.png","hash":"def456..."}
]

In the zigLearning folder there are three files which show the functions on how to open, close, and delete directories in zig. As well as editind and creating files in zig. 
