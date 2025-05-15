#!/bin/bash
#
# extract_results.sh
#
# Usage:
#   ./extract_results.sh [input_file]
#   cat input_file | ./extract_results.sh
#
# Reads JSON of the form:
#   {"results":[{…},{…},…], …}
# and writes each `{…}` in “results” as its own line.

# check for jq
if ! command -v jq &>/dev/null; then
  echo "Error: this script requires jq. Install it from https://stedolan.github.io/jq/" >&2
  exit 1
fi

# Check if an input JSON filename was provided as an argument
if [ -z "$1" ]; then
  echo "Error: Please provide the input JSON filename as an argument."
  echo "Usage: $0 <input_filename.json>"
  exit 1
fi

# Assign the first argument (input filename) to a variable
input_file="$1"

# Check if the input file exists
if [ ! -f "$input_file" ]; then
  echo "Error: The input file '$input_file' does not exist."
  exit 1
fi

# Get the filename without the extension
base_name=$(basename "$input_file" .json)

# Construct the output filename
output_file="converted_${base_name}.json"
# For the FIM module to detect the file and generate the alerts
touch "$output_file"
sleep 120

# Use jq to read the JSON file and extract each object, redirecting the output to the output file
jq -c '.results[]' "$input_file" > "$output_file"

echo "The output has been saved to '$output_file'."