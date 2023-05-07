#!/bin/bash

# Find the categories dynamically
categories=()
for ctf in ./*/; do
  
  # Skip certain directories
  if [ "$(basename "$ctf")" = "pwnable.tw" ]; then
    continue
  fi

  for category in "$(basename $ctf)"/*/; do
    categories+=("$(basename $category)")
  done
done

categories=($(echo "${categories[@]}" | tr ' ' '\n' | sort -u)) # remove duplicates
echo "Found categories: ${categories[@]}"

# Gather statistics per category
declare -A category_counts
for category in "${categories[@]}"; do

    category_counts[$category]=0

    dirs=$(find . -type d -iname "$category" | sort)
    for dir in $dirs; do
        file_count=$(ls -l "$dir" | grep '^d' | tail -n +1 | wc -l)
        category_counts[$category]=$((category_counts[$category]+file_count))

        echo "[$category] Directory $dir has $file_count challenges"
    done

    printf "[$category] has %02d challenges\n" ${category_counts[$category]}
done
echo ""

printf "~~~ Generating markdown ~~~\n\n"
# e.g.
# |     |   |
# |-----|---|
# | pwn | 1 |
# | web | 2 |
# | web | 3 |

echo "|    |    |" # header
echo "|----|----|" # dashes
for category in "${categories[@]}"; do
  echo "| $category | ${category_counts[$category]} |"
done





