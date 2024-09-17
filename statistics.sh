#!/bin/bash

# Find the categories dynamically
categories=(
  "crypto"
  "hypervisor-pwn"
  "misc"
  "pwn"
  "pyjail"
  "rev"
  "Android"
  "web"
)
echo "Using categories: ${categories[@]}"

declare -A angstromctf23
for category in "${categories[@]}"; do
    angstromctf23[$category]=0
done
angstromctf23[pyjail]=1 # obligatory

declare -A b01lers22
for category in "${categories[@]}"; do
    b01lers22[$category]=0
done
b01lers22[pwn]=1 # veryfastvm
b01lers22[web]=1 # hackerplace

declare -A csaw22finals
for category in "${categories[@]}"; do
    csaw22finals[$category]=0
done
csaw22finals[pyjail]=2 # embryo-leak, super-guesser-game

declare -A csaw22quals
for category in "${categories[@]}"; do
    csaw22quals[$category]=0
done
csaw22quals[pwn]=1 # how2pwn

declare -A diceCTF23
for category in "${categories[@]}"; do
    diceCTF23[$category]=0
done
diceCTF23[hypervisor-pwn]=1 # dice-visor
diceCTF23[misc]=1 # mlog
diceCTF23[rev]=3 # not-baby-parallelism, parallelism, time-travel

declare -A googleCTF22
for category in "${categories[@]}"; do
    googleCTF22[$category]=0
done
googleCTF22[misc]=1 # appnote
googleCTF22[pwn]=1  # segfault-labyrinth
googleCTF22[pyjail]=1  # treebox

declare -A hackasat23
for category in "${categories[@]}"; do
    hackasat23[$category]=0
done
hackasat23[pwn]=2 # RISC-V-Smash baby, dROP-Baby

declare -A insomnihack2022
for category in "${categories[@]}"; do
    insomnihack2022[$category]=0
done
insomnihack2022[rev]=1 # herald
insomnihack2022[web]=1 # PimpMyVariant

declare -A justCTF22
for category in "${categories[@]}"; do
    justCTF22[$category]=0
done
justCTF22[pwn]=1 # arm

declare -A m0lecon22
for category in "${categories[@]}"; do
    m0lecon22[$category]=0
done
m0lecon22[crypto]=1 # fancynotes
m0lecon22[web]=1 # dumbforum

declare -A midnightquals23
for category in "${categories[@]}"; do
    midnightquals23[$category]=0
done
midnightquals23[pwn]=1 # scaas
midnightquals23[rev]=1 # oss

declare -A uiuctf20
for category in "${categories[@]}"; do
    uiuctf20[$category]=0
done
uiuctf20[pwn]=2 # accounting-accidents, baby-kernel

declare -A uiuctf22
for category in "${categories[@]}"; do
    uiuctf22[$category]=0
done
uiuctf22[pwn]=2 # no-syscalls-allowed, odd-shell
uiuctf22[pyjail]=3 # a-horse-with-no-names, a-horse-with-no-neighs, safepy

declare -A uiuctf23
for category in "${categories[@]}"; do
    uiuctf23[$category]=0
done
uiuctf23[pwn]=3    # chainmail, virophage, zapping-a-suid1
uiuctf23[pyjail]=1 # rattler-read

declare -A umass22
for category in "${categories[@]}"; do
    umass22[$category]=0
done
umass22[rev]=1 # baby-vm
umass22[web]=2 # umassdining, venting

declare -A lakecCTF23
for category in "${categories[@]}"; do
    lakecCTF23[$category]=0
done
lakecCTF23[pwn]=1 # trustMEE

declare -A insomnihack2024
for category in "${categories[@]}"; do
    insomnihack2024[$category]=0
done
insomnihack2024[pwn]=1     # CryptoNotes
insomnihack2024[Android]=1 # CryptoNotes

declare -A midnightquals24
for category in "${categories[@]}"; do
    midnightquals24[$category]=0
done
midnightquals24[pwn]=1 # roborop

declare -A sekaictf24
for category in "${categories[@]}"; do
    sekaictf24[$category]=0
done
sekaictf24[Android]=1 # hijacker


# Gather statistics per category
declare -A category_counts
for category in "${categories[@]}"; do

    acc=0
    acc=$((acc+angstromctf23[$category]))
    acc=$((acc+b01lers22[$category]))
    acc=$((acc+csaw22finals[$category]))
    acc=$((acc+csaw22quals[$category]))
    acc=$((acc+diceCTF23[$category]))
    acc=$((acc+googleCTF22[$category]))
    acc=$((acc+hackasat23[$category]))
    acc=$((acc+insomnihack2022[$category]))
    acc=$((acc+justCTF22[$category]))
    acc=$((acc+m0lecon22[$category]))
    acc=$((acc+midnightquals23[$category]))
    acc=$((acc+uiuctf20[$category]))
    acc=$((acc+uiuctf22[$category]))
    acc=$((acc+uiuctf23[$category]))
    acc=$((acc+umass22[$category]))
    acc=$((acc+lakecCTF23[$category]))
    acc=$((acc+insomnihack2024[$category]))
    acc=$((acc+midnightquals24[$category]))
    acc=$((acc+sekaictf24[$category]))
    category_counts[$category]=$acc

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
