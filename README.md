# SquatCobbler
generates list of registered typo squatting domains from an input and returns them in json. Uses built in DNS resolver on windows, and a golang dns resolver on linux. This allows more threads and as a result will run much faster on linux. 

Optionally look up whois info on all domains that exist

## Usage
SquatCobbler has the following arguments:  

  -i string  
   &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;a file to read input from or a single domain input 
        
  -o string  
   &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;a file to write output to, otherwise goes to stdout  
        
  -whois  
  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if true lookup whois for all domains  
### Examples

```
./squatcobbler -i inputlist.txt -o existingdomains.json -whois
```

Read a domain per line from inputlist, generate variations, check whois information, and write output to existingdomains.json

```
./squatcobbler -i google.com 
```
Generate variations from google.com without checking whois and write to stdout (still in json)

## Variations

The following variations are generated:

1. Homograph  
Swap characters in SLD for similar looking characters (including unicode/punnycode) - e.g. 0 for o

2. Typo  
Swap charcters in SLD for nearby ones

3. Combination  
Merge portions of a subdomain with the SLD

4. Swap  
Swap neighboring characters in the SLD

5. SwapTLD  
Swap the TLD for other possibilities

6. Insertion  
Insert characters in SLD

