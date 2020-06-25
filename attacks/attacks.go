package attacks

import (
	"github.com/m-m-adams/squatcobbler/domain"
)

func swapChars(input string, replacement rune, index int) (output string) {
	r := []rune(input)
	r[index] = replacement
	output = string(r)
	return
}

//Impersonation is a function which manipulates a domain to fool people
type Impersonation func(domain.Domain) []domain.Domain

//All includes all attacks
var All = []Impersonation{HomographAttack, TypoAttack, CombinationAttack, SwapAttack, SwapTLDAttack, InsertionAttack}

//TypoAttack performs a replacement attack simulating a user pressing the wrong keys
func TypoAttack(dom domain.Domain) []domain.Domain {
	results := []domain.Domain{}

	keyboard := map[rune]string{'q': "12wa", '2': "3wq1", '3': "4ew2", '4': "5re3", '5': "6tr4", '6': "7yt5", '7': "8uy6", '8': "9iu7", '9': "0oi8", '0': "po9",
		'w': "3esaq2", 'e': "4rdsw3", 'r': "5tfde4", 't': "6ygfr5", 'y': "7uhgt6", 'u': "8ijhy7", 'i': "9okju8", 'o': "0plki9", 'p': "lo0",
		'a': "qwsz", 's': "edxzaw", 'd': "rfcxse", 'f': "tgvcdr", 'g': "yhbvft", 'h': "ujnbgy", 'j': "ikmnhu", 'k': "olmji", 'l': "kop",
		'z': "asx", 'x': "zsdc", 'c': "xdfv", 'v': "cfgb", 'b': "vghn", 'n': "bhjm", 'm': "njk"}

	for i, char := range dom.SLD {

		for j := range keyboard[char] {
			typod := dom
			typod.SLD = swapChars(typod.SLD, []rune(keyboard[char])[j], i)
			results = append(results, typod)
		}

	}

	return results
}

//HomographAttack performs a homograph permutation attack
func HomographAttack(dom domain.Domain) (results []domain.Domain) {
	// set local variables
	homographs := map[rune][]rune{
		'a': {'à', 'á', 'â', 'ã', 'ä', 'å', 'ɑ', 'а', 'ạ', 'ǎ', 'ă', 'ȧ', 'α', 'ａ'},
		'b': {'d', 'ʙ', 'Ь', 'ɓ', 'Б', 'ß', 'β', 'ᛒ', '\u1E05', '\u1E03', '\u1D6C'}, // 'lb', 'ib'
		'c': {'ϲ', 'с', 'ƈ', 'ċ', 'ć', 'ç', 'ｃ'},
		'd': {'b', 'ԁ', 'ժ', 'ɗ', 'đ'}, // 'cl', 'dl', 'di'
		'e': {'é', 'ê', 'ë', 'ē', 'ĕ', 'ě', 'ė', 'е', 'ẹ', 'ę', 'є', 'ϵ', 'ҽ'},
		'f': {'Ϝ', 'ƒ', 'Ғ'},
		'g': {'q', 'ɢ', 'ɡ', 'Ԍ', 'Ԍ', 'ġ', 'ğ', 'ց', 'ǵ', 'ģ'},
		'h': {'һ', 'հ', '\u13C2', 'н'}, // 'lh', 'ih'
		'i': {'1', 'l', '\u13A5', 'í', 'ï', 'ı', 'ɩ', 'ι', 'ꙇ', 'ǐ', 'ĭ'},
		'j': {'ј', 'ʝ', 'ϳ', 'ɉ'},
		'k': {'κ', 'κ'}, // 'lk', 'ik', 'lc'
		'l': {'1', 'i', 'ɫ', 'ł'},
		'm': {'n', 'ṃ', 'ᴍ', 'м', 'ɱ'}, // 'nn', 'rn', 'rr'
		'n': {'m', 'r', 'ń'},
		'o': {'0', 'Ο', 'ο', 'О', 'о', 'Օ', 'ȯ', 'ọ', 'ỏ', 'ơ', 'ó', 'ö', 'ӧ', 'ｏ'},
		'p': {'ρ', 'р', 'ƿ', 'Ϸ', 'Þ'},
		'q': {'g', 'զ', 'ԛ', 'գ', 'ʠ'},
		'r': {'ʀ', 'Г', 'ᴦ', 'ɼ', 'ɽ'},
		's': {'Ⴝ', '\u13DA', 'ʂ', 'ś', 'ѕ'},
		't': {'τ', 'т', 'ţ'},
		'u': {'μ', 'υ', 'Ս', 'ս', 'ц', 'ᴜ', 'ǔ', 'ŭ'},
		'v': {'ѵ', 'ν', '\u1E7F', '\u1E7D'}, // 'v̇'
		'w': {'ѡ', 'ա', 'ԝ'},                // 'vv'
		'x': {'х', 'ҳ', '\u1E8B'},
		'y': {'ʏ', 'γ', 'у', 'Ү', 'ý'},
		'z': {'ʐ', 'ż', 'ź', 'ʐ', 'ᴢ'},
	}

	for i, char := range dom.SLD {
		for j := range homographs[char] {
			typod := dom
			typod.SLD = swapChars(typod.SLD, []rune(homographs[char])[j], i)
			results = append(results, typod)
		}

	}

	return results
}

//CombinationAttack combines subdomains into the SLD
func CombinationAttack(dom domain.Domain) (results []domain.Domain) {
	for i := range dom.Subdomain {
		typod := dom
		typod.SLD = dom.Subdomain[i:] + typod.SLD
		results = append(results, typod)
	}

	return results
}

//InsertionAttack adds an extra character in the domain
func InsertionAttack(dom domain.Domain) (results []domain.Domain) {
	chars := "abcdefghijklmnopqrstuvwxyz0123456789-"
	for _, char := range chars {
		for i := range dom.SLD {
			typod := dom
			typod.SLD = dom.SLD[:i] + string(char) + dom.SLD[i:]
			results = append(results, typod)
		}

	}

	return results
}

//SwapAttack switches neighboring letters
func SwapAttack(dom domain.Domain) (results []domain.Domain) {
	for i := 1; i < len([]rune(dom.SLD)); i++ {

		typod := dom

		temp := []rune(dom.SLD)

		temp[i-1], temp[i] = temp[i], temp[i-1]

		typod.SLD = string(temp)
		results = append(results, typod)

	}

	return results
}

//SwapTLDAttack switches intended tlds to other ones
func SwapTLDAttack(dom domain.Domain) (results []domain.Domain) {
	tlds := []string{"net", "com", "ca", "org", "cr", "cx", "cab", "cat"}
	for _, tld := range tlds {

		typod := dom

		typod.TLD = tld
		results = append(results, typod)

	}

	return results
}
