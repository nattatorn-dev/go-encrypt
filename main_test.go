package main

import (
	"testing"
)

func Test(t *testing.T) {
	key := "7583dfc02d6c5d6d33bb619ff29e03adce4135864006442097d5311c57e7ac5f"
	message := "Hello"
	encrypted := Encrypt(message, key)
	decrypted := Decrypt(encrypted, key)

	if decrypted != message {
		t.Error()
	}
}

func BenchmarkEncrypt(b *testing.B) {

	benchmarks := []struct {
		useCase string
		str     string
	}{
		{"TEXT 5 Charaters", "Hello"},
		{"JSON", "{\n  \"data\": [{\n    \"type\": \"articles\",\n    \"id\": \"1\",\n    \"attributes\": {\n      \"title\": \"JSON:API paints my bikeshed!\",\n      \"body\": \"The shortest article. Ever.\",\n      \"created\": \"2015-05-22T14:56:29.000Z\",\n      \"updated\": \"2015-05-22T14:56:28.000Z\"\n    },\n    \"relationships\": {\n      \"author\": {\n        \"data\": {\"id\": \"42\", \"type\": \"people\"}\n      }\n    }\n  }],\n  \"included\": [\n    {\n      \"type\": \"people\",\n      \"id\": \"42\",\n      \"attributes\": {\n        \"name\": \"John\",\n        \"age\": 80,\n        \"gender\": \"male\"\n      }\n    }\n  ]\n}"},
	}
	for _, benchmark := range benchmarks {
		funcuntion := GetEncrypt(benchmark.str)
		b.Run(benchmark.useCase, funcuntion)
	}
}

func GetEncrypt(str string) func(*testing.B) {
	key := "367d7e5adbd236f276aa40b5b98587a1b221c9461f132ab53d03fe8df18a14de"
	return func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Encrypt(str, key)
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	benchmarks := []struct {
		useCase         string
		encryptedString string
	}{
		{"TEXT 5 Charaters", "173750cb679ab5e7be33800907541da0dd4818e15b41aa224b6444e1c6dd098a39"},
		{"JSON", "6a7a01b733689cef9064881ac95e83effdcf3f42022a3df3cd50d60f24697cc379f1047ff398dc9555408abbea034e36b6dcfc7cce1b6c6807ae1eada2c59393dda77b2cc343e70d6fa1b29db643fb74428a728cde7d6fad233a002da8b28b68643e047bbfc9ec1dc39742b9f47cf9c8444c7d351e38a7e9d6df0f2a51db90471c283754f82fbaddac7cd23c4e668369c0b02f678461d9ec9219275e39530acf4ede8dfe87527ed51de500d6f37e800b014c9c5a4175818d57f92387de3911031daaeee950a89bb965ff3a3fb2d7ec98d9f678d5bf198fe5da8600a518b99b5fb06d583d0fee2377ee396ff38c145b14b5369dc6a6cb0d656de83b9f6e3181cab5a57cba4c6ec5f2f34b0b7d784c083ac8895711cbc3399b84188070b0aac59c8a7aa8e82d01f22d3830c0076892d2303c3e6c7365468071aca27580e894cbb915cdabedbee182a73b419ae78d600f5fdee21c81c0d63ec736e8419f419bd280dc9883ae255c3ddad52df4104dfa67698637f57853afe4bec7f4f8debc1bb295f2097e874e3e1d4d993500ae7e40a357a08f9d6a64e3eb91dd8709e315d892ccbce4528aed3b410eb3d4d83dcd8aa48c4c6fb09cdfd2114409ea71f15c219c545347b414914dd4e7097cc2e07fac110c564e238fb02917f297f9cb772796cd3a8969680d8af8ec459336a87bcf89967fc3cff9b83169f55301c24e4daa0551e7da73f88067cd85b88fee6f059211c49f6e15683bafff5980adbc04c7844aa69c635cc26a44fc3b9ceed8fc3ce5fa1cb4066f2070efe22714444fe0"},
	}
	for _, benchmark := range benchmarks {
		funcuntion := GetDecrypt(benchmark.encryptedString)
		b.Run(benchmark.useCase, funcuntion)
	}
}

func GetDecrypt(encryptedString string) func(*testing.B) {
	key := "3f2d6205b72af1d43e282331a495679c9d3db7757342e231c50a639209fd3e15"
	return func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Decrypt(encryptedString, key)
		}
	}
}
