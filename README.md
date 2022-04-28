[![GitHub Actions](https://github.com/Cysharp/LitJWT/workflows/Build-Debug/badge.svg)](https://github.com/Cysharp/LitJWT/actions) [![Releases](https://img.shields.io/github/release/Cysharp/LitJWT.svg)](https://github.com/Cysharp/LitJWT/releases)

LitJWT
===

Lightweight, Fast [JWT(JSON Web Token)](https://jwt.io/) implementation for .NET. This library mainly focus on performance, 5 times faster encoding/decoding and very low allocation.

![image](https://user-images.githubusercontent.com/46207/58414904-c4c31300-80b7-11e9-9bd2-12f794518494.png)

NuGet: [LitJWT](https://www.nuget.org/packages/LitJWT)

Supported platform is `netstandard 2.1`, `net5.0` or greater.

```
Install-Package LitJWT
```

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
## Table of Contents

- [How to use](#how-to-use)
- [Custom Serializer](#custom-serializer)
- [AlgorithmResolver](#algorithmresolver)
- [Details of Performance](#details-of-performance)
- [HMACSHA or RSA](#hmacsha-or-rsa)
- [License](#license)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

How to use
---

```csharp
// using LitJWT;
// using LitJWT.Algorithms;

// Get recommended-size random key.
var key = HS256Algorithm.GenerateRandomRecommendedKey();

// Create encoder, JwtEncoder is thread-safe and recommend to store static/singleton.
var encoder = new JwtEncoder(new HS256Algorithm(key));

// Encode with payload, expire, and use specify payload serializer.
var token = encoder.Encode(new { foo = "pay", bar = "load" }, TimeSpan.FromMinutes(30));
```

```csharp
// Create decoder, JwtDecoder is also thread-safe so recommend to store static/singleton.
var decoder = new JwtDecoder(encoder.SignAlgorithm);

// Decode and verify, you can check the result.
var result = decoder.TryDecode(token, out var payload);
if (result == DecodeResult.Success)
{
    Console.WriteLine((payload.foo, payload.bar));
}
```

Custom Serializer
---
In default. LitJWT is using `System.Text.Json.JsonSerializer`. If you want to use custom `JsonSerializerOptions`, `JwtEncoder` and `JwtDecoder` have `JsonSerializerOptions serializerOptions` constructor overload.

If you want to use another serializer, encode method receives `Action<T, JwtWriter> payloadWriter`. You have to invoke `writer.Write(ReadOnlySpan<byte> payload)` method to serialize. `ReadOnlySpan<byte>` must be Utf8 binary.

Here is the sample of use JSON.NET, this have encoding overhead.

```csharp
var token = encoder.Encode(new PayloadSample { foo = "pay", bar = "load" }, TimeSpan.FromMinutes(30),
    (x, writer) => writer.Write(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(x))));
```

Decode method receives `delegate T PayloadParser<T>(ReadOnlySpan<byte> payload)`. `ReadOnlySpan<byte>` is utf8 json. Yes, utf8 based serializer is best but you can also use JSON.NET(but have encoding penalty).

```
var result = decoder.TryDecode(token, x => JsonConvert.DeserializeObject<PayloadSample>(Encoding.UTF8.GetString(x)), out var payload);
```

AlgorithmResolver
---
Decoding algorithm is whitelist, you should add algorithms when create `JwtDecoder`.

```csharp
var resolver = new JwtAlgorithmResolver(
    new HS256Algorithm(),
    new HS384Algorithm(),
    new HS512Algorithm(),
    new RS256Algorithm(),
    new RS384Algorithm(),
    new RS512Algorithm());
var decoder = new JwtDecoder(resolver);
```

`JwtAlgorithmResolver` and `JwtDecoder` are both thread-safe.

Details of Performance
---
* Directly encode/decode Base64Url(don't use string replace)
* Parsing JSON on Utf8 binary(decoded Base64Url result) directly
* `ReadOnlySpan<byte>` key custom dictionary
* Uses `Span<T>` API for encrypt
* Uses `stackalloc byte[]` and `ArrayPool<byte>`

For example, standard implementation of Base64Url encoding is like here.

```csharp
Convert.ToBase64String(input).TrimEnd('=').Replace('+', '-').Replace('/', '_')
```

It has three unnecessary allocations(trim, replace, replace) and searching. I've implemented [Base64Url](https://github.com/Cysharp/LitJWT/blob/master/src/LitJWT/Base64.cs) converter and it has `Span<T>` based APIs to achive zero allocation.

`ReadOnlySpan<byte>` can not become dictionary key but decoding JWT requires `alg`, `exp`, `nbf` match to avoid extra decoding. I've implement [custom Utf8String Dictionary](https://github.com/Cysharp/LitJWT/blob/master/src/LitJWT/ReadOnlyUtf8StringDictionary.cs) it store data on initialize and match by `bool TryGetValue(ReadOnlySpan<byte> key, out TValue value)`. 

**Encode**

|                    Method |      Mean | Error | Ratio |  Gen 0 | Gen 1 | Gen 2 | Allocated |
|-------------------------- |----------:|------:|------:|-------:|------:|------:|----------:|
|                    LitJwt |  1.560 us |    NA |  1.00 | 0.0477 |     - |     - |     320 B |
|                 JwtDotNet |  8.164 us |    NA |  5.23 | 0.9613 |     - |     - |    6216 B |
| MicrosoftIdentityModelJwt | 12.673 us |    NA |  8.12 | 1.8311 |     - |     - |   11665 B |

**Decode**

|                    Method |      Mean | Error | Ratio |  Gen 0 |  Gen 1 | Gen 2 | Allocated |
|-------------------------- |----------:|------:|------:|-------:|-------:|------:|----------:|
|                    LitJwt |  2.245 us |    NA |  1.00 | 0.0229 |      - |     - |     192 B |
|                 JwtDotNet | 12.788 us |    NA |  5.70 | 2.2583 | 0.0153 |     - |   14385 B |
| MicrosoftIdentityModelJwt | 13.099 us |    NA |  5.83 | 2.2125 |      - |     - |   14113 B |

`LitJWT` is completely working on Utf8 so `Encode` method has three overloads.

* `string Encode<T>(...)`
* `byte[] EncodeAsUtf8Bytes<T>(...)`
* `void Encode<T>(IBufferWriter<byte> writer, ...)`

`IBufferWriter` is fastest if you can write directly to I/O pipelines. `byte[]` is better than `string` because it can avoid utf8-string encoding cost.

For example [gRPC C#](https://github.com/grpc/grpc/tree/master/src/csharp) or [MagicOnion](https://github.com/Cysharp/MagicOnion/) can set binary header. It has better performance than use string value.

```csharp
// gRPC Header
var metadata = new Metadata();
metadata.Add("auth-token-bin", encoder.EncodeAsUtf8Bytes());
```

HMACSHA or RSA
---
If you don't need asymmetric encryption, HMACSHA is better.

**Encode**

| Method |       Mean | Error |  Gen 0 | Gen 1 | Gen 2 | Allocated |
|------- |-----------:|------:|-------:|------:|------:|----------:|
|  HS256 |   1.928 us |    NA | 0.1335 |     - |     - |     888 B |
|  HS384 |   1.787 us |    NA | 0.1373 |     - |     - |     888 B |
|  HS512 |   1.714 us |    NA | 0.1373 |     - |     - |     888 B |
|  RS256 | 618.728 us |    NA |      - |     - |     - |    1008 B |
|  RS384 | 629.516 us |    NA |      - |     - |     - |    1008 B |
|  RS512 | 639.434 us |    NA |      - |     - |     - |    1008 B |

**Decode**

| Method |      Mean | Error | Gen 0 | Gen 1 | Gen 2 | Allocated |
|------- |----------:|------:|------:|------:|------:|----------:|
|  HS256 |  1.876 us |    NA |     - |     - |     - |         - |
|  HS384 |  1.677 us |    NA |     - |     - |     - |         - |
|  HS512 |  1.735 us |    NA |     - |     - |     - |         - |
|  RS256 | 56.549 us |    NA |     - |     - |     - |     120 B |
|  RS384 | 55.625 us |    NA |     - |     - |     - |     120 B |
|  RS512 | 55.746 us |    NA |     - |     - |     - |     120 B |

For example, use session key(to browser, unity client, etc...), client don't decode and only to store.

License
---
This library is under the MIT License.