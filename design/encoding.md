# ASN.1 Encoding
ASN.1's main serialization format is "Distinguished Encoding Rules" (DER) and "Basic Encoding Rules" (BER) is a variant of DER with canonicalization added. For instance, if a type includes a SET OF, the members must be sorted for DER serialization. <br> 
A certificate represented in DER is often further encoded into PEM, which uses base64 to encode arbitrary bytes as alphanumeric characters (and ‘+’ and ‘/') and adds separator lines <br> 

    ("-----BEGIN CERTIFICATE-----" and “-----END CERTIFICATE-----")
PEM is useful because it’s easier to copy-paste.<br><br>
This document is based on [this source](https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/).

# **ASN.1 Types**

### **OBJECT IDENTIFIER**
Object identifiers are globally unique, hierarchical identifiers made of a sequence of integers. They can refer to any kind of “thing,” but are commonly used to identify standards, algorithms, certificate extensions, organizations, or policy documents. As an example: 1.2.840.113549 identifies RSA Security LLC. RSA can then assign OIDs starting with that prefix, like 1.2.840.113549.1.1.11, which identifies sha256WithRSAEncryption, as defined in [RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017#page-69).

### **INTEGER**
Integers can be positive or negative. The length of any DER field can be expressed as a series of up to 126 bytes, so the biggest integer you can represent in DER is $`256^{2**1008}-1`$. For a truly unbounded integer you'd have to encode in BER, which allows indefinitely long fields.

### **Strings**

ASN.1 has a lot of string types: BMPString, GeneralString, GraphicString, IA5String, ISO646String, NumericString, PrintableString, TeletexString, T61String, UniversalString, UTF8String, VideotexString, and VisibleString. For the purposes of HTTPS certificates you mostly have to care about PrintableString, UTF8String, and IA5String. The string type for a given field is defined by the ASN.1 module that defines the field. For instance:

    CPSuri ::= IA5String

PrintableString is a restricted subset of ASCII, allowing alphanumerics, spaces, and a specific handful of punctuation: ' () + , - . / : = ?. Notably it doesn’t include * or @. There are no storage-size benefits to more restrictive string types.

Some fields, like DirectoryString in RFC 5280, allow the serialization code to choose among multiple string types. Since DER encoding includes the type of string you’re using, make sure that when you encode something as PrintableString it really meets the PrintableString requirements.

IA5String, based on International Alphabet No. 5, is more permissive: It allows nearly any ASCII character, and is used for email address, DNS names, and URLs in certificates. Note that there are a few byte values where the IA5 meaning of the byte value is different than the US-ASCII meaning of that same value.

TeletexString, BMPString, and UniversalString are deprecated for use in HTTPS certificates, but you may see them when parsing older CA certificates, which are long-lived and may predate the deprecation.

Strings in ASN.1 are not null-terminated like strings in C and C++. In fact, it’s perfectly legal to have embedded null bytes. This can cause vulnerabilities when two systems interpret the same ASN.1 string differently. For instance, some CAs used to be able to be tricked into issuing for “example.com\0.evil.com” on the basis of ownership of evil.com. Certificate validation libraries at the time treated the result as valid for “example.com”. Be very careful handling ASN.1 strings in C and C++ to avoid creating vulnerabilities.

### **Dates and Times**

Again, there are lots of time types: UTCTime, GeneralizedTime, DATE, TIME-OF-DAY, DATE-TIME and DURATION. For HTTPS certificates you only have to care about UTCTime and GeneralizedTime.

UTCTime represents a date and time as YYMMDDhhmm[ss], with an optional timezone offset or “Z” to represent Zulu (aka UTC aka 0 timezone offset). For instance the UTCTimes 820102120000Z and 820102070000-0500 both represent the same time: January 2nd, 1982, at 7am in New York City (UTC-5) and at 12pm in UTC.

Since UTCTime is ambiguous as to whether it’s the 1900’s or 2000’s, RFC 5280 clarifies that it represents dates from 1950 to 2050. RFC 5280 also requires that the “Z” timezone must be used and seconds must be included.

GeneralizedTime supports dates after 2050 through the simple expedient of representing the year with four digits. It also allows fractional seconds (with either a comma or a full stop as the decimal separator). RFC 5280 forbids fractional seconds and requires the “Z.”

### **NULL**
NULL stands for an empty field

### **SEQUENCE**
A SEQUENCE is equivalent to a "struct" in most programming languages. It holds a fixed number of fields of different types. <br>

### **SEQUENCE OF**
A SEQUENCE OF holds an arbitrary number of fields of a single type. This is analogous to an array or a list in a programming language. SEQUENCE and SEQUENCE OF are both encoded the same way.

### **SET and SET OF**
These are pretty much the same as SEQUENCE and SEQUENCE OF, except that they do not specify the ordering of elements in them. However, in encoded form they must be sorted.

### **CHOICE**

CHOICE is a type that can contain exactly one of the types listed in its definition. For instance, Time can contain exactly one of a UTCTime or a GeneralizedTime:

    Time ::= CHOICE {
        utcTime        UTCTime,
        generalTime    GeneralizedTime }

### **ANY**
ANY indicates that a value can be of any type. In practice, it is usually constrained by things that can’t quite be expressed in the ASN.1 grammar. For instance:

    AttributeTypeAndValue ::= SEQUENCE {
        type     AttributeType,
        value    AttributeValue }

    AttributeType ::= OBJECT IDENTIFIER

    AttributeValue ::= ANY -- DEFINED BY AttributeType

This is particularly useful for extensions, where you want to leave room for additional fields to be defined separately after the main specification is published, so you have a way to register new types (object identifiers), and allow the definitions for those types to specify what the structure of the new fields should be.

Note that ANY is a relic of the 1988 ASN.1 notation. In the 1994 edition, ANY was deprecated and replaced with Information Object Classes, which are a formalized way of specifying the kind of extension behavior people wanted from ANY. RFC 5280 however still uses the old syntax. RFC 5912 uses the 2002 ASN.1 syntax to express the same types from RFC 5280 and several related specifications.

### **Other Notation**

Comments begin with --. Fields of a SEQUENCE or SET can be marked OPTIONAL, or they can be marked DEFAULT foo, which means the same thing as OPTIONAL except that when the field is absent it should be considered to contain “foo.” Types with a length (strings, octet and bit strings, sets and sequences OF things) can be given a SIZE parameter that constrains their length, either to an exact length or to a range.

Types can be constrained to have certain values by using curly braces after the type definition. This example defines that the Version field can have three values, and assigns meaningful names to those values:

    Version ::= INTEGER { v1(0), v2(1), v3(2) }

This is also often used in assigning names to specific OIDs (note this is a single value, with no commas indicating alternate values). Example from RFC 5280.

    id-pkix  OBJECT IDENTIFIER  ::=
            { iso(1) identified-organization(3) dod(6) internet(1)
                        security(5) mechanisms(5) pkix(7) }

You’ll also see `[number]`, `IMPLICIT`, `EXPLICIT`, `UNIVERSAL`, and `APPLICATION`. These define details of how a value should be encoded, which we’ll talk about below.

<br>

# **The Encoding**
ASN.1 is associated with many encodings: BER, DER, PER, XER, and more. Basic Encoding Rules (BER) are fairly flexible. Distinguished Encoding Rules (DER) are a subset of BER with canonicalization rules so there is only one way to express a given structure. Packed Encoding Rules (PER) use fewer bytes to encode things, so they are useful when space or transmission time is at a premium. XML Encoding Rules (XER) are useful when for some reason you want to use XML.

HTTPS certificates are generally encoded in DER. It’s possible to encode them in BER, but since the signature value is calculated over the equivalent DER encoding, not the exact bytes in the certificate, encoding a certificate in BER invites unnecessary trouble. I’ll describe BER, and explain as I go the additional restrictions provided by DER.

### **Type-Length-Value**
BER is a type-length-value encoding, just like Protocol Buffers and Thrift. That means, every encoded object is prepended with a type tag and a length field. The type tag is a byte, or series of bytes. <br>
**Example:** an integer with the decimal value 65537 (0x010001) would be encoded as `0x0203010001`:<br>

| type tag  | length    | value     |
| ----- | --------- | --------- |
| 02    |	03      | 01 00 01  |
|  |  |  |

### **Tag**

The tag is usually one byte. There is a means to encode arbitrarily large tag numbers using multiple bytes (the “high tag number” form), but this is not typically necessary.

Here are some example "universal" tags:
| Tag (decimal) |	Tag (hex) |	Type |
| -- | -- | -- |
| 2  |	02 | 	INTEGER |
| 3 |	03 |	BIT STRING
| 4 |	04 |	OCTET STRING
| 5 |	05 |	NULL
| 6 |	06 |	OBJECT IDENTIFIER
| 12 |	0C |	UTF8String
| 16 |	10 (30)* |	SEQUENCE and SEQUENCE OF
| 17 |	11 (31)* | 	SET and SET OF
| 19 |	13 |	PrintableString
| 22 |	16 |	IA5String
| 23 |	17 |	UTCTime
| 24 |	18 |	GeneralizedTime

These tags all happen to be **under 31 (0x1F)**, and that’s for a good reason: Bits 8, 7, and 6 (the high bits of the tag byte) are used to encode **extra information**, so any universal tag numbers higher than 31 would need to use the “high tag number” form, which takes extra bytes. There are a small handful of universal tags higher than 31, but they’re quite rare.

*The two tags marked with a * are always encoded as 0x30 or 0x31, because bit 6 is used to indicate whether a field is Constructed vs Primitive. These tags are always Constructed, so their encoding has bit 6 set to 1 (more on this later).

## **Tag Classes**
The above tags all belong to the "universal" class. There are other classes available to define custom tags. These are specified using Bits 8 and 7:

| Class | 	Bit 8 |	Bit 7 |
| --- | -- | -- |
Universal | 	0 |	0
Application |	0 | 	1
Context-specific | 	1 | 	0
Private | 	1 | 	1

For instance, for a point that is defined as

    Point ::= SEQUENCE {
        x INTEGER OPTIONAL,
        y INTEGER OPTIONAL
    }
it would be impossible to distinguish between a point that only defines an x value from a point with only a y value. Let's say we encode an x corrdinate of 9 that way, it would look like

    30 03 02 01 09
That’s a SEQUENCE of length 3 (bytes), containing an INTEGER of length 1, which has the value 9. But you’d also encode a Point with a y coordinate of 9 exactly the same way. To resolve this ambiguity, a specification needs to provide **encoding instructions** that assign a unique tag to each entry. Using the application class we can define tags that help distinguish the two.

    Point ::= SEQUENCE {
        x [APPLICATION 0] INTEGER OPTIONAL,
        y [APPLICATION 1] INTEGER OPTIONAL
    }

Though for this use case, it's more common to use the context-specific class (represented by a number in brackets by itself):

    Point ::= SEQUENCE {
        x [0] INTEGER OPTIONAL,
        y [1] INTEGER OPTIONAL
    }

So now, to encode a Point with just an x coordinate of 9, instead of encoding x as a UNIVERSAL INTEGER, you’d sets bit 8 and 7 of the encoded tag to (1, 0) to indicate the context specific class, and set the low bits to 0, giving this encoding:

    30 03 80 01 09

And to represent a Point with just a y coordinate of 9, you’d do the same thing, except you’d set the low bits to 1:

    30 03 81 01 09

Or you could represent a Point with x and y coordinate both equal to 9:

    30 06 80 01 09 81 01 09

## **Length**

The length in the tag-length-value tuple always represents the total number of bytes in the object including all sub-objects. So a SEQUENCE with one field doesn’t have a length of 1; it has a length of however many bytes the encoded form of that field take up.

The encoding of length can take two forms: short or long. The short form is a single byte, between 0 and 127.

The long form is at least two bytes long, and has bit 8 of the first byte set to 1. Bits 7-1 of the first byte indicate how many more bytes are in the length field itself. Then the remaining bytes specify the length itself, as a multi-byte integer.

The longest possible length would start with the byte 254 (a length byte of 255 is reserved for future extensions), specifying that 126 more bytes would follow in the length field alone. If each of those 126 bytes was 255, that would indicate 21008-1 bytes to follow in the value field.

The long form allows you to encode the same length multiple ways - for instance by using two bytes to express a length that could fit in one, or by using long form to express a length that could fit in the short form. DER says to always use the smallest possible length representation.

Safety warning: Don’t fully trust the length values that you decode! For instance, check that the encoded length is less than the amount of data available from the stream being decoded.

## **Indefinite length**

It’s also possible, in BER, to encode a string, SEQUENCE, SEQUENCE OF, SET, or SET OF where you don’t know the length in advance (for instance when streaming output). To do this, you encode the length as a single byte with the value 80, and encode the value as a series of encoded objects concatenated together, with the end indicated by the two bytes 00 00 (which can be considered as a zero-length object with tag 0). So, for instance, the indefinite length encoding of a UTF8String would be the encoding of one or more UTF8Strings concatenated together, and concatenated finally with 00 00.

Indefinite-ness can be arbitrarily nested! So, for example, the UTF8Strings that you concatenate together to form an indefinite-length UTF8String can themselves be encoded either with definite length or indefinite length.

A length byte of 80 is distinguishing because it’s not a valid short form or long form length. Since bit 8 is set to 1, this would normally be interpreted as the long form, but the remaining bits are supposed to indicate the number of additional bytes that make up the length. Since bits 7-1 are all 0, that would indicate a long-form encoding with zero bytes making up the length, which is not allowed.

DER forbids indefinite length encoding. You must use the definite length encoding (that is, with the length specified at the beginning).

## **Constructed vs Primitive**

Bit 6 of the first tag byte is used to indicate whether the value is encoded in primitive form or constructed form. Primitive encoding represents the value directly - for instance, in a UTF8String the value would consist solely of the string itself, in UTF-8 bytes. Constructed encoding represents the value as a concatenation of other encoded values. For instance, as described in the “Indefinite length” section, a UTF8String in constructed encoding would consist of multiple encoded UTF8Strings (each with a tag and length), concatenated together. The length of the overall UTF8String would be the total length, in bytes, of all those concatenated encoded values. Constructed encoding can use either definite or indefinite length. Primitive encoding always uses definite length, because there’s no way to express indefinite length without using constructed encoding.

INTEGER, OBJECT IDENTIFIER, and NULL must use primitive encoding. SEQUENCE, SEQUENCE OF, SET, and SET OF must use constructed encoding (because they are inherently concatenations of multiple values). BIT STRING, OCTET STRING, UTCTime, GeneralizedTime, and the various string types can use either primitive encoding or constructed encoding, at the sender’s discretion-- in BER. However, in DER all types that have an encoding choice between primitive and constructed must use the primitive encoding.

## **EXPLICIT vs IMPLICIT**

The encoding instructions e.g. `[1]`, or `[APPLICATION 8]`, can also include the keyword EXPLICIT or IMPLICIT (example from RFC 5280):

    TBSCertificate  ::=  SEQUENCE  {
        version         [0]  Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                            -- If present, version MUST be v2 or v3
        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                            -- If present, version MUST be v2 or v3
        extensions      [3]  Extensions OPTIONAL
                            -- If present, version MUST be v3 --  }

This defines how the tag should be encoded; it doesn’t have to do with whether the tag number is explicitly assigned or not (since both IMPLICIT and EXPLICIT always go alongside a specific tag number). IMPLICIT encodes the field just like the underlying type, but with the tag number and class provided in the ASN.1 module. EXPLICIT encodes the field as the underlying type, and then wraps that in an outer encoding. The outer encoding has the tag number and class from the ASN.1 module and additionally has the Constructed bit set.

Here’s an example ASN.1 encoding instruction using IMPLICIT:

    [5] IMPLICIT UTF8String

This would encode “hi” as:

    85 02 68 69

Compare to this ASN.1 encoding instruction using EXPLICIT:

    [5] EXPLICIT UTF8String

This would encode “hi” as:

    A5 04 0C 02 68 69

When the IMPLICIT or EXPLICIT keyword is not present, the default is EXPLICIT, unless the module sets a different default at the top with “EXPLICIT TAGS,” “IMPLICIT TAGS,” or “AUTOMATIC TAGS.” For instance, RFC 5280 defines two modules, one where EXPLICIT tags are the default, and a second one that imports the first, and has IMPLICIT tags as the default. Implicit encoding uses fewer bytes than explicit encoding.

AUTOMATIC TAGS is the same as IMPLICIT TAGS, but with additional property that tag numbers ([0], [1], etc) are automatically assigned in places that need them, like SEQUENCEs with optional fields.
<br><br>

# Encoding of specific types

In this section we’ll talk about how the value of each type is encoded, with examples. <br>

## **INTEGER encoding**

Integers are encoded as one or more bytes, in two’s complement with the high bit (bit 8) of the leftmost byte as the sign bit. As the BER specification says:

The value of a two's complement binary number is derived by numbering the bits in the contents octets, starting with bit 1 of the last octet as bit zero and ending the numbering with bit 8 of the first octet. Each bit is assigned a numerical value of 2N, where N is its position in the above numbering sequence. The value of the two's complement binary number is obtained by summing the numerical values assigned to each bit for those bits which are set to one, excluding bit 8 of the first octet, and then reducing this value by the numerical value assigned to bit 8 of the first octet if that bit is set to one.

So for instance this one-byte value (represented in binary) encodes decimal 50:

    00110010 (== decimal 50)

This one-byte value (represented in binary) encodes decimal -100:

    10011100 (== decimal -100)

This five-bytes value (represented in binary) encodes decimal -549755813887 (i.e. -2^39 + 1):

    10000000 00000000 00000000 00000000 00000001 (== decimal -549755813887)

BER and DER both require that integers be represented in the shortest form possible. That is enforced with this rule:

... the bits of the first octet and bit 8 of the second octet:

1.  shall not all be ones; and
2.  shall not all be zero.

Rule (2) roughly means: if there are leading zero bytes in the encoding you could just as well leave them off and have the same number. Bit 8 of the second byte is important here too because if you want to represent certain values, you must use a leading zero byte. For instance, decimal 255 is encoded as two bytes:

    00000000 11111111

That’s because a single-byte encoding of 11111111 by itself means -1 (bit 8 is treated as the sign bit).

Rule (1) is best explained with an example. Decimal -128 is encoded as:

    10000000 (== decimal -128)

However, that could also be encoded as:

    11111111 10000000 (== decimal -128, but an invalid encoding)

Expanding that out, it’s 

    -2^15 + 2^14 + 2^13 + 2^12 + 2^11 + 2^10 + 2^9 + 2^8 + 2^7 == -27 == -128.     
Note that the 1 in “10000000” was a sign bit in the single-byte encoding, but means 27 in the two-byte encoding.

This is a generic transform: For any negative number encoded as BER (or DER) you could prefix it with 11111111 and get the same number. This is called **sign extension**. Or equivalently, if there’s a negative number where the encoding of the value begins with 11111111, you could remove that byte and still have the same number. So BER and DER require the **shortest encoding**.

The two’s complement encoding of INTEGERs has practical impact in certificate issuance: RFC 5280 requires that serial numbers be positive. Since the first bit is always a sign bit, that means serial numbers encoded in DER as 8 bytes can be at most 63 bits long. Encoding a 64-bit positive serial number requires a 9-byte encoded value (with the first byte being zero).

Here’s the encoding of an INTEGER with the value 2^63+1 (which happens to be a 64-bit positive number):

    02 09 00 80 00 00 00 00 00 00 01

## **String encoding**

Strings are encoded as their literal bytes. Since IA5String and PrintableString just define different subsets of acceptable characters, their encodings differ only by tag.

A PrintableString containing “hi”:

    13 02 68 69

An IA5String containing “hi”:

    16 02 68 69

UTF8Strings are the same, but can encode a wider variety of characters. For instance, this is the encoding of a UTF8String containing U+1F60E Smiling Face With Sunglasses (😎):

    0c 04 f0 9f 98 8e

## **Date and Time encoding**

UTCTime and GeneralizedTime are actually encoded like strings, surprisingly! As described above in the “Types” section, UTCTime represents dates in the format YYMMDDhhmmss. GeneralizedTime uses a four-digit year YYYY in place of YY. Both have an optional timezone offset or “Z” (Zulu) to indicate no timezone offset from UTC.

For instance, December 15, 2019 at 19:02:10 in the PST time zone (UTC-8) is represented in a UTCTime as: 191215190210-0800. Encoded in BER, that’s:

    17 11 31 39 31 32 31 35 31 39 30 32 31 30 2d 30 38 30 30

For BER encoding, seconds are optional in both UTCTime and GeneralizedTime, and timezone offsets are allowed. However, DER (along with RFC 5280) specify that seconds must be present, fractional seconds must not be present, and the time must be expressed as UTC with the “Z” form.

The above date would be encoded in DER as:

    17 0d 31 39 31 32 31 36 30 33 30 32 31 30 5a

## **OBJECT IDENTIFIER encoding**

As described above, OIDs are conceptually a series of integers. They are always at least two components long. The first component is always 0, 1, or 2. When the first component is 0 or 1, the second component is always less than 40. Because of this, the first two components are unambiguously represented as 40*X+Y, where X is the first component and Y is the second.

So, for instance, to encode 2.999.3, you would combine the first two components into 1079 decimal (40*2 + 999), which would give you “1079.3”.

After applying that transform, each component is encoded in base 128, with the most significant byte first. Bit 8 is set to “1” in every byte except the last in a component; that’s how you know when one component is done and the next one begins. So the component “3” would be represented simply as the byte 0x03. The component “129” would be represented as the bytes 0x81 0x01. Once encoded, all the components of an OID are concatenated together to form the encoded value of the OID.

OIDs must be represented in the fewest bytes possible, whether in BER or DER. So components cannot begin with the byte 0x80.

As an example, the OID 1.2.840.113549.1.1.11 (representing sha256WithRSAEncryption) is encoded like so:

    06 09 2a 86 48 86 f7 0d 01 01 0b

## **NULL encoding**

The value of an object containing NULL is always zero-length, so the encoding of NULL is always just the tag and a length field of zero:

    05 00

## **SEQUENCE encoding**

The first thing to know about SEQUENCE is that it always uses Constructed encoding because it contains other objects. In other words, the value bytes of a SEQUENCE contain the concatenation of the encoded fields of that SEQUENCE (in the order those fields were defined). This also means that bit 6 of a SEQUENCE’s tag (the Constructed vs Primitive bit) is always set to 1. So even though the tag number for SEQUENCE is technically 0x10, its tag byte, once encoded, is always 0x30.

When there are fields in a SEQUENCE with the OPTIONAL annotation, they are simply omitted from the encoding if not present. As a decoder processes elements of the SEQUENCE, it can figure out which type is being decoded based on what’s been decoded so far, and the tag bytes it reads. If there is ambiguity, for instance when elements have the same type, the ASN.1 module must specify **encoding instructions** that assign distinct tag numbers to the elements.

DEFAULT fields are similar to OPTIONAL ones. If a field’s value is the default, it may be omitted from the BER encoding. In the DER encoding, it MUST be omitted.

As an example, RFC 5280 defines AlgorithmIdentifier as a SEQUENCE:

    AlgorithmIdentifier  ::=  SEQUENCE  {
            algorithm               OBJECT IDENTIFIER,
            parameters              ANY DEFINED BY algorithm OPTIONAL  }

Here’s the encoding of the AlgorithmIdentifier containing 1.2.840.113549.1.1.11. RFC 8017 says “parameters” should have the type NULL for this algorithm.

    30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00

## **SEQUENCE OF encoding**

A SEQUENCE OF is encoded in exactly the same way as a SEQUENCE. If you’re decoding, the only way you can tell the difference between a SEQUENCE and a SEQUENCE OF is by reference to the ASN.1 module.

Here is the encoding of a SEQUENCE OF INTEGER containing the numbers 7, 8, and 9:

    30 09 02 01 07 02 01 08 02 01 09

## **SET encoding**

Like SEQUENCE, a SET is Contructed, meaning that its value bytes are the concatenation of its encoded fields. Its tag number is 0x11. Since the Constructed vs Primitive bit (bit 6) is always set to 1, that means it’s encoded with a tag byte of 0x31.

The encoding of a SET, like a SEQUENCE, omits OPTIONAL and DEFAULT fields if they are absent or have the default value. Any ambiguity that results due to fields with the same type must be resolved by the ASN.1 module, and DEFAULT fields MUST be omitted from DER encoding if they have the default value.

In BER, a SET may be encoded in any order. In DER, a SET must be encoded in ascending order by tag.

## **SET OF encoding**

A SET OF items is encoded the same way as a SET, including the tag byte of 0x31. For DER encoding, there is a similar requirement that the SET OF must be encoded in ascending order. Because all elements in the SET OF have the same type, ordering by tag is not sufficient. So the elements of a SET OF are sorted by their encoded values, with shorter values treated as if they were padded to the right with zeroes.

## **BIT STRING encoding**

A BIT STRING of N bits is encoded as N/8 bytes (rounded up), with a one-byte prefix that contains the “number of unused bits,” for clarity when the number of bits is not a multiple of 8. For instance, when encoding the bit string `011011100101110111` (18 bits), we need at least three bytes. But that’s somewhat more than we need: it gives us capacity for 24 bits total. Six of those bits will be unused. Those six bits are written at the rightmost end of the bit string, so this is encoded as:

    03 04 06 6e 5d c0

In BER, the unused bits can have any value, so the last byte of that encoding could just as well be c1, c2, c3, and so on. In DER, the unused bits must all be zero.

## **OCTET STRING encoding**

An OCTET STRING is encoded as the bytes it contains. Here’s an example of an OCTET STRING containing the bytes 03, 02, 06, and A0:

    04 04 03 02 06 A0

## **CHOICE and ANY encoding**

A CHOICE or ANY field is encoded as whatever type it actually holds, unless modified by encoding instructions. So if a CHOICE field in an ASN.1 specification allows an INTEGER or a UTCTime, and the specific object being encoded contains an INTEGER, then it is encoded as an INTEGER.

In practice, CHOICE fields very often have encoding instructions. For instance, consider this example from RFC 5280, where the encoding instructions are necessary to distinguish rfc822Name from dNSName, since they both have the underlying type `IA5String`:

    GeneralName ::= CHOICE {
            otherName                       [0]     OtherName,
            rfc822Name                      [1]     IA5String,
            dNSName                         [2]     IA5String,
            x400Address                     [3]     ORAddress,
            directoryName                   [4]     Name,
            ediPartyName                    [5]     EDIPartyName,
            uniformResourceIdentifier       [6]     IA5String,
            iPAddress                       [7]     OCTET STRING,
            registeredID                    [8]     OBJECT IDENTIFIER }

Here’s an example encoding of a GeneralName containing the `rfc822Name` a@example.com (recalling that [1] means to use tag number 1, in the tag class “context-specific” (bit 8 set to 1), with the IMPLICIT tag encoding method):

    81 0d 61 40 65 78 61 6d 70 6c 65 2e 63 6f 6d

Here’s an example encoding of a GeneralName containing the dNSName “example.com”:

    82 0b 65 78 61 6d 70 6c 65 2e 63 6f 6d

## **Safety**

It’s important to be very careful decoding BER and DER, particularly in non-memory-safe languages like C and C++. There’s a long history of vulnerabilities in decoders. Parsing input in general is a common source of vulnerabilities. The ASN.1 encoding formats in particular seem to be particular vulnerability magnets. They are complicated formats, with many variable-length fields. Even the lengths have variable lengths! Also, ASN.1 input is often attacker-controlled. If you have to parse a certificate in order to distinguish an authorized user from an unauthorized one, you have to assume that some of the time you will be parsing, not a certificate, but some bizarre input crafted to exploit bugs in your ASN.1 code.

To avoid these problems, it is best to use a memory-safe language whenever possible. And whether you can use a memory-safe language or not, it’s best to use an ASN.1 compiler to generate your parsing code rather than writing it from scratch.

