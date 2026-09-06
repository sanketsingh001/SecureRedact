using FintechGuard.Pii.Algorithms;
using FluentAssertions;
using Xunit;

namespace FintechGuard.Pii.Tests;

public class AlgorithmTests
{
    [Theory]
    [InlineData("212345678901", true)] // Valid Verhoeff test vector
    [InlineData("212345678908", false)] // Altered check digit
    [InlineData("212345678910", false)] // Transposition
    public void Verhoeff_ValidatesCorrectly(string digits, bool expected)
    {
        VerhoeffValidator.Validate(digits.AsSpan()).Should().Be(expected);
    }

    [Theory]
    [InlineData("4532015112830366", true)]  // Valid Visa (Luhn passes)
    [InlineData("4532-0151-1283-0366", true)]
    [InlineData("4532015112830367", false)] // Failed Luhn
    [InlineData("1234567890123456", false)] // Random 16 digits fails Luhn
    public void Luhn_ValidatesCorrectly(string card, bool expected)
    {
        LuhnValidator.ValidateWithSeparators(card.AsSpan()).Should().Be(expected);
    }

    [Theory]
    [InlineData("DE89370400440532013000", true)] // Valid German IBAN
    [InlineData("GB82WEST12345698765432", true)] // Valid UK IBAN
    [InlineData("DE89370400440532013001", false)] // Invalid check digit
    public void Iban_ValidatesCorrectly(string iban, bool expected)
    {
        IbanValidator.Validate(iban.AsSpan()).Should().Be(expected);
    }

    [Theory]
    [InlineData("ABCDE1234F", false)] // 4th char D is invalid entity type (allowed: P, C, H, F, A, T, B, L, J, G)
    [InlineData("ABCPE1234F", true)] // 4th char P (Person)
    [InlineData("ABCCE1234F", true)] // 4th char C (Company)
    [InlineData("ABCXE1234F", false)] // 4th char X (Invalid entity type)
    [InlineData("ABCPE12345", false)] // Last char must be letter
    public void Pan_ValidatesCorrectly(string pan, bool expected)
    {
        PanValidator.Validate(pan.AsSpan()).Should().Be(expected);
    }

    [Theory]
    [InlineData("27ABCPE1234F1Z5", true)] // 27 (Maharashtra) + valid PAN + 1 + Z + 5
    [InlineData("99ABCPE1234F1Z5", false)] // State code 99 is invalid (only 01-38)
    [InlineData("27ABCPE1234F1A5", false)] // 14th char must be 'Z'
    public void Gstin_ValidatesCorrectly(string gstin, bool expected)
    {
        GstinValidator.Validate(gstin.AsSpan()).Should().Be(expected);
    }

    [Theory]
    [InlineData("123-45-6789", true)]
    [InlineData("000-45-6789", false)] // Area 000 invalid
    [InlineData("666-45-6789", false)] // Area 666 invalid
    [InlineData("950-45-6789", false)] // Area 9xx invalid
    [InlineData("123-00-6789", false)] // Group 00 invalid
    [InlineData("123-45-0000", false)] // Serial 0000 invalid
    public void Ssn_ValidatesCorrectly(string ssn, bool expected)
    {
        SsnValidator.Validate(ssn.AsSpan()).Should().Be(expected);
    }
}
