using System;
using System.Security.Cryptography;

namespace Csg.ApiKeyGenerator;

public class TimeBasedTokenGenerator
{
    private static readonly DateTimeOffset Epoch = new(1970, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private HashType HashType { get; set; } = HashType.HMACSHA256;
        
    /// <summary>
    /// The number of seconds in an interval of time when the same key will be generated.
    /// </summary>
    public int IntervalSeconds { get; set; } = 60;

    public int AllowedNumberOfDriftIntervals { get; set; } = 1;

    public int TokenIterations { get; set; } = 1000;

    private const int KeyLength = 32;

    /// <summary>
    /// Generates a time-based token based using the current
    /// </summary>
    /// <param name="clientID"></param>
    /// <param name="secret"></param>
    /// <param name="utcNow"></param>
    /// <returns></returns>
    public byte[] ComputeToken(string clientID, string secret, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(clientID)) throw new ArgumentNullException(nameof(clientID));
        if (string.IsNullOrWhiteSpace(secret)) throw new ArgumentNullException(nameof(secret));

        return now < Epoch ? 
            throw new ArgumentOutOfRangeException(nameof(now)) : 
            ComputeTokenInternal(clientID, secret, GetCounter(now));
    }

    public bool ValidateToken(string clientID, string secret, byte[] token, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(clientID)) throw new ArgumentNullException(nameof(clientID));
        if (string.IsNullOrWhiteSpace(secret)) throw new ArgumentNullException(nameof(secret));
        ArgumentNullException.ThrowIfNull(token);

        var counter = GetCounter(now);

        // get epoch seconds rounded to the nearest interval
        var systemToken = ComputeTokenInternal(clientID, secret, counter);
            
        // slow compare the hashes
        if (TokenCompareHelper.AreTokensEqual(systemToken, token))
        {
            return true;
        }

        // attempt to match tokens for the number of intervals of tolerance forward or backward

        for (var i = 1; i <= AllowedNumberOfDriftIntervals; i++)
        {
            var altCounter = counter + i;
            // try a match where the caller's clock was ahead of the system time
            systemToken = ComputeTokenInternal(clientID, secret, altCounter);

            if (TokenCompareHelper.AreTokensEqual(systemToken, token))
            {
                return true;
            }

            altCounter = counter - i;
            // try a match where the caller's clock was behind the system time
            systemToken = ComputeTokenInternal(clientID, secret, altCounter);

            if (TokenCompareHelper.AreTokensEqual(systemToken, token))
            {
                return true;
            }
        }
        
        return false;
    }
    
    private HMAC GetHashMethod(byte[] key)
    {
        return HashType switch
        {
            HashType.HMACSHA1 => new HMACSHA1(key),
            HashType.HMACSHA256 => new HMACSHA256(key),
            HashType.HMACSHA512 => new HMACSHA512(key),
            _ => throw new NotSupportedException($"An unsupported hash type {HashType} was specified.")
        };
    }

    private long GetCounter(DateTimeOffset now)
    {
        var epochSeconds = (long)now.Subtract(Epoch).TotalSeconds;

        return epochSeconds / IntervalSeconds;
    }
    
    private byte[] ComputeTokenInternal(string clientID, string secret, long counter)
    {
        if (string.IsNullOrWhiteSpace(clientID)) throw new ArgumentNullException(nameof(clientID));
        if (string.IsNullOrWhiteSpace(secret)) throw new ArgumentNullException(nameof(secret));

        ArgumentOutOfRangeException.ThrowIfNegative(counter);

        var salt = BitConverter.GetBytes(counter);
        var hashAlgorithmName = GetHashAlgorithmName();
        var key = Rfc2898DeriveBytes.Pbkdf2(secret, salt, TokenIterations, hashAlgorithmName, KeyLength);
        var message = System.Text.Encoding.UTF8.GetBytes(clientID.Trim().ToUpperInvariant());

        return GetHashMethod(key).ComputeHash(message);
    }

    private HashAlgorithmName GetHashAlgorithmName()
    {
        return HashType switch
        {
            HashType.HMACSHA1 => HashAlgorithmName.SHA1,
            HashType.HMACSHA256 => HashAlgorithmName.SHA256,
            HashType.HMACSHA512 => HashAlgorithmName.SHA512,
            _ => throw new ArgumentOutOfRangeException()
        };
    }
}