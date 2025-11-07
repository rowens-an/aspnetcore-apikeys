namespace Csg.ApiKeyGenerator;

public static class TokenCompareHelper
{
    public static bool AreTokensEqual(byte[] a, byte[] b)
    {
        if (a.Length != b.Length)
            return false;

        if (a.Length == 0)
            return true;

        var result = true;

        for (var i = 0; i < a.Length; i++)
        {
            if (a[i] != b[i])
            {
                result = false;
            }
        }

        return result;
    }
}