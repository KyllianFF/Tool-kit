<#
    Toolkit - Features / QR codes

    A QR code encoder, so a link or a Wi-Fi network becomes a code without
    pasting it into a web site that keeps it: the Wi-Fi password of a client
    is exactly what should not be typed into a random generator online.

    The encoder follows ISO/IEC 18004 the way Project Nayuki's reference
    implementation lays it out: byte mode in UTF-8, the smallest version that
    holds the data, Reed-Solomon error correction split into blocks and
    interleaved, the zigzag placement, and the mask with the lowest penalty.
    It is written in C# because a QR symbol is tens of thousands of module
    operations per mask, eight masks per code, as the text is typed.
#>

<#
.SYNOPSIS
    Compiles the QR code encoder, once per session.
#>
function Initialize-TkQrCodeType {
    [CmdletBinding()]
    param()

    if ('TkQrCode' -as [type]) {
        return
    }

    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;

public static class TkQrCode
{
    // [error correction level L, M, Q, H][version 0 to 40]; version 0 is unused.
    private static readonly int[,] EccCodewordsPerBlock = {
        { -1,  7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30 },
        { -1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28 },
        { -1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30 },
        { -1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30 }
    };

    private static readonly int[,] ErrorCorrectionBlocks = {
        { -1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4,  4,  4,  4,  4,  6,  6,  6,  6,  7,  8,  8,  9,  9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25 },
        { -1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5,  5,  8,  9,  9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49 },
        { -1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8,  8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68 },
        { -1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81 }
    };

    // Modules left for data and error correction once the function patterns are drawn.
    public static int GetRawDataModules(int version)
    {
        int result = (16 * version + 128) * version + 64;

        if (version >= 2)
        {
            int alignments = version / 7 + 2;
            result -= (25 * alignments - 10) * alignments - 55;

            if (version >= 7)
            {
                result -= 36;
            }
        }

        return result;
    }

    public static int GetDataCodewords(int version, int level)
    {
        return GetRawDataModules(version) / 8 - EccCodewordsPerBlock[level, version] * ErrorCorrectionBlocks[level, version];
    }

    // Multiplication in GF(2^8) modulo x^8 + x^4 + x^3 + x^2 + 1.
    public static int Multiply(int x, int y)
    {
        int z = 0;

        for (int i = 7; i >= 0; i--)
        {
            z = (z << 1) ^ ((z >> 7) * 0x11D);
            z ^= ((y >> i) & 1) * x;
        }

        return z;
    }

    public static byte[] ReedSolomonDivisor(int degree)
    {
        byte[] result = new byte[degree];
        result[degree - 1] = 1;
        int root = 1;

        for (int i = 0; i < degree; i++)
        {
            for (int j = 0; j < result.Length; j++)
            {
                result[j] = (byte) Multiply(result[j], root);

                if (j + 1 < result.Length)
                {
                    result[j] ^= result[j + 1];
                }
            }

            root = Multiply(root, 0x02);
        }

        return result;
    }

    public static byte[] ReedSolomonRemainder(byte[] data, byte[] divisor)
    {
        byte[] result = new byte[divisor.Length];

        foreach (byte value in data)
        {
            int factor = value ^ result[0];
            Array.Copy(result, 1, result, 0, result.Length - 1);
            result[result.Length - 1] = 0;

            for (int i = 0; i < result.Length; i++)
            {
                result[i] ^= (byte) Multiply(divisor[i], factor);
            }
        }

        return result;
    }

    // The 15 format bits: the level and the mask, with their BCH code, masked.
    public static int GetFormatBits(int level, int mask)
    {
        int[] levelBits = { 1, 0, 3, 2 };
        int data = (levelBits[level] << 3) | mask;
        int remainder = data;

        for (int i = 0; i < 10; i++)
        {
            remainder = (remainder << 1) ^ ((remainder >> 9) * 0x537);
        }

        return ((data << 10) | remainder) ^ 0x5412;
    }

    // The 18 version bits of versions 7 and up.
    public static int GetVersionBits(int version)
    {
        int remainder = version;

        for (int i = 0; i < 12; i++)
        {
            remainder = (remainder << 1) ^ ((remainder >> 11) * 0x1F25);
        }

        return (version << 12) | remainder;
    }

    public static bool[,] Encode(byte[] data, int level, out int version, out int mask)
    {
        version = 0;

        for (int candidate = 1; candidate <= 40; candidate++)
        {
            int countBits = candidate <= 9 ? 8 : 16;
            int needed = 4 + countBits + data.Length * 8;

            if (data.Length < (1 << countBits) && needed <= GetDataCodewords(candidate, level) * 8)
            {
                version = candidate;
                break;
            }
        }

        if (version == 0)
        {
            throw new ArgumentException("The text is too long for a QR code at this error correction level.");
        }

        int capacity = GetDataCodewords(version, level) * 8;
        List<bool> bits = new List<bool>(capacity);

        AppendBits(bits, 4, 4);
        AppendBits(bits, data.Length, version <= 9 ? 8 : 16);

        foreach (byte value in data)
        {
            AppendBits(bits, value, 8);
        }

        AppendBits(bits, 0, Math.Min(4, capacity - bits.Count));
        AppendBits(bits, 0, (8 - bits.Count % 8) % 8);

        for (int pad = 0xEC; bits.Count < capacity; pad ^= 0xEC ^ 0x11)
        {
            AppendBits(bits, pad, 8);
        }

        byte[] codewords = new byte[capacity / 8];

        for (int i = 0; i < bits.Count; i++)
        {
            if (bits[i])
            {
                codewords[i >> 3] |= (byte) (1 << (7 - (i & 7)));
            }
        }

        byte[] all = AddErrorCorrection(codewords, version, level);
        int size = version * 4 + 17;
        bool[,] modules = new bool[size, size];
        bool[,] function = new bool[size, size];

        DrawFunctionPatterns(modules, function, version, level, size);
        DrawCodewords(modules, function, all, size);

        mask = 0;
        long lowest = long.MaxValue;

        for (int candidate = 0; candidate < 8; candidate++)
        {
            ApplyMask(modules, function, candidate, size);
            DrawFormat(modules, function, level, candidate, size);

            long penalty = Penalty(modules, size);

            if (penalty < lowest)
            {
                lowest = penalty;
                mask = candidate;
            }

            // A mask is an exclusive or: applying it again removes it.
            ApplyMask(modules, function, candidate, size);
        }

        ApplyMask(modules, function, mask, size);
        DrawFormat(modules, function, level, mask, size);

        return modules;
    }

    // Eight bits of grey per pixel, dark modules black, with a light quiet zone around.
    public static byte[] ToGray8(bool[,] modules, int scale, int border, out int width)
    {
        int size = modules.GetLength(0);
        width = (size + border * 2) * scale;
        byte[] pixels = new byte[width * width];

        for (int i = 0; i < pixels.Length; i++)
        {
            pixels[i] = 255;
        }

        for (int y = 0; y < size; y++)
        {
            for (int x = 0; x < size; x++)
            {
                if (!modules[y, x])
                {
                    continue;
                }

                for (int dy = 0; dy < scale; dy++)
                {
                    int row = ((y + border) * scale + dy) * width;

                    for (int dx = 0; dx < scale; dx++)
                    {
                        pixels[row + (x + border) * scale + dx] = 0;
                    }
                }
            }
        }

        return pixels;
    }

    private static void AppendBits(List<bool> bits, int value, int length)
    {
        for (int i = length - 1; i >= 0; i--)
        {
            bits.Add(((value >> i) & 1) != 0);
        }
    }

    private static byte[] AddErrorCorrection(byte[] data, int version, int level)
    {
        int blocks = ErrorCorrectionBlocks[level, version];
        int eccLength = EccCodewordsPerBlock[level, version];
        int raw = GetRawDataModules(version) / 8;
        int shortBlocks = blocks - raw % blocks;
        int shortLength = raw / blocks;
        byte[] divisor = ReedSolomonDivisor(eccLength);
        byte[][] parts = new byte[blocks][];

        for (int i = 0, offset = 0; i < blocks; i++)
        {
            int dataLength = shortLength - eccLength + (i < shortBlocks ? 0 : 1);
            byte[] block = new byte[dataLength];
            Array.Copy(data, offset, block, 0, dataLength);
            offset += dataLength;

            byte[] ecc = ReedSolomonRemainder(block, divisor);
            parts[i] = new byte[shortLength + 1];
            Array.Copy(block, 0, parts[i], 0, dataLength);
            Array.Copy(ecc, 0, parts[i], shortLength + 1 - eccLength, eccLength);
        }

        byte[] result = new byte[raw];

        for (int i = 0, position = 0; i < shortLength + 1; i++)
        {
            for (int j = 0; j < blocks; j++)
            {
                // Short blocks have no byte at the last data position.
                if (i != shortLength - eccLength || j >= shortBlocks)
                {
                    result[position] = parts[j][i];
                    position++;
                }
            }
        }

        return result;
    }

    private static void SetFunction(bool[,] modules, bool[,] function, int x, int y, bool dark)
    {
        modules[y, x] = dark;
        function[y, x] = true;
    }

    private static void DrawFunctionPatterns(bool[,] modules, bool[,] function, int version, int level, int size)
    {
        for (int i = 0; i < size; i++)
        {
            SetFunction(modules, function, 6, i, i % 2 == 0);
            SetFunction(modules, function, i, 6, i % 2 == 0);
        }

        DrawFinder(modules, function, 3, 3, size);
        DrawFinder(modules, function, size - 4, 3, size);
        DrawFinder(modules, function, 3, size - 4, size);

        int[] positions = AlignmentPositions(version, size);
        int count = positions.Length;

        for (int i = 0; i < count; i++)
        {
            for (int j = 0; j < count; j++)
            {
                bool corner = (i == 0 && j == 0) || (i == 0 && j == count - 1) || (i == count - 1 && j == 0);

                if (corner)
                {
                    continue;
                }

                for (int dy = -2; dy <= 2; dy++)
                {
                    for (int dx = -2; dx <= 2; dx++)
                    {
                        SetFunction(modules, function, positions[i] + dx, positions[j] + dy, Math.Max(Math.Abs(dx), Math.Abs(dy)) != 1);
                    }
                }
            }
        }

        // Reserved now, so data never lands on them; drawn for real once the mask is known.
        DrawFormat(modules, function, level, 0, size);

        if (version >= 7)
        {
            int versionBits = GetVersionBits(version);

            for (int i = 0; i < 18; i++)
            {
                bool bit = ((versionBits >> i) & 1) != 0;
                int a = size - 11 + i % 3;
                int b = i / 3;
                SetFunction(modules, function, a, b, bit);
                SetFunction(modules, function, b, a, bit);
            }
        }
    }

    private static void DrawFinder(bool[,] modules, bool[,] function, int x, int y, int size)
    {
        for (int dy = -4; dy <= 4; dy++)
        {
            for (int dx = -4; dx <= 4; dx++)
            {
                int distance = Math.Max(Math.Abs(dx), Math.Abs(dy));
                int xx = x + dx;
                int yy = y + dy;

                if (0 <= xx && xx < size && 0 <= yy && yy < size)
                {
                    SetFunction(modules, function, xx, yy, distance != 2 && distance != 4);
                }
            }
        }
    }

    private static int[] AlignmentPositions(int version, int size)
    {
        if (version == 1)
        {
            return new int[0];
        }

        int count = version / 7 + 2;
        int step = version == 32 ? 26 : (version * 4 + count * 2 + 1) / (count * 2 - 2) * 2;
        int[] result = new int[count];
        result[0] = 6;

        for (int i = count - 1, position = size - 7; i >= 1; i--, position -= step)
        {
            result[i] = position;
        }

        return result;
    }

    private static bool Bit(int value, int index)
    {
        return ((value >> index) & 1) != 0;
    }

    private static void DrawFormat(bool[,] modules, bool[,] function, int level, int mask, int size)
    {
        int bits = GetFormatBits(level, mask);

        for (int i = 0; i <= 5; i++)
        {
            SetFunction(modules, function, 8, i, Bit(bits, i));
        }

        SetFunction(modules, function, 8, 7, Bit(bits, 6));
        SetFunction(modules, function, 8, 8, Bit(bits, 7));
        SetFunction(modules, function, 7, 8, Bit(bits, 8));

        for (int i = 9; i < 15; i++)
        {
            SetFunction(modules, function, 14 - i, 8, Bit(bits, i));
        }

        for (int i = 0; i < 8; i++)
        {
            SetFunction(modules, function, size - 1 - i, 8, Bit(bits, i));
        }

        for (int i = 8; i < 15; i++)
        {
            SetFunction(modules, function, 8, size - 15 + i, Bit(bits, i));
        }

        SetFunction(modules, function, 8, size - 8, true);
    }

    private static void DrawCodewords(bool[,] modules, bool[,] function, byte[] data, int size)
    {
        int index = 0;

        for (int right = size - 1; right >= 1; right -= 2)
        {
            // The vertical timing pattern takes column 6.
            if (right == 6)
            {
                right = 5;
            }

            for (int vertical = 0; vertical < size; vertical++)
            {
                for (int j = 0; j < 2; j++)
                {
                    int x = right - j;
                    bool upward = ((right + 1) & 2) == 0;
                    int y = upward ? size - 1 - vertical : vertical;

                    if (!function[y, x] && index < data.Length * 8)
                    {
                        modules[y, x] = Bit(data[index >> 3], 7 - (index & 7));
                        index++;
                    }
                }
            }
        }
    }

    private static void ApplyMask(bool[,] modules, bool[,] function, int mask, int size)
    {
        for (int y = 0; y < size; y++)
        {
            for (int x = 0; x < size; x++)
            {
                bool invert;

                switch (mask)
                {
                    case 0: invert = (x + y) % 2 == 0; break;
                    case 1: invert = y % 2 == 0; break;
                    case 2: invert = x % 3 == 0; break;
                    case 3: invert = (x + y) % 3 == 0; break;
                    case 4: invert = (x / 3 + y / 2) % 2 == 0; break;
                    case 5: invert = x * y % 2 + x * y % 3 == 0; break;
                    case 6: invert = (x * y % 2 + x * y % 3) % 2 == 0; break;
                    default: invert = ((x + y) % 2 + x * y % 3) % 2 == 0; break;
                }

                if (invert && !function[y, x])
                {
                    modules[y, x] = !modules[y, x];
                }
            }
        }
    }

    // The four penalty rules of the standard; the mask with the lowest total is used.
    private static long Penalty(bool[,] modules, int size)
    {
        long result = 0;
        bool[] finder = { true, false, true, true, true, false, true };

        for (int pass = 0; pass < 2; pass++)
        {
            for (int a = 0; a < size; a++)
            {
                bool color = false;
                int run = 0;

                for (int b = 0; b < size; b++)
                {
                    bool current = pass == 0 ? modules[a, b] : modules[b, a];

                    if (b > 0 && current == color)
                    {
                        run++;

                        if (run == 5)
                        {
                            result += 3;
                        }
                        else if (run > 5)
                        {
                            result++;
                        }
                    }
                    else
                    {
                        color = current;
                        run = 1;
                    }
                }

                for (int b = 0; b + 6 < size; b++)
                {
                    bool match = true;

                    for (int k = 0; k < 7 && match; k++)
                    {
                        match = (pass == 0 ? modules[a, b + k] : modules[b + k, a]) == finder[k];
                    }

                    if (!match)
                    {
                        continue;
                    }

                    bool lightBefore = true;
                    bool lightAfter = true;

                    for (int k = 1; k <= 4; k++)
                    {
                        int before = b - k;
                        int after = b + 6 + k;

                        if (before >= 0 && (pass == 0 ? modules[a, before] : modules[before, a]))
                        {
                            lightBefore = false;
                        }

                        if (after < size && (pass == 0 ? modules[a, after] : modules[after, a]))
                        {
                            lightAfter = false;
                        }
                    }

                    if (lightBefore || lightAfter)
                    {
                        result += 40;
                    }
                }
            }
        }

        for (int y = 0; y < size - 1; y++)
        {
            for (int x = 0; x < size - 1; x++)
            {
                bool corner = modules[y, x];

                if (corner == modules[y, x + 1] && corner == modules[y + 1, x] && corner == modules[y + 1, x + 1])
                {
                    result += 3;
                }
            }
        }

        int dark = 0;

        foreach (bool module in modules)
        {
            if (module)
            {
                dark++;
            }
        }

        int total = size * size;
        int steps = (Math.Abs(dark * 20 - total * 10) + total - 1) / total - 1;

        return result + steps * 10;
    }
}
'@
}

<#
.SYNOPSIS
    Lists the error correction levels.

.OUTPUTS
    PSCustomObject[] with Label and Level.
#>
function Get-TkQrErrorCorrectionChoice {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    return @(
        [pscustomobject] @{ Label = 'Medium, 15% can be damaged'; Level = 'M' }
        [pscustomobject] @{ Label = 'Low, 7%, the smallest code'; Level = 'L' }
        [pscustomobject] @{ Label = 'Quartile, 25%';              Level = 'Q' }
        [pscustomobject] @{ Label = 'High, 30%, for print';       Level = 'H' }
    )
}

<#
.SYNOPSIS
    Encodes a text as a QR code.

.PARAMETER Text
    The text or link. Written as UTF-8 bytes, which phones read as such.

.PARAMETER ErrorCorrection
    L, M, Q or H: how much of the code can be damaged and still read.

.OUTPUTS
    PSCustomObject with Version, Size, Mask, ErrorCorrection, Bytes and
    Modules, a square array of booleans, true for a dark module.
#>
function New-TkQrCode {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Text,
        [Parameter()] [ValidateSet('L', 'M', 'Q', 'H')] [string] $ErrorCorrection = 'M'
    )

    if (-not $Text) {
        throw 'There is nothing to encode.'
    }

    Initialize-TkQrCodeType

    $bytes   = (New-Object System.Text.UTF8Encoding($false)).GetBytes($Text)
    $level   = @{ L = 0; M = 1; Q = 2; H = 3 }[$ErrorCorrection]
    $version = 0
    $mask    = 0

    try {
        $modules = [TkQrCode]::Encode($bytes, $level, [ref] $version, [ref] $mask)
    }
    catch {
        $inner = if ($_.Exception.InnerException) { $_.Exception.InnerException } else { $_.Exception }
        throw $inner.Message
    }

    return [pscustomobject] @{
        Version         = $version
        Size            = $modules.GetLength(0)
        Mask            = $mask
        ErrorCorrection = $ErrorCorrection
        Bytes           = $bytes.Length
        Modules         = $modules
    }
}

<#
.SYNOPSIS
    Lists the security choices of a Wi-Fi QR code.

.OUTPUTS
    PSCustomObject[] with Label and Security, the value written after T:.
#>
function Get-TkWifiQrSecurityChoice {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    return @(
        [pscustomobject] @{ Label = 'WPA2 or WPA3 personal';  Security = 'WPA' }
        [pscustomobject] @{ Label = 'WPA3 personal only';     Security = 'SAE' }
        [pscustomobject] @{ Label = 'WEP, obsolete';          Security = 'WEP' }
        [pscustomobject] @{ Label = 'Open, no password';      Security = 'nopass' }
    )
}

<#
.SYNOPSIS
    Writes the text of a Wi-Fi QR code.

.DESCRIPTION
    The WIFI: form phone cameras read: the security type, the network name
    and the key, with backslash before \ ; , " and :, and a value that could
    be read as hexadecimal put in quotes. The key is checked against what
    the security allows, so a code that cannot join is not printed.

.PARAMETER Ssid
    The network name.

.PARAMETER Key
    The network key, the Wi-Fi password.

.PARAMETER Security
    WPA (WPA2 and WPA3 transition), SAE (WPA3 only), WEP or nopass.

.PARAMETER Hidden
    The network does not broadcast its name.

.OUTPUTS
    System.String
#>
function ConvertTo-TkWifiQrText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Ssid,
        [Parameter()] [AllowEmptyString()] [string] $Key = '',
        [Parameter()] [ValidateSet('WPA', 'SAE', 'WEP', 'nopass')] [string] $Security = 'WPA',
        [Parameter()] [switch] $Hidden
    )

    if (-not $Ssid) {
        throw 'Type the name of the network.'
    }

    if ([Text.Encoding]::UTF8.GetByteCount($Ssid) -gt 32) {
        throw 'A network name is at most 32 bytes long.'
    }

    switch ($Security) {

        'nopass' {
            if ($Key) { throw 'An open network has no password: leave it empty, or choose its security.' }
        }

        'WEP' {
            if ($Key.Length -notin @(5, 13) -and $Key -notmatch '^([0-9A-Fa-f]{10}|[0-9A-Fa-f]{26})$') {
                throw 'A WEP key is 5 or 13 characters, or 10 or 26 hexadecimal digits.'
            }
        }

        default {
            if (($Key.Length -lt 8 -or $Key.Length -gt 63) -and $Key -notmatch '^[0-9A-Fa-f]{64}$') {
                throw 'A WPA password is 8 to 63 characters, or 64 hexadecimal digits.'
            }
        }
    }

    $escape = {
        param($value)

        $escaped = $value -replace '([\\;,":])', '\$1'

        if ($value -match '^[0-9A-Fa-f]+$' -and $value.Length % 2 -eq 0) {
            '"{0}"' -f $escaped
        }
        else {
            $escaped
        }
    }

    $text = 'WIFI:T:{0};S:{1};' -f $Security, (& $escape $Ssid)

    if ($Security -ne 'nopass') {
        $text += 'P:{0};' -f (& $escape $Key)
    }

    if ($Hidden) {
        $text += 'H:true;'
    }

    return ($text + ';')
}
