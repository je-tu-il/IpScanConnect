using System;
using System.Collections.Concurrent;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace IpScanConnect.Services
{
    public static class IconCacheService
    {
        private static readonly ConcurrentDictionary<string, ImageSource> _cache =
            new ConcurrentDictionary<string, ImageSource>(StringComparer.OrdinalIgnoreCase);

        [DllImport("gdi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeleteObject(IntPtr hObject);

        public static ImageSource GetIconForPath(string exePath)
        {
            if (string.IsNullOrEmpty(exePath) || exePath == "N/A")
                return null;

            ImageSource cached;
            if (_cache.TryGetValue(exePath, out cached))
                return cached;

            try
            {
                if (!File.Exists(exePath))
                    return null;

                using (Icon icon = Icon.ExtractAssociatedIcon(exePath))
                {
                    if (icon == null) return null;
                    using (Bitmap bmp = icon.ToBitmap())
                    {
                        IntPtr hBitmap = bmp.GetHbitmap();
                        try
                        {
                            BitmapSource bs = Imaging.CreateBitmapSourceFromHBitmap(
                                hBitmap,
                                IntPtr.Zero,
                                Int32Rect.Empty,
                                BitmapSizeOptions.FromWidthAndHeight(24, 24));
                            bs.Freeze();
                            _cache[exePath] = bs;
                            return bs;
                        }
                        finally
                        {
                            DeleteObject(hBitmap);
                        }
                    }
                }
            }
            catch
            {
                return null;
            }
        }
    }
}
