using System;
using System.Runtime.InteropServices;

class Program
{
    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetRemoteTOD(string UncServerName, out IntPtr BufferPtr);

    [DllImport("Netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr Buffer);

    [StructLayout(LayoutKind.Sequential)]
    private struct TIME_OF_DAY_INFO
    {
        public int tod_elapsedt;
        public int tod_msecs;
        public int tod_hours;
        public int tod_mins;
        public int tod_secs;
        public int tod_hunds;
        public int tod_timezone;
        public int tod_tinterval;
        public int tod_day;
        public int tod_month;
        public int tod_year;
        public int tod_weekday;
    }

    static void Main(string[] args)
    {
        string serverName = null; 
        IntPtr bufferPtr;

        int result = NetRemoteTOD(serverName, out bufferPtr);

        if (result == 0) // NERR_Success
        {
            try
            {
                TIME_OF_DAY_INFO todInfo = Marshal.PtrToStructure<TIME_OF_DAY_INFO>(bufferPtr);
                TimeSpan uptime = TimeSpan.FromSeconds(todInfo.tod_elapsedt);

                Console.WriteLine($"System Uptime: {uptime}");

                if (uptime.TotalHours > 5)
                {
                    Console.WriteLine("The system has been up for more than 5 hours.");
                }
                else
                {
                    Console.WriteLine("The system has been up for less than or equal to 5 hours.");
                }
            }
            finally
            {
                NetApiBufferFree(bufferPtr);
            }
        }
        else
        {
            Console.WriteLine($"NetRemoteTOD failed with error code: {result}");
        }
    }
}
